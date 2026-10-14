import Darwin
import Foundation
import UIKit

/// Periodically re-runs the security checks on a background thread and reacts to threats
/// according to a `ProtectionMode`. A generation counter makes sure a stopped loop can never
/// run beside a new one; state is guarded by a lock.
class SecurityWatchdog {

    // MARK: - Singleton

  static let shared = SecurityWatchdog()

  private let threatCheck: () -> Bool
  private let reasonsProvider: () -> [String]
  private let uptime: () -> TimeInterval
  private let terminateProcess: () -> Void
  private let crash: (String) -> Void

  /// Creates a watchdog and subscribes to the app's background/foreground notifications. Every
  /// dependency has a production default and exists so tests can replace it.
  ///
  /// - Parameters:
  ///   - threatCheck: Returns true when a threat is present.
  ///   - reasonsProvider: Returns the reasons reported for a threat.
  ///   - uptime: Monotonic clock in seconds that does not advance during device sleep.
  ///   - terminateProcess: Kills the process (`TERMINATE`).
  ///   - crash: Aborts with a message (`THROW_EXCEPTION`).
  init(
    threatCheck: @escaping () -> Bool = {
      JailbreakDetection.isDeviceJailbroken() || JailbreakDetection.isDebuggerAttached()
    },
    reasonsProvider: @escaping () -> [String] = { JailbreakDetection.getThreatReasons() },
    uptime: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
    terminateProcess: @escaping () -> Void = { kill(getpid(), SIGKILL) },
    crash: @escaping (String) -> Void = { fatalError($0) }
  ) {
    self.threatCheck = threatCheck
    self.reasonsProvider = reasonsProvider
    self.uptime = uptime
    self.terminateProcess = terminateProcess
    self.crash = crash

    let center = NotificationCenter.default
    observers.append(center.addObserver(
      forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: nil
    ) { [weak self] _ in self?.appDidEnterBackground() })
    observers.append(center.addObserver(
      forName: UIApplication.willEnterForegroundNotification, object: nil, queue: nil
    ) { [weak self] _ in self?.appWillEnterForeground() })
  }

  /// Removes the notification observers.
  deinit {
    observers.forEach { NotificationCenter.default.removeObserver($0) }
  }

    // MARK: - App lifecycle

    /// While suspended in the background the process can be paused far longer than the
    /// timing-gap threshold without any debugger involved. The gap check is suspended while
    /// backgrounded and for one iteration after returning to the foreground; otherwise
    /// TERMINATE mode would kill the app every time the user comes back to it.
  private var inBackground = false
  private var skipNextGapCheck = false
  private var observers: [NSObjectProtocol] = []

  /// Suspends the timing-gap check while the app is backgrounded, where the process may be
  /// suspended for a long time.
  func appDidEnterBackground() {
    lock.lock(); defer { lock.unlock() }
    inBackground = true
  }

  /// Ends the background period and skips the next timing-gap check so suspension is not
  /// mistaken for a debugger pause.
  func appWillEnterForeground() {
    lock.lock(); defer { lock.unlock() }
    skipNextGapCheck = true
    inBackground = false
  }

  /// Decides whether the timing-gap check may run in this iteration, consuming the one-shot
  /// foreground grace.
  ///
  /// - Returns: `false` while backgrounded or during the grace iteration, otherwise `true`.
  private func gapCheckApplies() -> Bool {
    lock.lock(); defer { lock.unlock() }
    if inBackground { return false }
    if skipNextGapCheck {
      skipNextGapCheck = false
      return false
    }
    return true
  }

    // MARK: - State

  private let lock = NSLock()
  private var running = false

    /// Identifies the active loop. Each start() bumps it and stop() invalidates it, so a loop
    /// still sleeping from a previous start can never run alongside a new one.
  private var generation: UInt64 = 0

    /// Invoked with the detection reasons whenever a threat is found, before the
    /// protection mode action is applied.
  private var threatHandler: (([String]) -> Void)?

  var isRunning: Bool {
    lock.lock(); defer { lock.unlock() }
    return running
  }

  /// Registers (or clears) the callback that receives the reasons whenever a threat is found,
  /// before the protection mode is applied.
  ///
  /// - Parameter handler: Callback, or nil to remove it.
  func setThreatHandler(_ handler: (([String]) -> Void)?) {
    lock.lock(); defer { lock.unlock() }
    threatHandler = handler
  }

  /// Starts the watchdog thread. Ignored if it is already running. Each iteration flags a
  /// threat when `threatCheck` is true or more than 4x the interval passed since the previous
  /// iteration.
  ///
  /// - Parameters:
  ///   - interval: Base interval in seconds; values below 0.1 are raised to 0.1.
  ///   - protectionMode: Action applied on a threat.
  func start(interval: TimeInterval, protectionMode: ProtectionMode) {
    lock.lock()
    guard !running else { lock.unlock(); return }
    running = true
    skipNextGapCheck = false
    generation &+= 1
    let myGeneration = generation
    lock.unlock()

    let intervalSec = max(interval, 0.1)

    let t = Thread { [weak self] in
      self?.watchLoop(generation: myGeneration, intervalSec: intervalSec, mode: protectionMode)
    }
    t.name = Self.randomThreadName()
    t.qualityOfService = .background
    t.start()
  }

  /// Stops the watchdog; the running loop exits after its current iteration. Safe to call when
  /// not running.
  func stop() {
    lock.lock(); defer { lock.unlock() }
    running = false
    generation &+= 1
  }

  /// Tells whether the calling loop is still the active one.
  ///
  /// - Parameter myGeneration: Generation the loop was started with.
  /// - Returns: `true` if no start/stop happened since.
  private func isCurrent(_ myGeneration: UInt64) -> Bool {
    lock.lock(); defer { lock.unlock() }
    return generation == myGeneration
  }

    // MARK: - Watch Loop

  /// Body of the watchdog thread: checks, handles threats, then sleeps for the base interval
  /// +-40%.
  ///
  /// - Parameters:
  ///   - generation: Generation this loop belongs to; the loop exits when it changes.
  ///   - intervalSec: Base interval in seconds.
  ///   - mode: Action applied on a threat.
  private func watchLoop(generation myGeneration: UInt64, intervalSec: TimeInterval, mode: ProtectionMode) {
      // systemUptime does not advance while the device sleeps, so sleep is not mistaken for a pause.
    var lastRun = uptime()

    while isCurrent(myGeneration) {
      let now = uptime()

        // Timing-gap tamper check: catches debugger-induced pauses / breakpoints that stall the loop.
      let gapExceeded = gapCheckApplies() && now - lastRun > intervalSec * 4
      if gapExceeded || checkThreat() {
        handleThreat(mode: mode)
      }

      lastRun = now
      Thread.sleep(forTimeInterval: Self.randomDelay(base: intervalSec))
    }
  }

    // MARK: - Threat Handling

  /// Collects the reasons, notifies the threat handler and applies the protection mode.
  ///
  /// - Parameter mode: Action to apply.
  private func handleThreat(mode: ProtectionMode) {
    let reasons = reasonsProvider()

    lock.lock()
    let handler = threatHandler
    lock.unlock()
    handler?(reasons)

    switch mode {
      case .logOnly:
        NSLog("[SecurityWatchdog] Threat detected: %@", reasons.joined(separator: ", "))

      case .throwException:
        crash("Security threat detected: \(reasons.joined(separator: ", "))")

      case .terminate:
        terminateProcess()
    }
  }

    // MARK: - Threat Check

  /// Runs one round of checks.
  ///
  /// - Returns: `true` if `threatCheck` reports a threat.
  private func checkThreat() -> Bool {
    return threatCheck()
  }

    // MARK: - Helpers

  /// Builds a random 12-letter lowercase thread name.
  ///
  /// - Returns: The name.
  private static func randomThreadName() -> String {
    let chars = Array("abcdefghijklmnopqrstuvwxyz")
    return String((0..<12).map { _ in chars.randomElement()! })
  }

  /// Adds +-40% jitter to the interval.
  ///
  /// - Parameter base: Base interval in seconds.
  /// - Returns: A delay between 0.6x and 1.4x of `base`.
  private static func randomDelay(base: TimeInterval) -> TimeInterval {
    let jitter = base * 0.4
    let offset = TimeInterval.random(in: -jitter...jitter)
    return base + offset
  }
}
