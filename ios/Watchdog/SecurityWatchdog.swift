import Darwin
import Foundation

class SecurityWatchdog {
  
    // MARK: - Singleton
  
  static let shared = SecurityWatchdog()
  private init() {}
  
    // MARK: - State
  
  private var running = false
  private var intervalSec: TimeInterval = 3.0
  private var mode: ProtectionMode = .logOnly
  private var lastRun: TimeInterval = Date().timeIntervalSince1970
  private var watchThread: Thread?
  
  func start(interval: TimeInterval, protectionMode: ProtectionMode) {
    guard !running else { return }
    
    self.mode = protectionMode
    self.intervalSec = interval
    self.running = true
    self.lastRun = Date().timeIntervalSince1970
    
    let t = Thread {
      self.watchLoop()
    }
    t.name = Self.randomThreadName()
    t.qualityOfService = .background
    t.start()
    watchThread = t
  }
  
  private func performCheck() {
    do {
      if JailbreakDetection.isDeviceJailbroken() || JailbreakDetection.isDebuggerAttached() {
        try handleThreat()
      }
    } catch {
      NSLog("[SecurityWatchdog] Error during threat check: %@", error.localizedDescription)
    }
  }
  
  func stop() {
    running = false
  }
    // MARK: - Watch Loop
  
  private func watchLoop() {
    while running {
      do {
        let now = Date().timeIntervalSince1970
        
          // ── Timing-gap tamper check ──────────────────────────────────
          // if now - lastRun > interval * 4 → threat.
          // Catches debugger-induced pauses / breakpoints that stall the loop.
        if now - lastRun > self.intervalSec * 4 {
          try handleThreat()
        }
        
          // ── Normal threat check ──────────────────────────────────────
        if checkThreat() {
          try handleThreat()
        }
        
        self.lastRun = now
        Thread.sleep(forTimeInterval: Self.randomDelay(base: self.intervalSec))
        
      } catch {
        NSLog("[SecurityWatchdog] Error in watch loop: %@", error.localizedDescription)
      }
    }
  }
  
    // MARK: - Threat Handling
  
  private func handleThreat() throws {
    let reasons = JailbreakDetection.getDetectionReasons()
    
    switch mode {
      case .logOnly:
        NSLog("[SecurityWatchdog] Threat detected: %@", reasons.joined(separator: ", "))
        
      case .throwException:
        fatalError("Security threat detected: \(reasons.joined(separator: ", "))")
        
      case .terminate:
        kill(getpid(), SIGKILL)
    }
  }
  
    // MARK: - Threat Check
  
  private func checkThreat() -> Bool {
    return JailbreakDetection.isDeviceJailbroken() || JailbreakDetection.isDebuggerAttached()
  }
  
    // MARK: - Helpers
  
    /// Random 12-char lowercase thread name
  private static func randomThreadName() -> String {
    let chars = Array("abcdefghijklmnopqrstuvwxyz")
    return String((0..<12).map { _ in chars.randomElement()! })
  }
  
    /// Jitter ±40% around `base` to make timing less predictable and harder to bypass with breakpoints.
  private static func randomDelay(base: TimeInterval) -> TimeInterval {
    let jitter = base * 0.4
    let offset = TimeInterval.random(in: -jitter...jitter)
    return base + offset
  }
}
