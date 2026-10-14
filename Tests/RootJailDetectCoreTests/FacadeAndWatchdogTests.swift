import XCTest
@testable import RootJailDetectCore

// MARK: - ProtectionMode

final class ProtectionModeTests: XCTestCase {
  func testRawValuesAreDistinct() {
    let raws = [ProtectionMode.logOnly, .throwException, .terminate].map { $0.rawValue }
    XCTAssertEqual(Set(raws).count, 3)
  }

  func testInitFromRawValue() {
    XCTAssertEqual(ProtectionMode(rawValue: 0), .logOnly)
    XCTAssertEqual(ProtectionMode(rawValue: 1), .throwException)
    XCTAssertEqual(ProtectionMode(rawValue: 2), .terminate)
    XCTAssertNil(ProtectionMode(rawValue: 3))
    XCTAssertNil(ProtectionMode(rawValue: -1))
  }
}

// MARK: - JailbreakDetection facade

final class JailbreakDetectionTests: XCTestCase {
  func testSimulatorIsReported() {
    XCTAssertTrue(JailbreakDetection.isSimulator())
  }

  func testCleanSimulatorIsNotJailbroken() {
    XCTAssertFalse(JailbreakDetection.isDeviceJailbroken())
  }

  func testReasonsAreUnique() {
    let reasons = JailbreakDetection.getDetectionReasons()
    XCTAssertEqual(reasons.count, Set(reasons).count)
  }

  func testThreatReasonsExcludeSimulator() {
    XCTAssertFalse(JailbreakDetection.getThreatReasons().contains("Application running in simulator"))
    XCTAssertFalse(JailbreakDetection.getThreatReasons().contains("Simulator environment variable detected"))
  }

  func testThreatReasonsAreUnique() {
    let reasons = JailbreakDetection.getThreatReasons()
    XCTAssertEqual(reasons.count, Set(reasons).count)
  }

  func testReasonsIncludeSimulator() {
    XCTAssertTrue(JailbreakDetection.getDetectionReasons().contains("Application running in simulator"))
  }

  func testDebuggerDetectionIsBooleanAndStable() {
    XCTAssertEqual(JailbreakDetection.isDebuggerAttached(), JailbreakDetection.isDebuggerAttached())
  }

  func testRepeatedCallsAreConsistent() {
    let first = JailbreakDetection.isDeviceJailbroken()
    for _ in 0..<5 {
      XCTAssertEqual(JailbreakDetection.isDeviceJailbroken(), first)
    }
  }
}

// MARK: - SecurityWatchdog

final class SecurityWatchdogTests: XCTestCase {
  private final class Probe {
    private let lock = NSLock()
    private var _threats = 0
    private var _terminations = 0
    private var _crashes: [String] = []
    private var _checks = 0
    var threat = false
    var clock: TimeInterval = 0

    var terminations: Int { lock.lock(); defer { lock.unlock() }; return _terminations }
    var crashes: [String] { lock.lock(); defer { lock.unlock() }; return _crashes }
    var checks: Int { lock.lock(); defer { lock.unlock() }; return _checks }
    var handlerCalls: Int { lock.lock(); defer { lock.unlock() }; return _threats }

    func noteThreat() { lock.lock(); _threats += 1; lock.unlock() }
    func noteCheck() { lock.lock(); _checks += 1; lock.unlock() }
    func noteTerminate() { lock.lock(); _terminations += 1; lock.unlock() }
    func noteCrash(_ m: String) { lock.lock(); _crashes.append(m); lock.unlock() }
  }

  private var probe: Probe!
  private var watchdog: SecurityWatchdog!

  override func setUp() {
    probe = Probe()
    watchdog = SecurityWatchdog(
      threatCheck: { [probe] in probe!.noteCheck(); return probe!.threat },
      reasonsProvider: { ["reason-a", "reason-b"] },
      uptime: { [probe] in probe!.clock },
      terminateProcess: { [probe] in probe!.noteTerminate() },
      crash: { [probe] in probe!.noteCrash($0) }
    )
  }

  override func tearDown() {
    watchdog.stop()
  }

  private func waitUntil(_ timeout: TimeInterval = 3, _ cond: () -> Bool) -> Bool {
    let end = Date().addingTimeInterval(timeout)
    while Date() < end {
      if cond() { return true }
      Thread.sleep(forTimeInterval: 0.01)
    }
    return cond()
  }

  // lifecycle
  func testInitiallyNotRunning() {
    XCTAssertFalse(watchdog.isRunning)
  }

  func testStartStop() {
    watchdog.start(interval: 0.1, protectionMode: .logOnly)
    XCTAssertTrue(watchdog.isRunning)
    watchdog.stop()
    XCTAssertFalse(watchdog.isRunning)
  }

  func testStopWhenNotRunningIsHarmless() {
    watchdog.stop()
    watchdog.stop()
    XCTAssertFalse(watchdog.isRunning)
  }

  func testSecondStartIsIgnored() {
    probe.threat = true
    watchdog.start(interval: 0.1, protectionMode: .logOnly)
    watchdog.start(interval: 0.1, protectionMode: .terminate)
    XCTAssertTrue(waitUntil { probe.checks >= 2 })
    XCTAssertEqual(probe.terminations, 0, "second start must not replace the running mode")
  }

  func testRestartAfterStop() {
    watchdog.start(interval: 0.1, protectionMode: .logOnly)
    XCTAssertTrue(waitUntil { probe.checks >= 1 })
    watchdog.stop()
    let before = probe.checks
    Thread.sleep(forTimeInterval: 0.3)
    watchdog.start(interval: 0.1, protectionMode: .logOnly)
    XCTAssertTrue(watchdog.isRunning)
    XCTAssertTrue(waitUntil { probe.checks > before + 1 })
  }

  func testStopHaltsFurtherChecks() {
    watchdog.start(interval: 0.1, protectionMode: .logOnly)
    XCTAssertTrue(waitUntil { probe.checks >= 2 })
    watchdog.stop()
    Thread.sleep(forTimeInterval: 0.3)
    let settled = probe.checks
    Thread.sleep(forTimeInterval: 0.4)
    XCTAssertEqual(probe.checks, settled)
  }

  func testRapidStopStartNeverLeavesStaleLoops() {
    for _ in 0..<5 {
      watchdog.start(interval: 0.1, protectionMode: .logOnly)
      watchdog.stop()
    }
    Thread.sleep(forTimeInterval: 0.3)
    let settled = probe.checks
    Thread.sleep(forTimeInterval: 0.4)
    XCTAssertEqual(probe.checks, settled, "a stale loop kept running")
  }

  // threat handling
  func testCleanDeviceTriggersNothing() {
    watchdog.setThreatHandler { [probe] _ in probe!.noteThreat() }
    watchdog.start(interval: 0.1, protectionMode: .terminate)
    XCTAssertTrue(waitUntil { probe.checks >= 3 })
    XCTAssertEqual(probe.handlerCalls, 0)
    XCTAssertEqual(probe.terminations, 0)
    XCTAssertTrue(probe.crashes.isEmpty)
  }

  func testLogOnlyKeepsRunning() {
    probe.threat = true
    watchdog.setThreatHandler { [probe] _ in probe!.noteThreat() }
    watchdog.start(interval: 0.1, protectionMode: .logOnly)
    XCTAssertTrue(waitUntil { probe.handlerCalls >= 2 })
    XCTAssertEqual(probe.terminations, 0)
    XCTAssertTrue(probe.crashes.isEmpty)
    XCTAssertTrue(watchdog.isRunning)
  }

  func testTerminateKillsProcess() {
    probe.threat = true
    watchdog.start(interval: 0.1, protectionMode: .terminate)
    XCTAssertTrue(waitUntil { probe.terminations > 0 })
    XCTAssertTrue(probe.crashes.isEmpty)
  }

  func testThrowExceptionCrashesWithReasons() {
    probe.threat = true
    watchdog.start(interval: 0.1, protectionMode: .throwException)
    XCTAssertTrue(waitUntil { !probe.crashes.isEmpty })
    XCTAssertTrue(probe.crashes[0].contains("reason-a, reason-b"))
    XCTAssertEqual(probe.terminations, 0)
  }

  func testHandlerReceivesReasons() {
    probe.threat = true
    let lock = NSLock()
    var received: [[String]] = []
    watchdog.setThreatHandler { reasons in lock.lock(); received.append(reasons); lock.unlock() }
    watchdog.start(interval: 0.1, protectionMode: .logOnly)
    XCTAssertTrue(waitUntil { lock.lock(); defer { lock.unlock() }; return !received.isEmpty })
    XCTAssertEqual(received[0], ["reason-a", "reason-b"])
  }

  func testHandlerRunsBeforeTermination() {
    probe.threat = true
    let lock = NSLock()
    var order: [String] = []
    let w = SecurityWatchdog(
      threatCheck: { true }, reasonsProvider: { [] }, uptime: { 0 },
      terminateProcess: { lock.lock(); order.append("terminate"); lock.unlock() },
      crash: { _ in })
    w.setThreatHandler { _ in lock.lock(); order.append("handler"); lock.unlock() }
    w.start(interval: 0.1, protectionMode: .terminate)
    defer { w.stop() }
    XCTAssertTrue(waitUntil { lock.lock(); defer { lock.unlock() }; return order.count >= 2 })
    XCTAssertEqual(Array(order.prefix(2)), ["handler", "terminate"])
  }

  func testHandlerCanBeCleared() {
    probe.threat = true
    watchdog.setThreatHandler { [probe] _ in probe!.noteThreat() }
    watchdog.setThreatHandler(nil)
    watchdog.start(interval: 0.1, protectionMode: .logOnly)
    XCTAssertTrue(waitUntil { probe.checks >= 2 })
    XCTAssertEqual(probe.handlerCalls, 0)
  }

  func testNoHandlerIsFine() {
    probe.threat = true
    watchdog.start(interval: 0.1, protectionMode: .terminate)
    XCTAssertTrue(waitUntil { probe.terminations > 0 })
  }

  // interval clamping
  func testZeroIntervalIsClamped() {
    watchdog.start(interval: 0, protectionMode: .logOnly)
    Thread.sleep(forTimeInterval: 0.5)
    // unclamped this would spin thousands of times
    XCTAssertLessThan(probe.checks, 20)
    XCTAssertGreaterThan(probe.checks, 0)
  }

  func testNegativeIntervalIsClamped() {
    watchdog.start(interval: -3, protectionMode: .logOnly)
    Thread.sleep(forTimeInterval: 0.4)
    XCTAssertLessThan(probe.checks, 20)
    XCTAssertGreaterThan(probe.checks, 0)
  }

  // timing gap
  func testLargeClockJumpIsTreatedAsPause() {
    watchdog.setThreatHandler { [probe] _ in probe!.noteThreat() }
    watchdog.start(interval: 0.1, protectionMode: .logOnly)
    Thread.sleep(forTimeInterval: 0.15)
    XCTAssertEqual(probe.handlerCalls, 0)
    probe.clock = 0.1 * 4 + 10
    XCTAssertTrue(waitUntil { probe.handlerCalls > 0 })
  }

  func testSmallClockAdvanceIsNotAPause() {
    watchdog.setThreatHandler { [probe] _ in probe!.noteThreat() }
    watchdog.start(interval: 0.1, protectionMode: .logOnly)
    for _ in 0..<10 {
      probe.clock += 0.04
      Thread.sleep(forTimeInterval: 0.04)
    }
    XCTAssertEqual(probe.handlerCalls, 0)
  }

  func testRestartResetsTimingBaseline() {
    watchdog.setThreatHandler { [probe] _ in probe!.noteThreat() }
    watchdog.start(interval: 0.1, protectionMode: .logOnly)
    watchdog.stop()
    probe.clock = 1_000_000
    watchdog.start(interval: 0.1, protectionMode: .logOnly)
    Thread.sleep(forTimeInterval: 0.3)
    XCTAssertEqual(probe.handlerCalls, 0, "stale baseline caused a false alarm")
  }

  // background / foreground
  func testGapWhileBackgroundedIsNotAThreat() {
    watchdog.setThreatHandler { [probe] _ in probe!.noteThreat() }
    watchdog.start(interval: 0.1, protectionMode: .terminate)
    Thread.sleep(forTimeInterval: 0.15)

    watchdog.appDidEnterBackground()
    probe.clock = 60_000 // process suspended for a minute
    Thread.sleep(forTimeInterval: 0.4)

    XCTAssertEqual(probe.handlerCalls, 0)
    XCTAssertEqual(probe.terminations, 0)
  }

  func testReturningFromBackgroundDoesNotKillApp() {
    watchdog.setThreatHandler { [probe] _ in probe!.noteThreat() }
    watchdog.start(interval: 0.1, protectionMode: .terminate)
    Thread.sleep(forTimeInterval: 0.15)

    watchdog.appDidEnterBackground()
    probe.clock = 60_000
    Thread.sleep(forTimeInterval: 0.3)
    watchdog.appWillEnterForeground()
    Thread.sleep(forTimeInterval: 0.4)

    XCTAssertEqual(probe.terminations, 0, "app was killed when returning from background")
    XCTAssertEqual(probe.handlerCalls, 0)
  }

  func testGapCheckWorksAgainAfterGraceIteration() {
    watchdog.setThreatHandler { [probe] _ in probe!.noteThreat() }
    watchdog.start(interval: 0.1, protectionMode: .logOnly)
    Thread.sleep(forTimeInterval: 0.15)
    watchdog.appDidEnterBackground()
    watchdog.appWillEnterForeground()
    Thread.sleep(forTimeInterval: 0.3)

    probe.clock = 0.1 * 4 + 10
    XCTAssertTrue(waitUntil { probe.handlerCalls > 0 })
  }

  func testRealThreatsStillDetectedInBackground() {
    probe.threat = true
    watchdog.setThreatHandler { [probe] _ in probe!.noteThreat() }
    watchdog.appDidEnterBackground()
    watchdog.start(interval: 0.1, protectionMode: .logOnly)
    XCTAssertTrue(waitUntil { probe.handlerCalls > 0 })
  }

  func testUIKitNotificationsDriveLifecycle() {
    watchdog.setThreatHandler { [probe] _ in probe!.noteThreat() }
    watchdog.start(interval: 0.1, protectionMode: .terminate)
    Thread.sleep(forTimeInterval: 0.15)

    NotificationCenter.default.post(name: UIApplication.didEnterBackgroundNotification, object: nil)
    probe.clock = 60_000
    Thread.sleep(forTimeInterval: 0.3)
    NotificationCenter.default.post(name: UIApplication.willEnterForegroundNotification, object: nil)
    Thread.sleep(forTimeInterval: 0.4)

    XCTAssertEqual(probe.terminations, 0)
  }

  // singleton
  func testSharedIsSingleton() {
    XCTAssertTrue(SecurityWatchdog.shared === SecurityWatchdog.shared)
    XCTAssertFalse(SecurityWatchdog.shared.isRunning)
  }
}
