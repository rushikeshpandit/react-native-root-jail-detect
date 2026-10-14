import Foundation
import React

/// React Native native module for iOS. Exposes the detectors to JavaScript through Promises and
/// forwards watchdog threats as `onSecurityThreat` events. Subclasses `RCTEventEmitter`, which
/// also supplies `addListener` / `removeListeners`.
@objc(RootJailDetect)
class RootJailDetect: RCTEventEmitter {

  static let threatEvent = "onSecurityThreat"

  private var hasListeners = false

  /// Declares the events this module can emit.
  ///
  /// - Returns: `["onSecurityThreat"]`.
  override func supportedEvents() -> [String]! {
    return [RootJailDetect.threatEvent]
  }

  /// Called by React Native when the first JS listener subscribes; enables event delivery.
  override func startObserving() {
    hasListeners = true
  }

  /// Called by React Native when the last JS listener unsubscribes; disables event delivery.
  override func stopObserving() {
    hasListeners = false
  }


  /// Tells React Native the module needs no main-thread initialisation.
  ///
  /// - Returns: Always `false`.
  @objc override static func requiresMainQueueSetup() -> Bool {
    return false
  }

  /// Runs all jailbreak/instrumentation checks.
  ///
  /// - Parameters:
  ///   - resolve: Called with `true` if the device is jailbroken, `false` otherwise.
  ///   - reject: Unused; this call does not fail.
  @objc func isDeviceCompromised(
    _ resolve: RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    let isJailbroken = JailbreakDetection.isDeviceJailbroken()
    resolve(isJailbroken)
  }

  /// Checks whether the app runs in the simulator.
  ///
  /// - Parameters:
  ///   - resolve: Called with `true` in the simulator.
  ///   - reject: Unused; this call does not fail.
  @objc func isSimulator(
    _ resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    let isSim = JailbreakDetection.isSimulator()
    resolve(isSim)
  }

  /// Checks whether a debugger is attached (always `false` in DEBUG builds).
  ///
  /// - Parameters:
  ///   - resolve: Called with `true` if the process is traced.
  ///   - reject: Unused; this call does not fail.
  @objc func isDebuggerAttached(
    _ resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    let isAttached = JailbreakDetection.isDebuggerAttached()
    resolve(isAttached)
  }

  /// Collects human-readable reasons from all detectors.
  ///
  /// - Parameters:
  ///   - resolve: Called with an array of unique strings (empty when clean).
  ///   - reject: Unused; this call does not fail.
  @objc
  func getDetectionReasons(
    _ resolve: RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    let reasons = JailbreakDetection.getDetectionReasons()
    resolve(Array(Set(reasons)))
  }

  // This method `startSecurityWatchdog` in the `RootJailDetect` class is responsible for starting a
  // security watchdog feature. It takes in an `options` dictionary parameter which contains
  // information about the interval and protection mode for the watchdog.
  /// Starts the runtime watchdog and connects its threat handler to the `onSecurityThreat` JS
  /// event (delivered only while JS listens). Ignored if it is already running.
  ///
  /// - Parameter options: Dictionary with optional `interval` (milliseconds as a number,
  ///   default 3000, native minimum 100) and `protectionMode` (`LOG_ONLY` default,
  ///   `THROW_EXCEPTION`, `TERMINATE`; unknown means `LOG_ONLY`).
  @objc
  func startSecurityWatchdog(_ options: NSDictionary) {

    let interval = options["interval"] as? Double ?? 3000
    let modeString = options["protectionMode"] as? String ?? "LOG_ONLY"

    let mode: ProtectionMode

    switch modeString {
    case "TERMINATE":
      mode = .terminate
    case "THROW_EXCEPTION":
      mode = .throwException
    default:
      mode = .logOnly
    }

    SecurityWatchdog.shared.setThreatHandler { [weak self] reasons in
      guard let self = self, self.hasListeners else { return }
      self.sendEvent(
        withName: RootJailDetect.threatEvent,
        body: [
          "reasons": reasons,
          "timestamp": Date().timeIntervalSince1970 * 1000,
        ]
      )
    }

    SecurityWatchdog.shared.start(
      interval: interval / 1000,
      protectionMode: mode
    )
  }

  // The `@objc func stopSecurityWatchdog()` method in the `RootJailDetect` class is responsible for
  // stopping a security watchdog feature. When this method is called, it invokes the `stop()` method
  // of the `SecurityWatchdog` class to halt the monitoring and protection mechanisms put in place by
  // the security watchdog. This action effectively disables the security monitoring that was
  // previously initiated by the `startSecurityWatchdog()` method.
  /// Stops the runtime watchdog. Safe to call when it is not running.
  @objc
  func stopSecurityWatchdog() {
    SecurityWatchdog.shared.stop()
  }

  /// Reports whether the watchdog loop is active.
  ///
  /// - Parameters:
  ///   - resolve: Called with `true` while it runs.
  ///   - reject: Unused; this call does not fail.
  @objc
  func isSecurityWatchdogRunning(
    _ resolve: RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    resolve(SecurityWatchdog.shared.isRunning)
  }
}
