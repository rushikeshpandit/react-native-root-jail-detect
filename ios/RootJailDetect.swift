import Foundation
import React

/// RootJailDetect
///
/// React Native native module that exposes iOS device
/// security checks (jailbreak detection, simulator detection,
/// and debugger detection) to the JavaScript layer.
///
/// This class acts as a bridge between React Native
/// and native security utilities.
@objc(RootJailDetect)
class RootJailDetect: NSObject {

  /**
   * Indicates whether the module must be initialized
   * on the main (UI) thread.
   *
   * Returning false allows React Native to initialize
   * this module on a background thread, improving performance.
   *
   * @return false to allow background initialization
   */
  @objc static func requiresMainQueueSetup() -> Bool {
    return false
  }

  /**
   * Checks whether the current device is compromised (jailbroken).
   *
   * Internally invokes native jailbreak-detection heuristics
   * and returns the result asynchronously via a Promise.
   *
   * @param resolve Promise resolver that receives true if the
   *                device is jailbroken, false otherwise
   * @param reject  Promise rejecter used when an error occurs
   */
  @objc func isDeviceCompromised(
    _ resolve: RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    let isJailbroken = JailbreakDetection.isDeviceJailbroken()
    resolve(isJailbroken)
  }

  /**
   * Determines whether the application is running
   * inside an iOS simulator environment.
   *
   * Simulators are often used for testing and may not
   * reflect real-device security conditions.
   *
   * @param resolve Promise resolver that receives true if
   *                running in simulator, false otherwise
   * @param reject  Promise rejecter used when an error occurs
   */
  @objc func isSimulator(
    _ resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    let isSim = JailbreakDetection.isSimulator()
    resolve(isSim)
  }

  /**
   * Checks whether a debugger is currently attached
   * to the running application process.
   *
   * This helps detect runtime inspection,
   * reverse engineering, and debugging attempts.
   *
   * @param resolve Promise resolver that receives true if
   *                a debugger is attached, false otherwise
   * @param reject  Promise rejecter used when an error occurs
   */
  @objc func isDebuggerAttached(
    _ resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    let isAttached = JailbreakDetection.isDebuggerAttached()
    resolve(isAttached)
  }

  /**
   Returns human-readable detection reasons.
  
   This mirrors the Kotlin implementation and allows
   SDK consumers to inspect why the device was flagged.
  
   Example:
   [
   "Frida port 27042 open",
   "Cydia application detected"
   ]
   */
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
  @objc
  func stopSecurityWatchdog() {
    SecurityWatchdog.shared.stop()
  }
}
