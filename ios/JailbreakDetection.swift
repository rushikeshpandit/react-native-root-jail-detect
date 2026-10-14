import Foundation

/// Facade over all iOS detectors; the Swift module and the watchdog talk only to this class.
@objc
public class JailbreakDetection: NSObject {
  
  private static let jailbreakChecker = JailbreakChecker()
  private static let simulatorChecker = SimulatorChecker()
  private static let debuggerChecker = DebuggerChecker()
  private static let fridaChecker = FridaChecker()
  private static let hookChecker = HookFrameworkChecker()
  private static let advancedChecker = AdvancedSecurityChecker()
  
  /// Decides whether the device is jailbroken or instrumented: jailbreak artifacts, Frida, hook
  /// frameworks, ptrace/tracer state and DYLD injection. Simulators and debuggers alone do not
  /// count.
  ///
  /// - Returns: `true` if any indicator was found.
  @objc
  public static func isDeviceJailbroken() -> Bool {
    
    return jailbreakChecker.isDeviceJailbroken()
    || fridaChecker.isFridaDetected()
    || hookChecker.detectHookFramework()
    || hookChecker.detectFunctionHook()
    || advancedChecker.detectPtrace()
    || advancedChecker.detectDYLDInjection()
  }
  
  /// Reports whether the app runs in the iOS simulator.
  ///
  /// - Returns: `true` in the simulator.
  @objc
  public static func isSimulator() -> Bool {
    return simulatorChecker.isSimulator()
  }
  
  /// Reports whether a debugger is attached. Always `false` in DEBUG builds, where Xcode
  /// attaches one by design.
  ///
  /// - Returns: `true` if the process is being traced.
  @objc
  public static func isDebuggerAttached() -> Bool {
    return debuggerChecker.isDebuggerAttached()
  }
  
  /// Reasons limited to what the watchdog acts on: everything except simulator findings.
  ///
  /// - Returns: De-duplicated, human-readable reasons.
  @objc
  public static func getThreatReasons() -> [String] {
    return collectReasons(includeSimulator: false)
  }

  /// All reasons from every detector, including simulator findings.
  ///
  /// - Returns: De-duplicated, human-readable reasons; empty when nothing was found.
  @objc
  public static func getDetectionReasons() -> [String] {
    return collectReasons(includeSimulator: true)
  }

  /// Gathers reasons from the detectors in a fixed order.
  ///
  /// - Parameter includeSimulator: Whether simulator findings are included.
  /// - Returns: De-duplicated reasons.
  private static func collectReasons(includeSimulator: Bool) -> [String] {
    
    var reasons: [String] = []
    
    reasons += jailbreakChecker.getReasons()
    if includeSimulator {
      reasons += simulatorChecker.getReasons()
    }
    reasons += debuggerChecker.getReasons()
    reasons += fridaChecker.getReasons()
    reasons += hookChecker.getReasons()
    reasons += advancedChecker.getReasons()
    
    return Array(Set(reasons))
  }
  
  /// Legacy Objective-C entry point that starts the shared watchdog. The React Native bridge
  /// uses `RootJailDetect.startSecurityWatchdog` instead.
  ///
  /// - Parameters:
  ///   - interval: Interval in milliseconds.
  ///   - protectionMode: `TERMINATE`, `THROW_EXCEPTION`; anything else means log only.
  @objc
  func startSecurityWatchdog(
    _ interval: NSNumber,
    protectionMode: NSString
  ) {
    
    let modeString = protectionMode as String
    
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
      interval: interval.doubleValue / 1000,
      protectionMode: mode
    )
  }
  
  /// Legacy Objective-C entry point that stops the shared watchdog.
  @objc
  func stopSecurityWatchdog() {
    SecurityWatchdog.shared.stop()
  }
  
}
