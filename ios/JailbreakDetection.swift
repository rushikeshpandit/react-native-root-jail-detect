import Foundation

  /// JailbreakDetection
  ///
  /// Public entry point for all device security checks.
  ///
  /// This class acts as a façade that delegates detection
  /// to specialized checker classes.
  ///
  /// Public API remains simple while still allowing
  /// detailed inspection through `getDetectionReasons()`.
@objc
public class JailbreakDetection: NSObject {
  
  private static let jailbreakChecker = JailbreakChecker()
  private static let simulatorChecker = SimulatorChecker()
  private static let debuggerChecker = DebuggerChecker()
  private static let fridaChecker = FridaChecker()
  private static let hookChecker = HookFrameworkChecker()
  private static let advancedChecker = AdvancedSecurityChecker()
  
  /**
   Determines whether the device appears to be jailbroken.
   
   - Returns: true if jailbreak indicators are detected
   */
  @objc
  public static func isDeviceJailbroken() -> Bool {
    
    return jailbreakChecker.isDeviceJailbroken()
    || fridaChecker.isFridaDetected()
    || hookChecker.detectHookFramework()
    || hookChecker.detectFunctionHook()
    || advancedChecker.detectPtrace()
    || advancedChecker.detectDYLDInjection()
  }
  
  /**
   Determines whether the app is running on simulator.
   
   - Returns: true if simulator environment detected
   */
  @objc
  public static func isSimulator() -> Bool {
    return simulatorChecker.isSimulator()
  }
  
  /**
   Determines whether a debugger is attached.
   
   - Returns: true if debugger detected
   */
  @objc
  public static func isDebuggerAttached() -> Bool {
    return debuggerChecker.isDebuggerAttached()
  }
  
  /**
   Returns human-readable detection reasons.
   
   Example:
   [
   "Frida port 27042 open",
   "Cydia application detected"
   ]
   */
  @objc
  public static func getDetectionReasons() -> [String] {
    
    var reasons: [String] = []
    
    reasons += jailbreakChecker.getReasons()
    reasons += simulatorChecker.getReasons()
    reasons += debuggerChecker.getReasons()
    reasons += fridaChecker.getReasons()
    reasons += hookChecker.getReasons()
    reasons += advancedChecker.getReasons()
    
    return Array(Set(reasons))
  }
  
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
  
  @objc
  func stopSecurityWatchdog() {
    SecurityWatchdog.shared.stop()
  }
  
}
