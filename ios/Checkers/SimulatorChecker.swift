import Foundation

  /// SimulatorChecker
  ///
  /// Detects whether the application is running
  /// inside the iOS Simulator.
class SimulatorChecker: DetectionRule {
  
  func isSimulator() -> Bool {
    return !getReasons().isEmpty
  }
  
  func getReasons() -> [String] {
    
    var reasons: [String] = []
    
#if targetEnvironment(simulator)
    reasons.append("Application running in simulator")
#endif
    
    if ProcessInfo.processInfo.environment["SIMULATOR_DEVICE_NAME"] != nil {
      reasons.append("Simulator environment variable detected")
    }
    
    return reasons
  }
}
