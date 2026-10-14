import Foundation

/// Detects the iOS simulator.
class SimulatorChecker: DetectionRule {

  private let isSimulatorBuild: Bool
  private let environment: () -> [String: String]

  /// Creates the checker; defaults read the real build flag and environment.
  ///
  /// - Parameters:
  ///   - isSimulatorBuild: Compile-time simulator flag.
  ///   - environment: Supplies the process environment.
  init(
    isSimulatorBuild: Bool = JailbreakChecker.isSimulatorBuild,
    environment: @escaping () -> [String: String] = { ProcessInfo.processInfo.environment }
  ) {
    self.isSimulatorBuild = isSimulatorBuild
    self.environment = environment
  }
  
  /// Whether any simulator indicator is present.
  ///
  /// - Returns: `true` if `getReasons()` is not empty.
  func isSimulator() -> Bool {
    return !getReasons().isEmpty
  }
  
  /// Checks the simulator build flag and the `SIMULATOR_DEVICE_NAME` environment variable.
  ///
  /// - Returns: One message per positive check; empty on a real device.
  func getReasons() -> [String] {
    
    var reasons: [String] = []
    
if isSimulatorBuild {
      reasons.append("Application running in simulator")
    }
    
    if environment()["SIMULATOR_DEVICE_NAME"] != nil {
      reasons.append("Simulator environment variable detected")
    }
    
    return reasons
  }
}
