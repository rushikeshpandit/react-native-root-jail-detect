/// Contract implemented by every detector: it can explain, in human-readable text, what it
/// found.
protocol DetectionRule {
  /// Runs the detector's checks.
  ///
  /// - Returns: One message per positive check; empty when nothing was found.
  func getReasons() -> [String]
}
