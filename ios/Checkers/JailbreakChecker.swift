import Foundation
import UIKit

/// Detects jailbreak artifacts: known files, a writable system location, jailbreak URL schemes
/// and restricted paths.
class JailbreakChecker: DetectionRule {

  private let fileExists: (String) -> Bool
  private let canWriteFile: (String) -> Bool
  private let canOpenURL: (URL) -> Bool
  private let pathAccessible: (String) -> Bool
  private let skipFileChecks: Bool

  /// Creates the checker. Defaults use the real system; each dependency can be replaced for
  /// tests.
  ///
  /// - Parameters:
  ///   - fileExists: Tells whether a path exists.
  ///   - canWriteFile: Tries to write and delete a probe file at a path.
  ///   - canOpenURL: Asks UIKit whether a URL can be opened.
  ///   - pathAccessible: Tells whether `stat` succeeds on a path.
  ///   - skipFileChecks: Skips the file-existence check; true on the simulator, where host
  ///   files would false-positive.
  init(
    fileExists: @escaping (String) -> Bool = { FileManager.default.fileExists(atPath: $0) },
    canWriteFile: @escaping (String) -> Bool = JailbreakChecker.systemCanWrite,
    canOpenURL: @escaping (URL) -> Bool = JailbreakChecker.systemCanOpen,
    pathAccessible: @escaping (String) -> Bool = JailbreakChecker.systemPathAccessible,
    skipFileChecks: Bool = JailbreakChecker.isSimulatorBuild
  ) {
    self.fileExists = fileExists
    self.canWriteFile = canWriteFile
    self.canOpenURL = canOpenURL
    self.pathAccessible = pathAccessible
    self.skipFileChecks = skipFileChecks
  }

#if targetEnvironment(simulator)
  static let isSimulatorBuild = true
#else
  static let isSimulatorBuild = false
#endif
  
  /// Whether any jailbreak indicator is present.
  ///
  /// - Returns: `true` if `getReasons()` is not empty.
  func isDeviceJailbroken() -> Bool {
    return !getReasons().isEmpty
  }
  
  /// Runs all jailbreak heuristics.
  ///
  /// - Returns: One message per positive heuristic; empty on a clean device.
  func getReasons() -> [String] {
    
    var reasons: [String] = []
    
    if hasJailbreakFiles() {
      reasons.append("Jailbreak related files detected")
    }
    
    if canWriteRestrictedDirectory() {
      reasons.append("Writable restricted system directory")
    }
    
    if canOpenJailbreakSchemes() {
      reasons.append("Jailbreak URL scheme detected")
    }
    
    if canAccessRestrictedPaths() {
      reasons.append("Restricted system paths accessible")
    }
    
    return reasons
  }
  
  /// Looks for the known jailbreak files, unless file checks are skipped.
  ///
  /// - Returns: `true` if one exists.
  private func hasJailbreakFiles() -> Bool {
    if skipFileChecks { return false }
    return SecurityConstants.jailbreakFilePaths.contains { fileExists($0) }
  }

  /// Tries to write `/private/jb_test.txt`, which only succeeds outside the sandbox.
  ///
  /// - Returns: `true` if the write succeeded.
  private func canWriteRestrictedDirectory() -> Bool {
    return canWriteFile("/private/jb_test.txt")
  }

  /// Checks whether Cydia/Sileo/Zebra-style URL schemes are registered.
  ///
  /// - Returns: `true` if any scheme can be opened.
  private func canOpenJailbreakSchemes() -> Bool {
    return SecurityConstants.jailbreakURLSchemes.contains { scheme in
      guard let url = URL(string: scheme) else { return false }
      return canOpenURL(url)
    }
  }

  /// Checks whether restricted system paths are visible to the sandboxed app.
  ///
  /// - Returns: `true` if any path is accessible.
  private func canAccessRestrictedPaths() -> Bool {
    return SecurityConstants.restrictedPaths.contains { pathAccessible($0) }
  }

  // MARK: - System implementations

  /// Production implementation of the write probe; the probe file is removed again.
  ///
  /// - Parameter path: File path to write.
  /// - Returns: `true` if writing and deleting succeeded.
  static func systemCanWrite(_ path: String) -> Bool {
    do {
      try "test".write(toFile: path, atomically: true, encoding: .utf8)
      try FileManager.default.removeItem(atPath: path)
      return true
    } catch {
      return false
    }
  }

  /// Production implementation of the URL-scheme probe, using `UIApplication.canOpenURL`.
  ///
  /// - Parameter url: URL whose scheme is tested.
  /// - Returns: `true` if it can be opened; `false` when no shared application is available.
  static func systemCanOpen(_ url: URL) -> Bool {
    guard let app = UIApplication.value(forKey: "sharedApplication") as? UIApplication else {
      return false
    }
    return app.canOpenURL(url)
  }

  /// Production implementation of the path probe, using `stat`.
  ///
  /// - Parameter path: Path to test.
  /// - Returns: `true` if `stat` succeeds.
  static func systemPathAccessible(_ path: String) -> Bool {
    var statInfo = stat()
    return stat(path, &statInfo) == 0
  }
}
