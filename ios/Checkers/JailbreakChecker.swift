import Foundation
import UIKit

  /// JailbreakChecker
  ///
  /// Performs filesystem and system checks commonly used
  /// to detect jailbroken iOS devices.
class JailbreakChecker: DetectionRule {
  
  func isDeviceJailbroken() -> Bool {
    return !getReasons().isEmpty
  }
  
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
  
    /// Detect known jailbreak files
  private func hasJailbreakFiles() -> Bool {
#if targetEnvironment(simulator)
      // SSH paths are macOS host paths — skip entirely on simulator
    return false
#else
    for path in SecurityConstants.jailbreakFilePaths {
      if FileManager.default.fileExists(atPath: path) {
        return true
      }
    }
    
    return false
#endif
  }
  
    /// Attempt write in protected directory
  private func canWriteRestrictedDirectory() -> Bool {
    
    let path = "/private/jb_test.txt"
    
    do {
      try "test".write(toFile: path, atomically: true, encoding: .utf8)
      try FileManager.default.removeItem(atPath: path)
      return true
    } catch {
      return false
    }
  }
  
    /// Detect jailbreak URL schemes
  private func canOpenJailbreakSchemes() -> Bool {
    
    guard let app = UIApplication.value(forKey: "sharedApplication") as? UIApplication else {
      return false
    }
    
    for scheme in SecurityConstants.jailbreakURLSchemes {
      
      if let url = URL(string: scheme), app.canOpenURL(url) {
        return true
      }
    }
    
    return false
  }
  
    /// Detect restricted paths
  private func canAccessRestrictedPaths() -> Bool {
    
    for path in SecurityConstants.restrictedPaths {
      
      var statInfo = stat()
      
      if stat(path, &statInfo) == 0 {
        return true
      }
    }
    
    return false
  }
}
