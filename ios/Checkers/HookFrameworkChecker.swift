import Darwin
import Foundation
import MachO

  /// HookFrameworkChecker
  ///
  /// Detects runtime hooking frameworks such as:
  ///
  /// - Cydia Substrate
  /// - Substitute
  /// - Fishhook
class HookFrameworkChecker: DetectionRule {
  
  func detectHookFramework() -> Bool {
    
    let handle = dlopen(nil, RTLD_NOW)
    
    if dlsym(handle, "MSHookFunction") != nil || dlsym(handle, "fishhook") != nil {
      
      return true
    }
    
    return false
  }
  
  func detectFunctionHook() -> Bool {
    
    guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "malloc") else {
      return false
    }
    
    let addr = UInt(bitPattern: symbol)
    
    if addr < 0x1_0000_0000 {
      return true
    }
    
    return false
  }
  
  func getReasons() -> [String] {
    
    var reasons: [String] = []
    
    if detectHookFramework() {
      reasons.append("Hook framework detected")
    }
    
    if detectFunctionHook() {
      reasons.append("Function hook detected")
    }
    
    return reasons
  }
}
