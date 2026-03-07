import Darwin
import Foundation
import MachO
import UIKit

  /// FridaChecker
  ///
  /// Detects runtime instrumentation frameworks
  /// such as Frida.
class FridaChecker: DetectionRule {
  
  func isFridaDetected() -> Bool {
    return !getReasons().isEmpty
  }
  
  func getReasons() -> [String] {
    
    var reasons: [String] = []
    
    if checkFridaLibraries() {
      reasons.append("Frida library loaded")
    }
    
    if checkFridaThreads() {
      reasons.append("Frida thread detected")
    }
    
    if detectFridaSymbols() {
      reasons.append("Frida symbols detected")
    }
    if checkFridaDynamicLibs() {
      reasons.append("Frida dynamic libraries detected")
    }
    
    if TCPCheck.connect(port: 27042) {
      reasons.append("Frida default port 27042 open")
    }
    
    return reasons
  }
  
    /// Detect Frida dylibs
  private func checkFridaLibraries() -> Bool {
    
    let libs = ["Frida", "frida-agent", "FridaGadget"]
    
    for i in 0..<_dyld_image_count() {
      
      if let image = _dyld_get_image_name(i) {
        
        let name = String(cString: image).lowercased()
        
        for lib in libs {
          if name.contains(lib.lowercased()) {
            return true
          }
        }
      }
    }
    
    return false
  }
  
    /// Detect suspicious thread names
  private func checkFridaThreads() -> Bool {
    
    var threads: thread_act_array_t?
    var count: mach_msg_type_number_t = 0
    
    guard task_threads(mach_task_self_, &threads, &count) == KERN_SUCCESS,
          let threadList = threads
    else {
      return false
    }
    
    defer {
      vm_deallocate(
        mach_task_self_,
        vm_address_t(bitPattern: threadList),
        vm_size_t(count) * vm_size_t(MemoryLayout<thread_t>.stride)
      )
    }
    
    for i in 0..<Int(count) {
      
      guard let pthread = pthread_from_mach_thread_np(threadList[i]) else {
        continue
      }
      
      var nameBuffer = [CChar](repeating: 0, count: 256)
      
      pthread_getname_np(pthread, &nameBuffer, 256)
      
      let name = String(cString: nameBuffer).lowercased()
      
      if name.contains("frida") || name.contains("gum") {
        return true
      }
    }
    
    return false
  }
  
    /// Detect Frida exported symbols
  private func detectFridaSymbols() -> Bool {
    
    let symbols = [
      "frida_agent_main",
      "gum_script_backend_create",
      "gum_init",
      "frida_agent_main",
      "frida",
    ]
    
    for sym in symbols {
      
      if dlsym(UnsafeMutableRawPointer(bitPattern: -2), sym) != nil {
        return true
      }
    }
    
    return false
  }
  
  /**
   Determines whether a Frida libraries are present or not.
   
   - Returns: true if Frida libraries are present
   */
  
  private func checkFridaDynamicLibs() -> Bool {
    let suspiciousPaths = [
      "/usr/lib/frida",
      "/Library/MobileSubstrate/DynamicLibraries/frida",
    ]
    
    return suspiciousPaths.contains {
      FileManager.default.fileExists(atPath: $0)
    }
  }
}
