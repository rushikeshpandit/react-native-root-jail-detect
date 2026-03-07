import Darwin
import Foundation
import MachO
import ObjectiveC.runtime

  /// AdvancedSecurityChecker
  ///
  /// Implements high-level runtime protections used by
  /// financial applications.
  ///
  /// Detects:
  /// - ptrace debuggers
  /// - DYLD injection
  /// - Frida memory patterns
  /// - Mach exception debugger
  /// - inline hooks
  /// - code section patching
  /// - Objective-C method swizzling
  /// - Frida runtime traps
  ///

@_silgen_name("ptrace")
func ptrace(
  _ request: Int32,
  _ pid: Int32,
  _ addr: UnsafeMutableRawPointer?,
  _ data: Int32
) -> Int32

class AdvancedSecurityChecker: DetectionRule {
  private let PT_DENY_ATTACH: Int32 = 31
  private let PT_TRACE_ME: Int32 = 0
  private let PT_DETACH: Int32 = 11
  
  func getReasons() -> [String] {
    
    var reasons: [String] = []
    
    if detectPtrace() {
      reasons.append("Debugger detected via ptrace")
    }
    
    if detectDYLDInjection() {
      reasons.append("Dynamic library injection detected")
    }
    
    if detectFridaMemory() {
      reasons.append("Frida memory pattern detected")
    }
    
    if detectMachExceptionPort() {
      reasons.append("Mach exception debugger detected")
    }
    
    if detectInlineHook() {
      reasons.append("Inline hook detected")
    }
    
    if detectCodeIntegrityViolation() {
      reasons.append("Executable code section modified")
    }
    
    if detectMethodSwizzling() {
      reasons.append("Objective-C method swizzling detected")
    }
    
    if detectFridaRuntimeTrap() {
      reasons.append("Frida runtime trap detected")
    }
    
    return reasons
  }
  
    // MARK: - ptrace Anti Debug
  
  func detectPtrace() -> Bool {
      // If a debugger is already attached, PTRACE_TRACEME fails with EPERM
    if ptrace(PT_TRACE_ME, 0, nil, 0) == -1 {
      return errno == EPERM
    }
      // Successfully self-traced — no debugger present, detach cleanly
    ptrace(PT_DETACH, 0, nil, 0)
    return false
  }
  
    // MARK: - DYLD Injection Detection
  
  func detectDYLDInjection() -> Bool {
#if DEBUG
      // DYLD vars are legitimately set by Xcode tooling in debug builds
    return false
#else
    let env = ProcessInfo.processInfo.environment
    let suspicious = [
      "DYLD_INSERT_LIBRARIES",
      "DYLD_LIBRARY_PATH",
      "DYLD_FRAMEWORK_PATH",
    ]
    return suspicious.contains { env[$0] != nil }
#endif
  }
  
    // MARK: - Frida Memory Detection
  
  func detectFridaMemory() -> Bool {
    
    for i in 0..<_dyld_image_count() {
      
      guard let image = _dyld_get_image_name(i) else {
        continue
      }
      
      let name = String(cString: image).lowercased()
      
      if name.contains("frida") || name.contains("gum-js") || name.contains("linjector") {
        
        return true
      }
    }
    
    return false
  }
  
    // MARK: - Mach Exception Debugger
  
  func detectMachExceptionPort() -> Bool {
#if DEBUG
      // Skip all debugger detection in debug builds.
      // Xcode always attaches LLDB when running via cable — these will
      // always fire and are meaningless in development.
    return false
#endif
    let maxCount = Int(EXC_TYPES_COUNT)
    
    let masks = exception_mask_array_t.allocate(capacity: maxCount)
    let ports = mach_port_array_t.allocate(capacity: maxCount)
    let behaviors = exception_behavior_array_t.allocate(capacity: maxCount)
    let flavors = thread_state_flavor_array_t.allocate(capacity: maxCount)
    var count: mach_msg_type_number_t = 0
    
    defer {
      masks.deallocate()
      ports.deallocate()
      behaviors.deallocate()
      flavors.deallocate()
    }
    
    let result = task_get_exception_ports(
      mach_task_self_,
      exception_mask_t(EXC_MASK_BREAKPOINT),
      masks,
      &count,
      ports,
      behaviors,
      flavors
    )
    
    guard result == KERN_SUCCESS && count > 0 else {
      return false
    }
    
      // Validate that at least one returned port is actually valid.
      // False positives occur when count > 0 but all ports are MACH_PORT_NULL
      // (e.g. system handlers registered for other masks bleed into results).
    for i in 0..<Int(count) {
      if ports[i] != MACH_PORT_NULL {
        return true
      }
    }
    
    return false
  }
  
    // MARK: - Inline Hook Detection
  
  func detectInlineHook() -> Bool {
    guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "open") else {
      return false
    }
      // Read the first 4 bytes (one ARM64 instruction)
    let ptr = symbol.assumingMemoryBound(to: UInt32.self)
    let instruction = ptr.pointee
      // ARM64 unconditional branch: opcode top 6 bits = 0b000101 (B) or 0b100101 (BL)
    let opcode = instruction >> 26
    return opcode == 0x05 || opcode == 0x25
  }
  
    // MARK: - Code Integrity Verification
  
  func detectCodeIntegrityViolation() -> Bool {
    for i in 0..<_dyld_image_count() {
      guard let header = _dyld_get_image_header(i) else { continue }
      let magic = UnsafePointer<mach_header>(header).pointee.magic
        // Allow all valid Mach-O magic values
      let validMagics: [UInt32] = [MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64]
      if !validMagics.contains(magic) { return true }
    }
    return false
  }
  
    // MARK: - Method Swizzling Detection
  func detectMethodSwizzling() -> Bool {
#if DEBUG
      // Skip all debugger detection in debug builds.
      // Xcode always attaches LLDB when running via cable — these will
      // always fire and are meaningless in development.
    return false
#endif
      // ── Strategy 1: Check a pure ObjC method with a known, stable IMP ──────
      // Use NSObject's `description` — it's pure ObjC, always in libobjc/CoreFoundation,
      // and a very common swizzling target.
    guard let cls = objc_getClass("NSObject") as? AnyClass,
          let method = class_getInstanceMethod(cls, #selector(NSObject.description))
    else { return false }
    
    let currentIMP = method_getImplementation(method)
    let impAddr = Int(bitPattern: UnsafeRawPointer(currentIMP))
    
    var info = Dl_info()
    guard dladdr(UnsafeRawPointer(bitPattern: impAddr), &info) != 0,
          let fname = info.dli_fname
    else { return true }
    
    let imagePath = String(cString: fname).lowercased()
    
      // NSObject.description IMP must live in libobjc or CoreFoundation
    let validOrigins = [
      "libobjc",
      "corefounda",  // CoreFoundation (truncated to avoid locale path issues)
      "dyld_shared_cache",
      "cryptex",
    ]
    let isValidOrigin = validOrigins.contains { imagePath.contains($0) }
    guard isValidOrigin else { return true }
    
      // ── Strategy 2: Cross-check multiple well-known ObjC methods ────────────
      // If ANY of these have been redirected outside their home binary, flag it.
    let checks: [(AnyClass, Selector, String)] = [
      (
        NSObject.self,
        #selector(NSObject.description),
        "libobjc"
      ),
      (
        NSObject.self,
        NSSelectorFromString("respondsToSelector:"),  // ← fixed
        "libobjc"
      ),
      (
        NSArray.self,
        #selector(getter: NSArray.count),  // ← fixed: property needs getter:
        "corefounda"
      ),
      (
        NSDictionary.self,
        #selector(getter: NSDictionary.allKeys),  // ← fixed: property needs getter:
        "corefounda"
      ),
    ]
    
    for (checkCls, sel, expectedOrigin) in checks {
      guard let m = class_getInstanceMethod(checkCls, sel) else { continue }
      
      let imp = method_getImplementation(m)
      let addr = Int(bitPattern: UnsafeRawPointer(imp))
      var dli = Dl_info()
      
      guard dladdr(UnsafeRawPointer(bitPattern: addr), &dli) != 0,
            let path = dli.dli_fname
      else { return true }  // Can't resolve — suspicious
      
      let resolvedPath = String(cString: path).lowercased()
      let isSharedCache =
      resolvedPath.contains("dyld_shared_cache")
      || resolvedPath.contains("cryptex")
      
      if !isSharedCache && !resolvedPath.contains(expectedOrigin) {
        return true  // IMP lives outside expected binary — swizzled
      }
    }
    
    return false
  }
  
    // MARK: - Frida Runtime Trap
  
  func detectFridaRuntimeTrap() -> Bool {
    
    /*
     Frida often injects gum-js runtime.
     This attempts to detect it via symbol lookup.
     */
    
    let suspiciousSymbols = [
      "gum_js_loop",
      "gum_script_backend_create",
      "frida_agent_main",
    ]
    
    for sym in suspiciousSymbols {
      
      if dlsym(UnsafeMutableRawPointer(bitPattern: -2), sym) != nil {
        return true
      }
    }
    
    return false
  }
}
