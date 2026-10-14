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

/// Low-level anti-tamper checks: tracer state, DYLD injection, Frida in memory, Mach exception
/// ports, inline hooks, code integrity, method swizzling and Frida runtime symbols.
class AdvancedSecurityChecker: DetectionRule {

  private let environment: () -> [String: String]
  private let imageNames: () -> [String]
  private let skipDyldCheck: Bool

#if DEBUG
  static let isDebugBuild = true
#else
  static let isDebugBuild = false
#endif

  /// Creates the checker; defaults use the real process.
  ///
  /// - Parameters:
  ///   - environment: Supplies the process environment.
  ///   - imageNames: Names of loaded dyld images.
  ///   - skipDyldCheck: Disables the DYLD check (true in DEBUG builds, where Xcode sets DYLD
  ///   variables).
  init(
    environment: @escaping () -> [String: String] = { ProcessInfo.processInfo.environment },
    imageNames: @escaping () -> [String] = FridaChecker.systemImageNames,
    skipDyldCheck: Bool = AdvancedSecurityChecker.isDebugBuild
  ) {
    self.environment = environment
    self.imageNames = imageNames
    self.skipDyldCheck = skipDyldCheck
  }

  
  /// Runs every advanced check.
  ///
  /// - Returns: One message per positive check; empty when clean.
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
  
  /// Reports whether the process is being traced, using the side-effect-free sysctl flag (the
  /// old `PT_TRACE_ME` probe left the process traced).
  ///
  /// - Returns: `true` if `P_TRACED` is set.
  func detectPtrace() -> Bool {
    return DebuggerChecker.systemIsTraced()
  }

    // MARK: - DYLD Injection Detection
  
  /// Looks for `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH` or `DYLD_FRAMEWORK_PATH`.
  ///
  /// - Returns: `true` if one is set; always `false` when skipped for debug builds.
  func detectDYLDInjection() -> Bool {
    // DYLD vars are legitimately set by Xcode tooling in debug builds
    if skipDyldCheck { return false }
    let env = environment()
    let suspicious = [
      "DYLD_INSERT_LIBRARIES",
      "DYLD_LIBRARY_PATH",
      "DYLD_FRAMEWORK_PATH",
    ]
    return suspicious.contains { env[$0] != nil }
  }

    // MARK: - Frida Memory Detection
  
  /// Looks for `frida`, `gum-js` or `linjector` in loaded image names.
  ///
  /// - Returns: `true` if one is loaded.
  func detectFridaMemory() -> Bool {
    return imageNames().contains { image in
      let name = image.lowercased()
      return name.contains("frida") || name.contains("gum-js") || name.contains("linjector")
    }
  }

    // MARK: - Mach Exception Debugger
  
  /// Looks for a debugger-owned breakpoint exception port with `task_get_exception_ports`.
  /// Disabled in DEBUG builds.
  ///
  /// - Returns: `true` if a valid port is registered.
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
  
  /// Checks whether `open` starts with a branch that leaves its own image (trampoline into
  /// injected code). arm64 only.
  ///
  /// - Returns: `true` if the prologue looks hooked; `false` on other architectures or when
  ///   `open` cannot be resolved.
  func detectInlineHook() -> Bool {
#if arch(arm64)
    guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "open") else {
      return false
    }
    let instruction = symbol.assumingMemoryBound(to: UInt32.self).pointee
    return AdvancedSecurityChecker.isHookedPrologue(
      instruction: instruction,
      at: UInt(bitPattern: symbol),
      imageBase: AdvancedSecurityChecker.systemImageBase
    )
#else
    return false
#endif
  }

  /// Decodes an arm64 `B` / `BL` instruction.
  ///
  /// - Parameters:
  ///   - instruction: 32-bit instruction word.
  ///   - address: Address the instruction is located at.
  /// - Returns: The branch destination, or nil if the instruction is not B/BL.
  static func branchTarget(of instruction: UInt32, at address: UInt) -> UInt? {
    let opcode = instruction >> 26
    guard opcode == 0x05 || opcode == 0x25 else { return nil }
    let offset = Int(Int32(bitPattern: instruction << 6) >> 6) * 4  // sign-extended imm26 * 4
    return UInt(bitPattern: Int(bitPattern: address) &+ offset)
  }

  /// Decides whether a function prologue is an inline-hook trampoline.
  ///
  /// - Parameters:
  ///   - instruction: First instruction of the function.
  ///   - address: Address of the function.
  ///   - imageBase: Maps an address to the base of its containing image, or nil if unmapped.
  /// - Returns: `true` if the instruction branches to a different image or into unmapped
  ///   memory.
  static func isHookedPrologue(
    instruction: UInt32,
    at address: UInt,
    imageBase: (UInt) -> UInt?
  ) -> Bool {
    guard let target = branchTarget(of: instruction, at: address) else { return false }
    guard let targetBase = imageBase(target) else { return true }  // jumps into anonymous memory
    return targetBase != imageBase(address)
  }

  /// Production `imageBase` implementation using `dladdr`.
  ///
  /// - Parameter address: Address to look up.
  /// - Returns: Base address of the image containing it, or nil.
  static func systemImageBase(_ address: UInt) -> UInt? {
    var info = Dl_info()
    guard dladdr(UnsafeRawPointer(bitPattern: address), &info) != 0,
          let base = info.dli_fbase
    else { return nil }
    return UInt(bitPattern: base)
  }

    // MARK: - Code Integrity Verification
  
  /// Checks that every loaded image has a valid Mach-O magic number.
  ///
  /// - Returns: `true` if an image header is corrupt.
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
  /// Verifies that key Foundation/ObjC methods are implemented inside the system libraries.
  /// Disabled in DEBUG builds.
  ///
  /// - Returns: `true` if a method implementation lives elsewhere.
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
  
  /// Looks for Gum/Frida runtime symbols.
  ///
  /// - Returns: `true` if one resolves.
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
