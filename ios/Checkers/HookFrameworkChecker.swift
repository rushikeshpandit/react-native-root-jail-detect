import Darwin
import Foundation
import MachO

/// Detects hooking frameworks (Substrate, fishhook) and a hooked `malloc`.
class HookFrameworkChecker: DetectionRule {

  private let hookSymbolExists: (String) -> Bool
  private let mallocAddress: () -> UInt?

  /// Creates the checker; defaults use the real dynamic linker.
  ///
  /// - Parameters:
  ///   - hookSymbolExists: Tells whether a symbol is present in the process.
  ///   - mallocAddress: Returns the address `malloc` resolves to.
  init(
    hookSymbolExists: @escaping (String) -> Bool = HookFrameworkChecker.systemSymbolExists,
    mallocAddress: @escaping () -> UInt? = HookFrameworkChecker.systemMallocAddress
  ) {
    self.hookSymbolExists = hookSymbolExists
    self.mallocAddress = mallocAddress
  }

  /// Looks for the `MSHookFunction` and `fishhook` symbols.
  ///
  /// - Returns: `true` if either exists.
  func detectHookFramework() -> Bool {
    return hookSymbolExists("MSHookFunction") || hookSymbolExists("fishhook")
  }

  /// Checks that `malloc` lives in the system shared cache; an address below 4 GB means it was
  /// redirected.
  ///
  /// - Returns: `true` if the address is below `0x1_0000_0000`; `false` if it cannot be
  ///   resolved.
  func detectFunctionHook() -> Bool {
    guard let addr = mallocAddress() else { return false }
    return addr < 0x1_0000_0000
  }

  /// Runs both hook checks.
  ///
  /// - Returns: One message per positive check; empty when clean.
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

  // MARK: - System implementations

  /// Production symbol lookup with `dlsym` on the main program.
  ///
  /// - Parameter name: Symbol name.
  /// - Returns: `true` if the symbol resolves.
  static func systemSymbolExists(_ name: String) -> Bool {
    let handle = dlopen(nil, RTLD_NOW)
    return dlsym(handle, name) != nil
  }

  /// Resolves `malloc` with `dlsym`.
  ///
  /// - Returns: Its address, or nil if unresolved.
  static func systemMallocAddress() -> UInt? {
    guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "malloc") else {
      return nil
    }
    return UInt(bitPattern: symbol)
  }
}
