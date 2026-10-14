import Darwin
import Foundation
import MachO
import UIKit

/// Detects the Frida instrumentation toolkit.
class FridaChecker: DetectionRule {

  private let imageNames: () -> [String]
  private let threadNames: () -> [String]
  private let symbolExists: (String) -> Bool
  private let fileExists: (String) -> Bool
  private let portOpen: (Int) -> Bool

  /// Creates the checker; defaults use the real process state.
  ///
  /// - Parameters:
  ///   - imageNames: Names of loaded dyld images.
  ///   - threadNames: Names of the process's threads.
  ///   - symbolExists: Tells whether a symbol resolves.
  ///   - fileExists: Tells whether a path exists.
  ///   - portOpen: Tells whether a local TCP port accepts connections.
  init(
    imageNames: @escaping () -> [String] = FridaChecker.systemImageNames,
    threadNames: @escaping () -> [String] = FridaChecker.systemThreadNames,
    symbolExists: @escaping (String) -> Bool = FridaChecker.systemSymbolExists,
    fileExists: @escaping (String) -> Bool = { FileManager.default.fileExists(atPath: $0) },
    portOpen: @escaping (Int) -> Bool = { TCPCheck.connect(port: $0) }
  ) {
    self.imageNames = imageNames
    self.threadNames = threadNames
    self.symbolExists = symbolExists
    self.fileExists = fileExists
    self.portOpen = portOpen
  }

  /// Whether any Frida indicator is present.
  ///
  /// - Returns: `true` if `getReasons()` is not empty.
  func isFridaDetected() -> Bool {
    return !getReasons().isEmpty
  }

  /// Checks loaded libraries, thread names, exported symbols, Frida directories and the default
  /// server port 27042.
  ///
  /// - Returns: One message per positive check; empty when clean.
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

    if portOpen(27042) {
      reasons.append("Frida default port 27042 open")
    }

    return reasons
  }

  /// Looks for `frida`, `frida-agent` or `FridaGadget` in loaded image names
  /// (case-insensitive).
  ///
  /// - Returns: `true` if one is loaded.
  private func checkFridaLibraries() -> Bool {
    let libs = ["frida", "frida-agent", "fridagadget"]
    return imageNames().contains { image in
      let name = image.lowercased()
      return libs.contains { name.contains($0) }
    }
  }

  /// Looks for Frida runtime threads: names containing `frida`, starting with `gum-` or
  /// containing `gum-js`.
  ///
  /// - Returns: `true` if one exists.
  private func checkFridaThreads() -> Bool {
    return threadNames().contains { raw in
      let name = raw.lowercased()
      // "gum" alone would match unrelated thread names; Frida's runtime threads are "gum-js-loop" / "gum-…".
      return name.contains("frida") || name.hasPrefix("gum-") || name.contains("gum-js")
    }
  }

  /// Looks for exported Frida/Gum symbols.
  ///
  /// - Returns: `true` if one resolves.
  private func detectFridaSymbols() -> Bool {
    let symbols = [
      "frida_agent_main",
      "gum_script_backend_create",
      "gum_init",
      "frida",
    ]
    return symbols.contains { symbolExists($0) }
  }

  /// Looks for Frida library directories.
  ///
  /// - Returns: `true` if one exists.
  private func checkFridaDynamicLibs() -> Bool {
    let suspiciousPaths = [
      "/usr/lib/frida",
      "/Library/MobileSubstrate/DynamicLibraries/frida",
    ]
    return suspiciousPaths.contains { fileExists($0) }
  }

  // MARK: - System implementations

  /// Lists the paths of all loaded dyld images.
  ///
  /// - Returns: Image paths.
  static func systemImageNames() -> [String] {
    return (0..<_dyld_image_count()).compactMap { i in
      _dyld_get_image_name(i).map { String(cString: $0) }
    }
  }

  /// Symbol lookup with `dlsym` across all loaded images.
  ///
  /// - Parameter name: Symbol name.
  /// - Returns: `true` if it resolves.
  static func systemSymbolExists(_ name: String) -> Bool {
    return dlsym(UnsafeMutableRawPointer(bitPattern: -2), name) != nil
  }

  /// Lists the names of all threads in the process via Mach `task_threads`.
  ///
  /// - Returns: Thread names (empty strings for unnamed threads).
  static func systemThreadNames() -> [String] {
    var threads: thread_act_array_t?
    var count: mach_msg_type_number_t = 0

    guard task_threads(mach_task_self_, &threads, &count) == KERN_SUCCESS,
          let threadList = threads
    else {
      return []
    }

    defer {
      vm_deallocate(
        mach_task_self_,
        vm_address_t(bitPattern: threadList),
        vm_size_t(count) * vm_size_t(MemoryLayout<thread_t>.stride)
      )
    }

    var names: [String] = []

    for i in 0..<Int(count) {
      guard let pthread = pthread_from_mach_thread_np(threadList[i]) else {
        continue
      }

      var nameBuffer = [CChar](repeating: 0, count: 256)
      pthread_getname_np(pthread, &nameBuffer, 256)
      names.append(String(cString: nameBuffer))
    }

    return names
  }
}
