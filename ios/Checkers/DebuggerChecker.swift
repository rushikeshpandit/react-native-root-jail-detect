import Darwin
import Foundation

/// Detects an attached debugger through the `P_TRACED` flag read with sysctl.
class DebuggerChecker: DetectionRule {

  private let skipInDebugBuild: Bool
  private let isTraced: () -> Bool

#if DEBUG
  static let isDebugBuild = true
#else
  static let isDebugBuild = false
#endif

  /// Creates the checker; defaults use the real build configuration and sysctl.
  ///
  /// - Parameters:
  ///   - skipInDebugBuild: When true, detection is disabled (true in DEBUG builds, where Xcode
  ///   attaches a debugger).
  ///   - isTraced: Returns whether the process is traced.
  init(
    skipInDebugBuild: Bool = DebuggerChecker.isDebugBuild,
    isTraced: @escaping () -> Bool = DebuggerChecker.systemIsTraced
  ) {
    self.skipInDebugBuild = skipInDebugBuild
    self.isTraced = isTraced
  }
  
  /// Whether a debugger is attached.
  ///
  /// - Returns: `false` when skipped for debug builds, otherwise `true` if `getReasons()` is
  ///   not empty.
  func isDebuggerAttached() -> Bool {
    if skipInDebugBuild { return false }
    return !getReasons().isEmpty
  }
  
  /// Reports the debugger if the process is traced.
  ///
  /// - Returns: `["Debugger attached via sysctl"]` or an empty list (also empty when skipped).
  func getReasons() -> [String] {
    if skipInDebugBuild { return [] }
    
    if isTraced() {
      return ["Debugger attached via sysctl"]
    }
    
    return []
  }
  
  /// Reads `kinfo_proc.p_flag` for the current process with sysctl. Has no side effects.
  ///
  /// - Returns: `true` if `P_TRACED` is set; `false` if it is clear or sysctl fails.
  static func systemIsTraced() -> Bool {
    var name: [Int32] = [
      CTL_KERN,
      KERN_PROC,
      KERN_PROC_PID,
      getpid(),
    ]
    var info = kinfo_proc()
    var size = MemoryLayout<kinfo_proc>.size
    
      // If sysctl fails, info is zeroed — p_flag will be 0, so no false positive.
      // But explicitly checking return avoids acting on stale/garbage memory.
    let ret = sysctl(&name, 4, &info, &size, nil, 0)
    guard ret == 0 else { return false }
    
    return (info.kp_proc.p_flag & P_TRACED) != 0
  }
}
