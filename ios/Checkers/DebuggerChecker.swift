import Darwin
import Foundation

  /// DebuggerChecker
  ///
  /// Detects debugger attachment using sysctl.
class DebuggerChecker: DetectionRule {
  
  func isDebuggerAttached() -> Bool {
#if DEBUG
      // Skip all debugger detection in debug builds.
      // Xcode always attaches LLDB when running via cable — these will
      // always fire and are meaningless in development.
    return false
#endif
    return !getReasons().isEmpty
  }
  
  func getReasons() -> [String] {
#if DEBUG
      // Skip all debugger detection in debug builds.
      // Xcode always attaches LLDB when running via cable — these will
      // always fire and are meaningless in development.
    return []
#endif
    
    if checkDebugger() {
      return ["Debugger attached via sysctl"]
    }
    
    return []
  }
  
  private func checkDebugger() -> Bool {
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
