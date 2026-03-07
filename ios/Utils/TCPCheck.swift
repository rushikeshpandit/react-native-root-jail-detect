import Darwin
import Foundation

  /// TCPCheck
  ///
  /// Utility used for detecting open ports
  /// commonly used by instrumentation tools.
enum TCPCheck {
  
  static func connect(port: Int) -> Bool {
    
    let socketFD = socket(AF_INET, SOCK_STREAM, 0)
    
    if socketFD < 0 {
      return false
    }
    
    var addr = sockaddr_in()
    
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = in_port_t(port).bigEndian
    addr.sin_addr.s_addr = inet_addr("127.0.0.1")
    
    let result = withUnsafePointer(to: &addr) {
      $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        
        Darwin.connect(
          socketFD,
          $0,
          socklen_t(MemoryLayout<sockaddr_in>.size)
        )
      }
    }
    
    close(socketFD)
    
    return result == 0
  }
}
