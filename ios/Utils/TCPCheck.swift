import Darwin
import Foundation

/// Probes local TCP ports, used to spot the Frida server.
enum TCPCheck {

  /// Tries to open a TCP connection to `127.0.0.1:port`. The connect is non-blocking and
  /// bounded by a timeout, because a blocking connect to a listener that never accepts can hang
  /// for about a minute. The socket is always closed.
  ///
  /// - Parameters:
  ///   - port: Port to probe; must be 1...65535, anything else returns false.
  ///   - timeoutMs: Maximum time to wait for the connection, in milliseconds (default 100).
  /// - Returns: `true` if the connection was established, `false` if the port is closed,
  ///   filtered, invalid or the attempt timed out.
  static func connect(port: Int, timeoutMs: Int32 = 100) -> Bool {
    guard port > 0, port <= Int(UInt16.max) else { return false }

    let socketFD = socket(AF_INET, SOCK_STREAM, 0)
    if socketFD < 0 {
      return false
    }
    defer { close(socketFD) }

    let flags = fcntl(socketFD, F_GETFL, 0)
    guard flags >= 0, fcntl(socketFD, F_SETFL, flags | O_NONBLOCK) == 0 else {
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

    if result == 0 { return true }
    guard errno == EINPROGRESS else { return false }

    var pfd = pollfd(fd: socketFD, events: Int16(POLLOUT), revents: 0)
    guard poll(&pfd, 1, timeoutMs) > 0 else { return false }

    var soError: Int32 = 0
    var len = socklen_t(MemoryLayout<Int32>.size)
    guard getsockopt(socketFD, SOL_SOCKET, SO_ERROR, &soError, &len) == 0 else { return false }

    return soError == 0
  }
}
