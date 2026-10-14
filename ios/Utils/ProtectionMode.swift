/// Action taken when the watchdog detects a threat: `logOnly` writes to the log,
/// `throwException` crashes the app with a fatal error and `terminate` kills the process with
/// SIGKILL. Raw values are 0, 1 and 2.
@objc
enum ProtectionMode: Int {
  case logOnly
  case throwException
  case terminate
}
