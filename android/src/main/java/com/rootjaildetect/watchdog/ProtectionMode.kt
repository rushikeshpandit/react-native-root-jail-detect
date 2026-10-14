package com.rootjaildetect.watchdog

/**
 * Action taken when the watchdog detects a threat: `LOG_ONLY` logs it, `THROW_EXCEPTION` throws
 * an uncaught exception on the main thread (crashing the app) and `TERMINATE` kills the
 * process.
 */
enum class ProtectionMode {
    LOG_ONLY,
    THROW_EXCEPTION,
    TERMINATE,
}
