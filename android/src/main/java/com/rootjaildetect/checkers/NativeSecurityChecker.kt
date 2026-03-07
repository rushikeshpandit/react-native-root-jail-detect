package com.rootjaildetect.checkers

/**
 * NativeSecurityChecker
 *
 * Uses native C++ code to detect:
 * - ptrace debugger attachment
 * - Frida instrumentation
 */
object NativeSecurityChecker {
    init {
        System.loadLibrary("rootjaildetect")
    }

    external fun detectPtrace(): Boolean

    external fun detectFridaNative(): Boolean

    external fun detectInlineHook(): Boolean

    external fun detectFridaSyscall(): Boolean
}
