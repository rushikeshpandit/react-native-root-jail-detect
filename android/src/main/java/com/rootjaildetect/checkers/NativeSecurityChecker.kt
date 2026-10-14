package com.rootjaildetect.checkers

/**
 * JNI entry points into `librootjaildetect.so`. The library is loaded when the object is first
 * used.
 */
object NativeSecurityChecker {
    init {
        System.loadLibrary("rootjaildetect")
    }

    /**
     * Native: reads `TracerPid` from `/proc/self/status`.
     *
     * @return `true` if another process is tracing this one.
     */
    external fun detectPtrace(): Boolean

    /**
     * Native: scans `/proc/self/maps` for Frida markers through libc.
     *
     * @return `true` if a marker is found.
     */
    external fun detectFridaNative(): Boolean

    /**
     * Native: inspects the first instruction of libc `open` for a branch trampoline.
     *
     * @return `true` if the prologue looks patched; `false` when it cannot be read safely.
     */
    external fun detectInlineHook(): Boolean

    /**
     * Native: scans `/proc/self/maps` using raw syscalls, which bypasses hooks installed on
     * libc.
     *
     * @return `true` if a Frida marker is found.
     */
    external fun detectFridaSyscall(): Boolean
}

/**
 * Abstraction over the JNI checks so they can be replaced where the native library cannot load
 * (JVM unit tests).
 */
interface NativeProbe {
    /**
     * Whether a tracer (debugger) is attached.
     *
     * @return `true` if detected.
     */
    fun detectPtrace(): Boolean

    /**
     * Whether Frida markers are visible through libc.
     *
     * @return `true` if detected.
     */
    fun detectFridaNative(): Boolean

    /**
     * Whether libc `open` is inline-hooked.
     *
     * @return `true` if detected.
     */
    fun detectInlineHook(): Boolean

    /**
     * Whether Frida markers are visible through raw syscalls.
     *
     * @return `true` if detected.
     */
    fun detectFridaSyscall(): Boolean
}

/**
 * Production `NativeProbe` that forwards to `NativeSecurityChecker`.
 */
object DefaultNativeProbe : NativeProbe {
    /**
     * Forwards to `NativeSecurityChecker.detectPtrace()`.
     *
     * @return Its result.
     */
    override fun detectPtrace(): Boolean = NativeSecurityChecker.detectPtrace()

    /**
     * Forwards to `NativeSecurityChecker.detectFridaNative()`.
     *
     * @return Its result.
     */
    override fun detectFridaNative(): Boolean = NativeSecurityChecker.detectFridaNative()

    /**
     * Forwards to `NativeSecurityChecker.detectInlineHook()`.
     *
     * @return Its result.
     */
    override fun detectInlineHook(): Boolean = NativeSecurityChecker.detectInlineHook()

    /**
     * Forwards to `NativeSecurityChecker.detectFridaSyscall()`.
     *
     * @return Its result.
     */
    override fun detectFridaSyscall(): Boolean = NativeSecurityChecker.detectFridaSyscall()
}
