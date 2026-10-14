package com.rootjaildetect

import android.content.Context
import com.rootjaildetect.checkers.*

/**
 * Facade over all Android checkers. Application code talks only to this class; it delegates to
 * the specialised checkers and the JNI probes.
 *
 * @param context Android context used by the root checker for package-manager lookups.
 * @param rootChecker Root heuristics.
 * @param emulatorChecker Emulator heuristics.
 * @param debuggerChecker Debugger heuristics.
 * @param fridaChecker Frida heuristics.
 * @param hookChecker Xposed / hook-framework heuristics.
 * @param nativeProbe JNI checks; replaceable so tests do not need the native library.
 */
class RootDetection(
    context: Context,
    private val rootChecker: RootChecker = RootChecker(context),
    private val emulatorChecker: EmulatorChecker = EmulatorChecker(),
    private val debuggerChecker: DebuggerChecker = DebuggerChecker(),
    private val fridaChecker: FridaChecker = FridaChecker(),
    private val hookChecker: HookFrameworkChecker = HookFrameworkChecker(),
    private val nativeProbe: NativeProbe = DefaultNativeProbe,
) {
    /**
     * Decides whether the device is rooted or instrumented. Evaluates root, Frida, Xposed,
     * stack-trace hook and the four native probes, stopping at the first positive. Emulators
     * and debuggers alone do not count.
     *
     * @return `true` if any indicator was found.
     */
    fun isDeviceRooted(): Boolean =
        rootChecker.isDeviceRooted() ||
        fridaChecker.isFridaDetected() ||
        hookChecker.detectXposed() ||
        hookChecker.detectStack() ||
        nativeProbe.detectPtrace() ||
        nativeProbe.detectFridaNative() ||
        nativeProbe.detectInlineHook() ||
        nativeProbe.detectFridaSyscall()

    /**
     * Delegates to the emulator checker.
     *
     * @return `true` when running inside an emulator.
     */
    fun isEmulator(): Boolean = emulatorChecker.isEmulator()

    /**
     * Delegates to the debugger checker.
     *
     * @return `true` when a debugger is attached.
     */
    fun isDebuggerAttached(): Boolean = debuggerChecker.isDebuggerAttached()

    /**
     * All reasons from every checker, including emulator findings.
     *
     * @return De-duplicated, human-readable reason strings, empty when nothing was found.
     */
    fun getDetectionReasons(): List<String> = collectReasons(includeEmulator = true)

    /**
     * Reasons limited to what the watchdog acts on: the same as `getDetectionReasons()` minus
     * emulator findings, because an emulator alone does not trigger the watchdog.
     *
     * @return De-duplicated reason strings.
     */
    fun getThreatReasons(): List<String> = collectReasons(includeEmulator = false)

    /**
     * Gathers reasons from the checkers and the native probes in a fixed order.
     *
     * @param includeEmulator Whether emulator findings are included.
     * @return De-duplicated reason strings.
     */
    private fun collectReasons(includeEmulator: Boolean): List<String> {
        val reasons = mutableListOf<String>()

        reasons += rootChecker.getReasons()
        if (includeEmulator) {
            reasons += emulatorChecker.getReasons()
        }
        reasons += debuggerChecker.getReasons()
        reasons += fridaChecker.getReasons()
        reasons += hookChecker.getReasons()

        if (nativeProbe.detectPtrace()) {
            reasons.add("Debugger detected via ptrace")
        }

        if (nativeProbe.detectFridaNative()) {
            reasons.add("Frida detected via native memory scan")
        }

        if (nativeProbe.detectInlineHook()) {
            reasons.add("Inline hook detected in libc")
        }

        if (nativeProbe.detectFridaSyscall()) {
            reasons.add("Frida detected via syscall inspection")
        }

        return reasons.distinct()
    }
}
