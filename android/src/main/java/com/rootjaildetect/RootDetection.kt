package com.rootjaildetect

import android.content.Context
import com.rootjaildetect.checkers.*

/**
 * RootDetection
 *
 * Public entry point for all security checks.
 *
 * This class acts as a façade and delegates detection
 * responsibilities to specialized checkers.
 */
class RootDetection(
    context: Context,
) {
    private val rootChecker = RootChecker(context)
    private val emulatorChecker = EmulatorChecker()
    private val debuggerChecker = DebuggerChecker()
    private val fridaChecker = FridaChecker()
    private val hookChecker = HookFrameworkChecker()

    /**
     * Returns true if the device appears to be rooted.
     */
    fun isDeviceRooted(): Boolean =
        rootChecker.isDeviceRooted() ||
        fridaChecker.isFridaDetected() ||
        hookChecker.detectXposed() ||
        hookChecker.detectStack() ||
        NativeSecurityChecker.detectPtrace() ||
        NativeSecurityChecker.detectFridaNative() ||
        NativeSecurityChecker.detectInlineHook() ||
        NativeSecurityChecker.detectFridaSyscall()

    /**
     * Returns true if running inside emulator.
     */
    fun isEmulator(): Boolean = emulatorChecker.isEmulator()

    /**
     * Returns true if debugger attached.
     */
    fun isDebuggerAttached(): Boolean = debuggerChecker.isDebuggerAttached()

    /**
     * Returns human readable reasons explaining
     * why the device was flagged as compromised.
     */
    fun getDetectionReasons(): List<String> {

        val reasons = mutableListOf<String>()

        reasons += rootChecker.getReasons()
        reasons += emulatorChecker.getReasons()
        reasons += debuggerChecker.getReasons()
        reasons += fridaChecker.getReasons()
        reasons += hookChecker.getReasons()

        if (NativeSecurityChecker.detectPtrace()) {
            reasons.add("Debugger detected via ptrace")
        }

        if (NativeSecurityChecker.detectFridaNative()) {
            reasons.add("Frida detected via native memory scan")
        }

        if (NativeSecurityChecker.detectInlineHook()) {
            reasons.add("Inline hook detected in libc")
        }

        if (NativeSecurityChecker.detectFridaSyscall()) {
            reasons.add("Frida detected via syscall inspection")
        }

        return reasons.distinct()
    }
}
