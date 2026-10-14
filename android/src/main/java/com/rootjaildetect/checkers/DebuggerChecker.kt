package com.rootjaildetect.checkers

import android.os.Debug
import java.io.File

/**
 * Heuristics that detect an attached debugger.
 *
 * @param statusFile Process status file to read `TracerPid` from.
 * @param debuggerConnected Supplies the Java debugger-connected flag.
 * @param waitingForDebugger Supplies the wait-for-debugger flag.
 */
class DebuggerChecker(
    private val statusFile: File = File("/proc/self/status"),
    private val debuggerConnected: () -> Boolean = { Debug.isDebuggerConnected() },
    private val waitingForDebugger: () -> Boolean = { Debug.waitingForDebugger() },
) {
    /**
     * Whether any debugger indicator is present.
     *
     * @return `true` if `getReasons()` is not empty.
     */
    fun isDebuggerAttached(): Boolean = getReasons().isNotEmpty()

    /**
     * Checks the Java debugger flag, the wait-for-debugger state and `TracerPid`.
     *
     * @return One message per positive check; empty when no debugger is attached.
     */
    fun getReasons(): List<String> {
        val reasons = mutableListOf<String>()

        if (debuggerConnected()) {
            reasons.add("Debugger is connected")
        }

        if (waitingForDebugger()) {
            reasons.add("Application waiting for debugger")
        }

        if (tracerPidCheck()) {
            reasons.add("TracerPid indicates debugger attachment")
        }

        return reasons
    }

    /**
     * Parses the `TracerPid:` line of the status file.
     *
     * @return `true` if the value is a positive number; `false` if the line is missing,
     *     malformed, zero or the file is unreadable.
     */
    private fun tracerPidCheck(): Boolean =
        try {
            statusFile.useLines { lines ->
                val tracer = lines.find { it.startsWith("TracerPid:") }
                val pid = tracer?.substringAfter(":")?.trim()?.toIntOrNull()
                pid != null && pid > 0
            }
        } catch (_: Exception) {
            false
        }
}
