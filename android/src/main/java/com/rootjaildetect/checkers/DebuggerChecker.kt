package com.rootjaildetect.checkers

import android.os.Debug
import java.io.File

class DebuggerChecker {
    fun isDebuggerAttached(): Boolean = getReasons().isNotEmpty()

    fun getReasons(): List<String> {
        val reasons = mutableListOf<String>()

        if (Debug.isDebuggerConnected()) {
            reasons.add("Debugger is connected")
        }

        if (Debug.waitingForDebugger()) {
            reasons.add("Application waiting for debugger")
        }

        if (tracerPidCheck()) {
            reasons.add("TracerPid indicates debugger attachment")
        }

        return reasons
    }

    private fun tracerPidCheck(): Boolean =
        try {
            File("/proc/self/status").useLines { lines ->
                val tracer = lines.find { it.startsWith("TracerPid:") }
                val pid = tracer?.substringAfter(":")?.trim()?.toIntOrNull()
                pid != null && pid > 0
            }
        } catch (_: Exception) {
            false
        }
}
