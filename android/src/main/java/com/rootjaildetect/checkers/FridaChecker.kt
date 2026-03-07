package com.rootjaildetect.checkers

import com.rootjaildetect.constants.SecurityConstants
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket

/**
 * FridaChecker
 *
 * Detects runtime instrumentation using Frida.
 */
class FridaChecker {
    fun isFridaDetected(): Boolean = getReasons().isNotEmpty()

    fun getReasons(): List<String> {
        val reasons = mutableListOf<String>()

        if (checkPort()) {
            reasons.add("Frida default port 27042 open")
        }

        if (checkLibraries()) {
            reasons.add("Frida library detected in process memory")
        }

        if (checkThreads()) {
            reasons.add("Frida thread detected")
        }

        if (detectFridaGadget()) {
            reasons.add("Frida gadget library detected")
        }

        if (detectSuspiciousProcess()) {
            reasons.add("Suspicious instrumentation process detected")
        }

        return reasons
    }

    private fun checkPort(): Boolean =
        try {
            Socket().use {
                it.connect(InetSocketAddress("127.0.0.1", 27042), 100)
                true
            }
        } catch (_: Exception) {
            false
        }

    private fun checkLibraries(): Boolean =
        try {
            File("/proc/self/maps").useLines { lines ->
                lines.any { line ->
                    SecurityConstants.FRIDA_LIBRARIES.any { line.contains(it) }
                }
            }
        } catch (_: Exception) {
            false
        }

    private fun checkThreads(): Boolean =
        try {
            val taskDir = File("/proc/self/task")
            taskDir.listFiles()?.any { dir ->
                val status = File(dir, "status")
                status.exists() &&
                    status.readText().contains("frida", true)
            } ?: false
        } catch (_: Exception) {
            false
        }

    private fun detectFridaGadget(): Boolean = File("/data/local/tmp/frida-gadget.so").exists()

    private fun detectSuspiciousProcess(): Boolean {
        val processes = File("/proc").listFiles() ?: return false

        processes.forEach { dir ->
            val cmd = File(dir, "cmdline")
            if (cmd.exists()) {
                val text = cmd.readText()
                if (text.contains("frida") ||
                    text.contains("magisk") ||
                    text.contains("xposed")
                ) {
                    return true
                }
            }
        }

        return false
    }
}
