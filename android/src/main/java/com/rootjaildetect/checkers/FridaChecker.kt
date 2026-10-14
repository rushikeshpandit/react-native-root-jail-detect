package com.rootjaildetect.checkers

import com.rootjaildetect.constants.SecurityConstants
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Heuristics that detect the Frida instrumentation toolkit.
 *
 * @param procRoot Root of the proc filesystem (injectable).
 * @param host Host probed for the Frida server.
 * @param port Port probed for the Frida server (27042).
 * @param gadgetPath Location of a dropped frida-gadget library.
 * @param connectTimeoutMs Socket connect timeout in milliseconds.
 */
class FridaChecker(
    private val procRoot: File = File("/proc"),
    private val host: String = "127.0.0.1",
    private val port: Int = FRIDA_DEFAULT_PORT,
    private val gadgetPath: String = "/data/local/tmp/frida-gadget.so",
    private val connectTimeoutMs: Int = 100,
) {
    /**
     * Whether any Frida indicator is present.
     *
     * @return `true` if `getReasons()` is not empty.
     */
    fun isFridaDetected(): Boolean = getReasons().isNotEmpty()

    /**
     * Checks the default server port, loaded libraries, thread names, gadget file and
     * suspicious processes.
     *
     * @return One message per positive check; empty when nothing is found.
     */
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

    /**
     * Tries a TCP connection to the Frida server port.
     *
     * @return `true` if the connection succeeds; `false` on any failure or timeout.
     */
    private fun checkPort(): Boolean =
        try {
            Socket().use {
                it.connect(InetSocketAddress(host, port), connectTimeoutMs)
                true
            }
        } catch (_: Exception) {
            false
        }

    /**
     * Scans `self/maps` for Frida library names.
     *
     * @return `true` if a line contains one; `false` if the file is unreadable.
     */
    private fun checkLibraries(): Boolean =
        try {
            File(procRoot, "self/maps").useLines { lines ->
                lines.any { line ->
                    SecurityConstants.FRIDA_LIBRARIES.any { line.contains(it) }
                }
            }
        } catch (_: Exception) {
            false
        }

    /**
     * Scans every `self/task/<tid>/status` for a `frida` or `gum-js-loop` thread name.
     *
     * @return `true` if found; `false` if unreadable.
     */
    private fun checkThreads(): Boolean =
        try {
            val taskDir = File(procRoot, "self/task")
            taskDir.listFiles()?.any { dir ->
                val status = File(dir, "status")
                status.exists() &&
                    status.readText().let { text ->
                        text.contains("frida", true) || text.contains("gum-js-loop", true)
                    }
            } ?: false
        } catch (_: Exception) {
            false
        }

    /**
     * Checks for the frida-gadget file.
     *
     * @return `true` if it exists.
     */
    private fun detectFridaGadget(): Boolean = File(gadgetPath).exists()

    /**
     * Scans `/proc/<pid>/cmdline` of visible processes for `frida`, `magisk` or `xposed`.
     * Unreadable entries are skipped so one bad process cannot hide a later match.
     *
     * @return `true` if a match is found.
     */
    private fun detectSuspiciousProcess(): Boolean {
        val processes = procRoot.listFiles() ?: return false

        processes.forEach { dir ->
            // Processes can exit (or be unreadable) between listing and reading.
            val text =
                try {
                    val cmd = File(dir, "cmdline")
                    if (cmd.exists()) cmd.readText() else null
                } catch (_: Exception) {
                    null
                } ?: return@forEach

            if (text.contains("frida") ||
                text.contains("magisk") ||
                text.contains("xposed")
            ) {
                return true
            }
        }

        return false
    }

    companion object {
        const val FRIDA_DEFAULT_PORT = 27042
    }
}
