package com.rootjaildetect.checkers

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.rootjaildetect.constants.SecurityConstants
import com.rootjaildetect.utils.CommandExecutor
import java.io.File

/**
 * RootChecker
 *
 * Contains heuristics used to detect rooted devices.
 */
class RootChecker(
    private val context: Context,
) {
    /**
     * Determines whether the current device is rooted.
     *
     * Combines multiple independent detection techniques
     * to improve accuracy and reduce false negatives.
     *
     * @return true if the device is likely rooted, false otherwise
     */
    fun isDeviceRooted(): Boolean = getReasons().isNotEmpty()

    fun getReasons(): List<String> {
        val reasons = mutableListOf<String>()

        if (hasSuBinary()) {
            reasons.add("SU binary found in system path")
        }
        if (hasRootAppsInstalled()) {
            reasons.add("Root management application detected")
        }
        if (hasTestKeys()) {
            reasons.add("Root management application detected")
        }
        if (canExecuteSu()) {
            reasons.add("SU command executable")
        }
        if (hasDangerousProps()) {
            reasons.add("Dangerous properties found")
        }
        if (writableSystemPartition()) {
            reasons.add("Writable system partition")
        }
        if (hasRootCloakingFiles()) {
            reasons.add("Root cloaking files found")
        }
        if (detectMagisk()) {
            reasons.add("Magisk detected")
        }
        if (detectKernelSU()) {
            reasons.add("KernelSU detected")
        }
        if (detectZygisk()) {
            reasons.add("Magisk Zygisk detected")
        }

        return reasons
    }

    /**
     * Checks for the presence of the "su" binary in common directories.
     *
     * Rooted devices usually expose this binary.
     */
    private fun hasSuBinary(): Boolean =
        SecurityConstants.SU_BINARY_DIRECTORIES.any {
            File(it, "su").exists()
        }

    /**
     * Checks whether known root management applications are installed.
     *
     * Presence of these apps strongly indicates rooting.
     */
    private fun hasRootAppsInstalled(): Boolean {
        SecurityConstants.ROOT_MANAGEMENT_PACKAGES.forEach { pkg ->
            try {
                context.packageManager.getPackageInfo(pkg, 0)
                return true
            } catch (_: PackageManager.NameNotFoundException) {
            }
        }
        return false
    }

    /**
     * Verifies whether the device build contains "test-keys".
     *
     * Custom ROMs and rooted devices often use test keys.
     */
    private fun hasTestKeys(): Boolean = Build.TAGS?.contains("test-keys") == true

    /**
     * Attempts to locate the "su" binary using shell commands.
     *
     * Successful execution indicates root access.
     */
    private fun canExecuteSu(): Boolean =
        try {
            CommandExecutor.execute("/system/xbin/which su").firstOrNull() != null
        } catch (_: Exception) {
            false
        }

    /**
     * Reads system properties and checks for insecure configurations.
     *
     * Certain properties are modified on rooted devices.
     */
    private fun hasDangerousProps(): Boolean {
        val props = CommandExecutor.execute("getprop")

        return props.any { line ->
            SecurityConstants.DANGEROUS_SYSTEM_PROPERTIES.any { (key, value) ->
                line.contains(key) && line.contains(value)
            }
        }
    }

    /**
     * Checks whether critical system partitions are mounted as writable.
     *
     * On non-rooted devices, /system should be read-only.
     */
    private fun writableSystemPartition(): Boolean {
        val mounts = CommandExecutor.execute("mount")

        return mounts.any { line ->
            val parts = line.split(" ")
            if (parts.size < 4) return@any false

            val mountPoint = parts[1]
            val options = parts[3]

            mountPoint == "/system" && options.contains("rw")
        }
    }

    /**
     * Searches for files commonly used to hide or manage root.
     *
     * These files are rarely present on stock devices.
     */
    private fun hasRootCloakingFiles(): Boolean =
        SecurityConstants.ROOT_CLOAKING_FILE_PATHS.any {
            File(it).exists()
        }

    /**
     * Detects Magisk systemless root.
     */
    private fun detectMagisk(): Boolean =
        File("/sbin/.magisk").exists() ||
            File("/sbin/magisk").exists() ||
            File("/data/adb/magisk").exists()

    /**
     * Detects KernelSU root method.
     */
    private fun detectKernelSU(): Boolean = File("/sys/kernel/kernelsu").exists()

    private fun detectZygisk(): Boolean =
        File("/data/adb/zygisk").exists() ||
            File("/data/adb/modules").exists()
}
