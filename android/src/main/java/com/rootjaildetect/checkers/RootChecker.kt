package com.rootjaildetect.checkers

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.rootjaildetect.constants.SecurityConstants
import com.rootjaildetect.utils.CommandExecutor
import java.io.File

/**
 * Heuristics that detect a rooted Android device. Every external dependency is a constructor
 * parameter so the logic can be unit-tested.
 *
 * @param context Used to query installed packages.
 * @param commandExecutor Runs a shell command and returns its stdout lines (defaults to
 *     `CommandExecutor`).
 * @param fileExists Tells whether a path exists (defaults to `File.exists`).
 * @param buildTags Supplies `Build.TAGS`.
 */
class RootChecker(
    private val context: Context,
    private val commandExecutor: (String) -> List<String> = { CommandExecutor.execute(it) },
    private val fileExists: (String) -> Boolean = { File(it).exists() },
    private val buildTags: () -> String? = { Build.TAGS },
) {
    /**
     * Whether any root indicator is present.
     *
     * @return `true` if `getReasons()` is not empty.
     */
    fun isDeviceRooted(): Boolean = getReasons().isNotEmpty()

    /**
     * Runs all root heuristics (su binary, root apps, test-keys, su command, dangerous
     * properties, writable /system, cloaking files, Magisk, KernelSU, Zygisk).
     *
     * @return One message per positive heuristic; empty on a clean device.
     */
    fun getReasons(): List<String> {
        val reasons = mutableListOf<String>()

        if (hasSuBinary()) {
            reasons.add("SU binary found in system path")
        }
        if (hasRootAppsInstalled()) {
            reasons.add("Root management application detected")
        }
        if (hasTestKeys()) {
            reasons.add("Test-keys build detected")
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
     * Looks for an `su` executable in the well-known directories.
     *
     * @return `true` if one exists.
     */
    private fun hasSuBinary(): Boolean =
        SecurityConstants.SU_BINARY_DIRECTORIES.any {
            fileExists(it + "su")
        }

    /**
     * Looks for known root-management packages (SuperSU, Magisk, KingRoot, ...).
     *
     * @return `true` if any is installed.
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
     * Checks whether the build is signed with test keys, typical of custom ROMs.
     *
     * @return `true` if `Build.TAGS` contains `test-keys`; `false` when tags are null.
     */
    private fun hasTestKeys(): Boolean = buildTags()?.contains("test-keys") == true

    /**
     * Asks the shell to locate `su` with `which su`.
     *
     * @return `true` if the command prints a path; `false` if it prints nothing or cannot run.
     */
    private fun canExecuteSu(): Boolean =
        try {
            commandExecutor("which su").firstOrNull() != null
        } catch (_: Exception) {
            false
        }

    /**
     * Reads `getprop` and looks for insecure values such as `ro.debuggable=1` or `ro.secure=0`.
     * A line must match `[key]: [value]` exactly.
     *
     * @return `true` if one is present; `false` if `getprop` fails.
     */
    private fun hasDangerousProps(): Boolean {
        val props =
            try {
                commandExecutor("getprop")
            } catch (_: Exception) {
                return false
            }

        return props.any { line ->
            val trimmed = line.trim()
            SecurityConstants.DANGEROUS_SYSTEM_PROPERTIES.any { (key, value) ->
                trimmed == "$key: $value"
            }
        }
    }

    /**
     * Reads `mount` and looks for `/system` mounted read-write. Understands both `dev
     * mountpoint type options` and `dev on mountpoint type fs (options)` output formats.
     *
     * @return `true` if `/system` is writable; `false` if `mount` fails.
     */
    private fun writableSystemPartition(): Boolean {
        val mounts =
            try {
                commandExecutor("mount")
            } catch (_: Exception) {
                return false
            }

        return mounts.any { line ->
            val parts = line.trim().split(Regex("\\s+"))

            // Two formats exist:
            //   "/dev/block/dm-0 / ext4 ro,seclabel,relatime"            (mount point in column 2)
            //   "/dev/block/dm-0 on /system type ext4 (rw,seclabel,...)" (mount point in column 3)
            val (mountPoint, options) =
                when {
                    parts.size >= 6 && parts[1] == "on" ->
                        parts[2] to parts.last().trim('(', ')')

                    parts.size >= 4 -> parts[1] to parts[3]

                    else -> return@any false
                }

            mountPoint == "/system" && options.split(",").contains("rw")
        }
    }

    /**
     * Looks for files left by root-cloaking tools and su daemons.
     *
     * @return `true` if any exists.
     */
    private fun hasRootCloakingFiles(): Boolean =
        SecurityConstants.ROOT_CLOAKING_FILE_PATHS.any {
            fileExists(it)
        }

    /**
     * Looks for Magisk files and directories.
     *
     * @return `true` if any exists.
     */
    private fun detectMagisk(): Boolean =
        fileExists("/sbin/.magisk") ||
            fileExists("/sbin/magisk") ||
            fileExists("/data/adb/magisk")

    /**
     * Looks for the KernelSU kernel interface.
     *
     * @return `true` if `/sys/kernel/kernelsu` exists.
     */
    private fun detectKernelSU(): Boolean = fileExists("/sys/kernel/kernelsu")

    /**
     * Looks for the Zygisk and Magisk module directories.
     *
     * @return `true` if any exists.
     */
    private fun detectZygisk(): Boolean =
        fileExists("/data/adb/zygisk") ||
            fileExists("/data/adb/modules")
}
