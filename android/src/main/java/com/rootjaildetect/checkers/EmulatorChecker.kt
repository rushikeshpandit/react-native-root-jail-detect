package com.rootjaildetect.checkers

import android.os.Build
import com.rootjaildetect.constants.SecurityConstants
import com.rootjaildetect.utils.SystemPropertyReader
import java.io.File

/**
 * Heuristics that detect an Android emulator.
 *
 * @param buildInfo Supplies fingerprint, model, brand and device strings (nulls allowed).
 * @param fileExists Tells whether a path exists.
 * @param propertyReader Reads a system property by key.
 */
class EmulatorChecker(
    private val buildInfo: () -> List<String?> = {
        listOf(Build.FINGERPRINT, Build.MODEL, Build.BRAND, Build.DEVICE)
    },
    private val fileExists: (String) -> Boolean = { File(it).exists() },
    private val propertyReader: (String) -> String? = { SystemPropertyReader.getProperty(it) },
) {
    /**
     * Whether any emulator indicator is present.
     *
     * @return `true` if `getReasons()` is not empty.
     */
    fun isEmulator(): Boolean = getReasons().isNotEmpty()

    /**
     * Checks for a `generic` build string, QEMU device files and emulator system properties.
     *
     * @return One message per positive heuristic; empty on a real device.
     */
    fun getReasons(): List<String> {
        val reasons = mutableListOf<String>()

        val props = buildInfo().joinToString()

        if (props.contains("generic", true)) {
            reasons.add("Generic emulator fingerprint detected")
        }

        if (SecurityConstants.KNOWN_FILES.any { fileExists(it) }) {
            reasons.add("Emulator specific file detected")
        }

        if (SecurityConstants.EMULATOR_PROPERTIES.any { (key, value) ->
                propertyReader(key)?.contains(value) == true
            }
        ) {
            reasons.add("Emulator system property detected")
        }

        return reasons
    }
}
