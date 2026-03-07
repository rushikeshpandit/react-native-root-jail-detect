package com.rootjaildetect.checkers

import android.os.Build
import com.rootjaildetect.constants.SecurityConstants
import com.rootjaildetect.utils.SystemPropertyReader
import java.io.File

class EmulatorChecker {
    fun isEmulator(): Boolean = getReasons().isNotEmpty()

    fun getReasons(): List<String> {
        val reasons = mutableListOf<String>()

        val props =
            listOf(
                Build.FINGERPRINT,
                Build.MODEL,
                Build.BRAND,
                Build.DEVICE,
            ).joinToString()

        if (props.contains("generic", true)) {
            reasons.add("Generic emulator fingerprint detected")
        }

        if (SecurityConstants.KNOWN_FILES.any { File(it).exists() }) {
            reasons.add("Emulator specific file detected")
        }

        if (SecurityConstants.EMULATOR_PROPERTIES.any { (key, value) ->
                SystemPropertyReader.getProperty(key)?.contains(value) == true
            }
        ) {
            reasons.add("Emulator system property detected")
        }

        return reasons
    }
}
