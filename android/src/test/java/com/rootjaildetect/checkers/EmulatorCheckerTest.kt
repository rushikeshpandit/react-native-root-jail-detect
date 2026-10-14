package com.rootjaildetect.checkers

import com.rootjaildetect.constants.SecurityConstants
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EmulatorCheckerTest {
    private var build: List<String?> = listOf("google/walleye/walleye:8.1:user/release-keys", "Pixel 2", "google", "walleye")
    private var files: Set<String> = emptySet()
    private var props: Map<String, String> = emptyMap()

    private fun checker() =
        EmulatorChecker(
            buildInfo = { build },
            fileExists = { it in files },
            propertyReader = { props[it] },
        )

    @Test
    fun realDevice_isNotEmulator() {
        assertFalse(checker().isEmulator())
        assertTrue(checker().getReasons().isEmpty())
    }

    @Test
    fun genericFingerprint_isDetected() {
        build = listOf("generic/sdk_gphone:11", "sdk_gphone", "google", "emu64")
        assertTrue(checker().getReasons().contains("Generic emulator fingerprint detected"))
        assertTrue(checker().isEmulator())
    }

    @Test
    fun genericMatch_isCaseInsensitive() {
        build = listOf("GENERIC_x86", null, null, null)
        assertTrue(checker().isEmulator())
    }

    @Test
    fun genericInAnyBuildField_isDetected() {
        listOf(
            listOf("generic", "a", "b", "c"),
            listOf("x", "generic", "b", "c"),
            listOf("x", "a", "generic", "c"),
            listOf("x", "a", "b", "generic"),
        ).forEach {
            build = it
            assertTrue(it.toString(), checker().isEmulator())
        }
    }

    @Test
    fun nullBuildFields_areNotEmulator() {
        build = listOf(null, null, null, null)
        assertFalse(checker().isEmulator())
    }

    @Test
    fun emptyBuildInfo_isNotEmulator() {
        build = emptyList()
        assertFalse(checker().isEmulator())
    }

    @Test
    fun eachKnownEmulatorFile_isDetected() {
        SecurityConstants.KNOWN_FILES.forEach {
            files = setOf(it)
            assertTrue(it, checker().getReasons().contains("Emulator specific file detected"))
        }
    }

    @Test
    fun unrelatedFile_isIgnored() {
        files = setOf("/system/bin/ls")
        assertFalse(checker().isEmulator())
    }

    @Test
    fun eachEmulatorProperty_isDetected() {
        SecurityConstants.EMULATOR_PROPERTIES.forEach { (k, v) ->
            props = mapOf(k to v)
            assertTrue(k, checker().getReasons().contains("Emulator system property detected"))
        }
    }

    @Test
    fun propertyValueMatch_isSubstringBased() {
        props = mapOf("ro.hardware" to "ranchu-goldfish-x86")
        assertTrue(checker().isEmulator())
    }

    @Test
    fun propertyWithRealValue_isIgnored() {
        props = mapOf("ro.hardware" to "qcom", "ro.kernel.qemu" to "0")
        assertFalse(checker().isEmulator())
    }

    @Test
    fun missingProperty_isIgnored() {
        props = emptyMap()
        assertFalse(checker().isEmulator())
    }

    @Test
    fun allSignals_yieldThreeReasons() {
        build = listOf("generic", "", "", "")
        files = setOf(SecurityConstants.KNOWN_FILES.first())
        props = mapOf("ro.kernel.qemu" to "1")
        assertEquals(3, checker().getReasons().size)
    }

    @Test
    fun defaultConstructor_onJvm_doesNotThrow() {
        // Build.* fields are null under the unit-test android.jar; must be handled.
        EmulatorChecker().isEmulator()
    }
}
