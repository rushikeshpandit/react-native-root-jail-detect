package com.rootjaildetect.checkers

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import com.rootjaildetect.constants.SecurityConstants
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito.doAnswer
import org.mockito.Mockito.doReturn
import org.mockito.Mockito.mock
import org.mockito.Mockito.`when`
import org.mockito.ArgumentMatchers.anyInt
import org.mockito.ArgumentMatchers.anyString

class RootCheckerTest {
    private lateinit var context: Context
    private lateinit var packageManager: PackageManager

    private var existingFiles: Set<String> = emptySet()
    private var tags: String? = "release-keys"
    private var commands: Map<String, List<String>> = emptyMap()
    private var failingCommands: Set<String> = emptySet()

    @Before
    fun setUp() {
        context = mock(Context::class.java)
        packageManager = mock(PackageManager::class.java)
        `when`(context.packageManager).thenReturn(packageManager)
        `when`(packageManager.getPackageInfo(anyString(), anyInt()))
            .thenAnswer { throw PackageManager.NameNotFoundException() }
        existingFiles = emptySet()
        tags = "release-keys"
        commands = emptyMap()
        failingCommands = emptySet()
    }

    private fun checker() =
        RootChecker(
            context,
            commandExecutor = { cmd ->
                if (cmd in failingCommands) throw java.io.IOException("cannot run $cmd")
                commands[cmd] ?: emptyList()
            },
            fileExists = { it in existingFiles },
            buildTags = { tags },
        )

    // ---------- positive: clean device ----------

    @Test
    fun cleanDevice_isNotRooted() {
        assertFalse(checker().isDeviceRooted())
        assertTrue(checker().getReasons().isEmpty())
    }

    // ---------- positive: each signal ----------

    @Test
    fun suBinary_inAnyKnownDirectory_isDetected() {
        SecurityConstants.SU_BINARY_DIRECTORIES.forEach { dir ->
            existingFiles = setOf(dir + "su")
            assertTrue("su in $dir", checker().getReasons().contains("SU binary found in system path"))
        }
    }

    @Test
    fun rootApp_eachKnownPackage_isDetected() {
        SecurityConstants.ROOT_MANAGEMENT_PACKAGES.forEach { pkg ->
            doReturn(mock(PackageInfo::class.java)).`when`(packageManager).getPackageInfo(pkg, 0)
            assertTrue(pkg, checker().getReasons().contains("Root management application detected"))
            doAnswer { throw PackageManager.NameNotFoundException() }
                .`when`(packageManager)
                .getPackageInfo(pkg, 0)
        }
    }

    @Test
    fun testKeys_isDetectedWithDistinctReason() {
        tags = "dev-keys,test-keys"
        val reasons = checker().getReasons()
        assertTrue(reasons.contains("Test-keys build detected"))
        assertFalse(
            "test-keys must not be reported as a root app",
            reasons.contains("Root management application detected"),
        )
    }

    @Test
    fun suCommandOutput_isDetected() {
        commands = mapOf("which su" to listOf("/system/xbin/su"))
        assertTrue(checker().getReasons().contains("SU command executable"))
    }

    @Test
    fun dangerousProps_areDetected() {
        SecurityConstants.DANGEROUS_SYSTEM_PROPERTIES.forEach { (key, value) ->
            commands = mapOf("getprop" to listOf("$key: $value"))
            assertTrue(key, checker().getReasons().contains("Dangerous properties found"))
        }
    }

    @Test
    fun dangerousProps_tolerateSurroundingWhitespace() {
        commands = mapOf("getprop" to listOf("  [ro.debuggable]: [1]  "))
        assertTrue(checker().getReasons().contains("Dangerous properties found"))
    }

    @Test
    fun writableSystem_legacyMountFormat_isDetected() {
        commands = mapOf("mount" to listOf("/dev/block/dm-0 /system ext4 rw,seclabel,relatime"))
        assertTrue(checker().getReasons().contains("Writable system partition"))
    }

    @Test
    fun writableSystem_modernMountFormat_isDetected() {
        commands =
            mapOf(
                "mount" to
                    listOf("/dev/block/dm-0 on /system type ext4 (rw,seclabel,relatime)"),
            )
        assertTrue(checker().getReasons().contains("Writable system partition"))
    }

    @Test
    fun rootCloakingFiles_areDetected() {
        SecurityConstants.ROOT_CLOAKING_FILE_PATHS.forEach { path ->
            existingFiles = setOf(path)
            assertTrue(path, checker().getReasons().contains("Root cloaking files found"))
        }
    }

    @Test
    fun magisk_eachPath_isDetected() {
        listOf("/sbin/.magisk", "/sbin/magisk", "/data/adb/magisk").forEach {
            existingFiles = setOf(it)
            assertTrue(it, checker().getReasons().contains("Magisk detected"))
        }
    }

    @Test
    fun kernelSu_isDetected() {
        existingFiles = setOf("/sys/kernel/kernelsu")
        assertTrue(checker().getReasons().contains("KernelSU detected"))
    }

    @Test
    fun zygisk_eachPath_isDetected() {
        listOf("/data/adb/zygisk", "/data/adb/modules").forEach {
            existingFiles = setOf(it)
            assertTrue(it, checker().getReasons().contains("Magisk Zygisk detected"))
        }
    }

    @Test
    fun multipleSignals_produceMultipleReasons() {
        existingFiles = setOf("/system/xbin/su", "/sbin/magisk")
        tags = "test-keys"
        val reasons = checker().getReasons()
        assertEquals(3, reasons.size)
        assertTrue(checker().isDeviceRooted())
    }

    // ---------- negative ----------

    @Test
    fun suFileWithDifferentName_isIgnored() {
        existingFiles = setOf("/system/xbin/sudo", "/system/bin/sum")
        assertFalse(checker().isDeviceRooted())
    }

    @Test
    fun nullBuildTags_isNotRooted() {
        tags = null
        assertFalse(checker().isDeviceRooted())
    }

    @Test
    fun releaseKeys_isNotRooted() {
        tags = "release-keys"
        assertFalse(checker().isDeviceRooted())
    }

    @Test
    fun suCommand_emptyOutput_isIgnored() {
        commands = mapOf("which su" to emptyList())
        assertFalse(checker().getReasons().contains("SU command executable"))
    }

    @Test
    fun suCommand_throwing_isTreatedAsNotRooted() {
        failingCommands = setOf("which su")
        assertFalse(checker().isDeviceRooted())
    }

    @Test
    fun getprop_throwing_doesNotCrash() {
        failingCommands = setOf("getprop")
        assertFalse(checker().isDeviceRooted())
    }

    @Test
    fun mount_throwing_doesNotCrash() {
        failingCommands = setOf("mount")
        assertFalse(checker().isDeviceRooted())
    }

    @Test
    fun safeProps_areIgnored() {
        commands =
            mapOf(
                "getprop" to
                    listOf(
                        "[ro.debuggable]: [0]",
                        "[ro.secure]: [1]",
                        "[service.adb.root]: [0]",
                        "[ro.build.type]: [user]",
                    ),
            )
        assertFalse(checker().isDeviceRooted())
    }

    @Test
    fun propKeyAndValueOnDifferentProps_isNotAFalsePositive() {
        // "[ro.secure]" appears but its value is [1]; "[0]" belongs to another property.
        commands = mapOf("getprop" to listOf("[ro.secure.extra]: [0]", "[ro.secure]: [1]"))
        assertFalse(checker().isDeviceRooted())
    }

    @Test
    fun readOnlySystem_legacyFormat_isIgnored() {
        commands = mapOf("mount" to listOf("/dev/block/dm-0 /system ext4 ro,seclabel,relatime"))
        assertFalse(checker().isDeviceRooted())
    }

    @Test
    fun readOnlySystem_modernFormat_isIgnored() {
        commands =
            mapOf("mount" to listOf("/dev/block/dm-0 on /system type ext4 (ro,seclabel,relatime)"))
        assertFalse(checker().isDeviceRooted())
    }

    @Test
    fun writableOtherPartition_isIgnored() {
        commands =
            mapOf(
                "mount" to
                    listOf(
                        "/dev/block/dm-1 /data ext4 rw,seclabel",
                        "/dev/block/dm-2 on /sdcard type f2fs (rw,nosuid)",
                    ),
            )
        assertFalse(checker().isDeviceRooted())
    }

    @Test
    fun optionContainingRwSubstring_isNotWritable() {
        commands = mapOf("mount" to listOf("/dev/block/dm-0 /system ext4 ro,errors=rwx"))
        assertFalse(checker().isDeviceRooted())
    }

    @Test
    fun malformedMountLines_areIgnored() {
        commands = mapOf("mount" to listOf("", "garbage", "a b", "a b c"))
        assertFalse(checker().isDeviceRooted())
    }

    @Test
    fun unrelatedFiles_areIgnored() {
        existingFiles = setOf("/system/bin/ls", "/data/adb/other")
        assertFalse(checker().isDeviceRooted())
    }

    @Test
    fun isDeviceRooted_matchesReasons() {
        existingFiles = setOf("/sys/kernel/kernelsu")
        val c = checker()
        assertEquals(c.getReasons().isNotEmpty(), c.isDeviceRooted())
    }
}
