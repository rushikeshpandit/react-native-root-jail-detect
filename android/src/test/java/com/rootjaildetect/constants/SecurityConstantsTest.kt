package com.rootjaildetect.constants

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SecurityConstantsTest {
    @Test
    fun suDirectories_areAbsoluteAndTrailingSlash() {
        // RootChecker builds "<dir>su", so a missing trailing slash would silently break detection.
        SecurityConstants.SU_BINARY_DIRECTORIES.forEach {
            assertTrue(it, it.startsWith("/") && it.endsWith("/"))
        }
    }

    @Test
    fun allPathLists_areAbsolute() {
        (SecurityConstants.ROOT_CLOAKING_FILE_PATHS + SecurityConstants.KNOWN_FILES).forEach {
            assertTrue(it, it.startsWith("/"))
        }
    }

    @Test
    fun noDuplicates() {
        listOf(
            SecurityConstants.ROOT_MANAGEMENT_PACKAGES.toList(),
            SecurityConstants.SU_BINARY_DIRECTORIES.toList(),
            SecurityConstants.ROOT_CLOAKING_FILE_PATHS.toList(),
            SecurityConstants.KNOWN_FILES.toList(),
            SecurityConstants.FRIDA_LIBRARIES,
        ).forEach { assertEquals(it.distinct().size, it.size) }
    }

    @Test
    fun dangerousProps_areBracketed() {
        SecurityConstants.DANGEROUS_SYSTEM_PROPERTIES.forEach { (k, v) ->
            assertTrue(k.startsWith("[") && k.endsWith("]"))
            assertTrue(v.startsWith("[") && v.endsWith("]"))
        }
    }

    @Test
    fun packages_lookLikePackageNames() {
        SecurityConstants.ROOT_MANAGEMENT_PACKAGES.forEach {
            assertTrue(it, Regex("[a-z0-9_]+(\\.[a-z0-9_]+)+").matches(it))
        }
    }

    @Test
    fun listsAreNotEmpty() {
        assertTrue(SecurityConstants.ROOT_MANAGEMENT_PACKAGES.isNotEmpty())
        assertTrue(SecurityConstants.EMULATOR_PROPERTIES.isNotEmpty())
        assertTrue(SecurityConstants.FRIDA_LIBRARIES.isNotEmpty())
        assertTrue(SecurityConstants.DANGEROUS_SYSTEM_PROPERTIES.isNotEmpty())
    }
}
