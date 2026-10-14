package com.rootjaildetect.utils

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.io.IOException

class CommandExecutorTest {
    private val hasEcho = File("/bin/echo").exists()

    @Test
    fun execute_returnsStdoutLines() {
        assumeTrue(hasEcho)
        assertEquals(listOf("hello"), CommandExecutor.execute("/bin/echo hello"))
    }

    @Test
    fun execute_multiWordOutput_isOneLine() {
        assumeTrue(hasEcho)
        assertEquals(listOf("a b c"), CommandExecutor.execute("/bin/echo a b c"))
    }

    @Test
    fun execute_noOutput_returnsEmptyList() {
        assumeTrue(File("/usr/bin/true").exists())
        assertTrue(CommandExecutor.execute("/usr/bin/true").isEmpty())
    }

    @Test(expected = IOException::class)
    fun execute_unknownCommand_throws() {
        CommandExecutor.execute("/definitely/not/a/command")
    }

    @Test(expected = Exception::class)
    fun execute_emptyCommand_throws() {
        CommandExecutor.execute("")
    }
}
