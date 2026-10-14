package com.rootjaildetect.checkers

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class DebuggerCheckerTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private fun status(content: String?): File {
        val f = File(tmp.root, "status")
        if (content != null) f.writeText(content)
        return f
    }

    private fun checker(
        status: File,
        connected: Boolean = false,
        waiting: Boolean = false,
    ) = DebuggerChecker(status, { connected }, { waiting })

    @Test
    fun noDebugger_isNotAttached() {
        val c = checker(status("Name:\tapp\nTracerPid:\t0\n"))
        assertFalse(c.isDebuggerAttached())
        assertTrue(c.getReasons().isEmpty())
    }

    @Test
    fun jdwpConnected_isDetected() {
        val c = checker(status("TracerPid:\t0"), connected = true)
        assertEquals(listOf("Debugger is connected"), c.getReasons())
        assertTrue(c.isDebuggerAttached())
    }

    @Test
    fun waitingForDebugger_isDetected() {
        val c = checker(status("TracerPid:\t0"), waiting = true)
        assertEquals(listOf("Application waiting for debugger"), c.getReasons())
    }

    @Test
    fun positiveTracerPid_isDetected() {
        val c = checker(status("Name:\tapp\nTracerPid:\t1234\nUid:\t1"))
        assertEquals(listOf("TracerPid indicates debugger attachment"), c.getReasons())
    }

    @Test
    fun tracerPidWithSpaces_isParsed() {
        assertTrue(checker(status("TracerPid:   42  ")).isDebuggerAttached())
    }

    @Test
    fun allSignals_yieldThreeReasons() {
        val c = checker(status("TracerPid:\t7"), connected = true, waiting = true)
        assertEquals(3, c.getReasons().size)
    }

    @Test
    fun zeroTracerPid_isIgnored() {
        assertFalse(checker(status("TracerPid:\t0")).isDebuggerAttached())
    }

    @Test
    fun missingTracerPidLine_isIgnored() {
        assertFalse(checker(status("Name:\tapp\nPid:\t1")).isDebuggerAttached())
    }

    @Test
    fun nonNumericTracerPid_isIgnored() {
        assertFalse(checker(status("TracerPid:\tabc")).isDebuggerAttached())
    }

    @Test
    fun emptyTracerPid_isIgnored() {
        assertFalse(checker(status("TracerPid:")).isDebuggerAttached())
    }

    @Test
    fun negativeTracerPid_isIgnored() {
        assertFalse(checker(status("TracerPid:\t-1")).isDebuggerAttached())
    }

    @Test
    fun emptyFile_isIgnored() {
        assertFalse(checker(status("")).isDebuggerAttached())
    }

    @Test
    fun missingStatusFile_isIgnored() {
        assertFalse(checker(File(tmp.root, "does-not-exist")).isDebuggerAttached())
    }

    @Test
    fun missingStatusFile_stillReportsOtherSignals() {
        val c = checker(File(tmp.root, "nope"), connected = true)
        assertTrue(c.isDebuggerAttached())
    }

    @Test
    fun indentedTracerPidLine_isNotMatched() {
        assertFalse(checker(status("  TracerPid:\t99")).isDebuggerAttached())
    }
}
