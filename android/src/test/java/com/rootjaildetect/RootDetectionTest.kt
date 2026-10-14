package com.rootjaildetect

import android.content.Context
import com.rootjaildetect.checkers.DebuggerChecker
import com.rootjaildetect.checkers.EmulatorChecker
import com.rootjaildetect.checkers.FridaChecker
import com.rootjaildetect.checkers.HookFrameworkChecker
import com.rootjaildetect.checkers.NativeProbe
import com.rootjaildetect.checkers.RootChecker
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito.mock
import org.mockito.Mockito.never
import org.mockito.Mockito.verify
import org.mockito.Mockito.`when`

class RootDetectionTest {
    private class FakeProbe(
        var ptrace: Boolean = false,
        var fridaNative: Boolean = false,
        var inlineHook: Boolean = false,
        var fridaSyscall: Boolean = false,
    ) : NativeProbe {
        override fun detectPtrace() = ptrace

        override fun detectFridaNative() = fridaNative

        override fun detectInlineHook() = inlineHook

        override fun detectFridaSyscall() = fridaSyscall
    }

    private lateinit var root: RootChecker
    private lateinit var emulator: EmulatorChecker
    private lateinit var debugger: DebuggerChecker
    private lateinit var frida: FridaChecker
    private lateinit var hook: HookFrameworkChecker
    private lateinit var probe: FakeProbe

    @Before
    fun setUp() {
        root = mock(RootChecker::class.java)
        emulator = mock(EmulatorChecker::class.java)
        debugger = mock(DebuggerChecker::class.java)
        frida = mock(FridaChecker::class.java)
        hook = mock(HookFrameworkChecker::class.java)
        probe = FakeProbe()
        `when`(root.getReasons()).thenReturn(emptyList())
        `when`(emulator.getReasons()).thenReturn(emptyList())
        `when`(debugger.getReasons()).thenReturn(emptyList())
        `when`(frida.getReasons()).thenReturn(emptyList())
        `when`(hook.getReasons()).thenReturn(emptyList())
    }

    private fun detection() =
        RootDetection(mock(Context::class.java), root, emulator, debugger, frida, hook, probe)

    // ---------- isDeviceRooted ----------

    @Test
    fun allClean_isNotRooted() {
        assertFalse(detection().isDeviceRooted())
    }

    @Test
    fun rootChecker_triggersRooted() {
        `when`(root.isDeviceRooted()).thenReturn(true)
        assertTrue(detection().isDeviceRooted())
    }

    @Test
    fun frida_triggersRooted() {
        `when`(frida.isFridaDetected()).thenReturn(true)
        assertTrue(detection().isDeviceRooted())
    }

    @Test
    fun xposed_triggersRooted() {
        `when`(hook.detectXposed()).thenReturn(true)
        assertTrue(detection().isDeviceRooted())
    }

    @Test
    fun stackHook_triggersRooted() {
        `when`(hook.detectStack()).thenReturn(true)
        assertTrue(detection().isDeviceRooted())
    }

    @Test
    fun eachNativeProbe_triggersRooted() {
        listOf<(FakeProbe) -> Unit>(
            { it.ptrace = true },
            { it.fridaNative = true },
            { it.inlineHook = true },
            { it.fridaSyscall = true },
        ).forEach { mutate ->
            probe = FakeProbe().also(mutate)
            assertTrue(detection().isDeviceRooted())
        }
    }

    @Test
    fun isDeviceRooted_shortCircuits() {
        `when`(root.isDeviceRooted()).thenReturn(true)
        detection().isDeviceRooted()
        verify(frida, never()).isFridaDetected()
    }

    @Test
    fun emulatorAndDebugger_doNotMakeDeviceRooted() {
        `when`(emulator.isEmulator()).thenReturn(true)
        `when`(debugger.isDebuggerAttached()).thenReturn(true)
        assertFalse(detection().isDeviceRooted())
    }

    // ---------- delegation ----------

    @Test
    fun isEmulator_delegates() {
        `when`(emulator.isEmulator()).thenReturn(true)
        assertTrue(detection().isEmulator())
        `when`(emulator.isEmulator()).thenReturn(false)
        assertFalse(detection().isEmulator())
    }

    @Test
    fun isDebuggerAttached_delegates() {
        `when`(debugger.isDebuggerAttached()).thenReturn(true)
        assertTrue(detection().isDebuggerAttached())
        `when`(debugger.isDebuggerAttached()).thenReturn(false)
        assertFalse(detection().isDebuggerAttached())
    }

    // ---------- reasons ----------

    @Test
    fun reasons_clean_isEmpty() {
        assertTrue(detection().getDetectionReasons().isEmpty())
    }

    @Test
    fun reasons_aggregateAllCheckers() {
        `when`(root.getReasons()).thenReturn(listOf("r"))
        `when`(emulator.getReasons()).thenReturn(listOf("e"))
        `when`(debugger.getReasons()).thenReturn(listOf("d"))
        `when`(frida.getReasons()).thenReturn(listOf("f"))
        `when`(hook.getReasons()).thenReturn(listOf("h"))
        assertEquals(listOf("r", "e", "d", "f", "h"), detection().getDetectionReasons())
    }

    @Test
    fun reasons_includeNativeFindings() {
        probe = FakeProbe(true, true, true, true)
        assertEquals(
            listOf(
                "Debugger detected via ptrace",
                "Frida detected via native memory scan",
                "Inline hook detected in libc",
                "Frida detected via syscall inspection",
            ),
            detection().getDetectionReasons(),
        )
    }

    @Test
    fun threatReasons_excludeEmulatorFindings() {
        `when`(root.getReasons()).thenReturn(listOf("r"))
        `when`(emulator.getReasons()).thenReturn(listOf("e"))
        `when`(debugger.getReasons()).thenReturn(listOf("d"))
        assertEquals(listOf("r", "d"), detection().getThreatReasons())
    }

    @Test
    fun threatReasons_includeNativeFindings() {
        probe = FakeProbe(ptrace = true)
        assertEquals(listOf("Debugger detected via ptrace"), detection().getThreatReasons())
    }

    @Test
    fun threatReasons_emulatorOnly_isEmpty() {
        `when`(emulator.getReasons()).thenReturn(listOf("e"))
        assertTrue(detection().getThreatReasons().isEmpty())
    }

    @Test
    fun reasons_areDeduplicated() {
        `when`(root.getReasons()).thenReturn(listOf("same"))
        `when`(hook.getReasons()).thenReturn(listOf("same", "other"))
        assertEquals(listOf("same", "other"), detection().getDetectionReasons())
    }

    @Test
    fun reasons_onlyReportTrueNativeProbes() {
        probe = FakeProbe(inlineHook = true)
        assertEquals(listOf("Inline hook detected in libc"), detection().getDetectionReasons())
    }
}
