package com.rootjaildetect.checkers

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class HookFrameworkCheckerTest {
    private fun frame(cls: String) = StackTraceElement(cls, "run", "F.java", 1)

    private fun checker(
        classes: Set<String> = emptySet(),
        stack: List<String> = listOf("com.app.Main"),
    ) = HookFrameworkChecker(
        classExists = { it in classes },
        stackTrace = { stack.map(::frame).toTypedArray() },
    )

    @Test
    fun cleanProcess_hasNoReasons() {
        val c = checker()
        assertFalse(c.detectXposed())
        assertFalse(c.detectStack())
        assertTrue(c.getReasons().isEmpty())
    }

    @Test
    fun xposedBridge_isDetected() {
        val c = checker(classes = setOf("de.robv.android.xposed.XposedBridge"))
        assertTrue(c.detectXposed())
        assertEquals(listOf("Xposed framework detected"), c.getReasons())
    }

    @Test
    fun otherClass_isNotXposed() {
        assertFalse(checker(classes = setOf("de.robv.android.other.Thing")).detectXposed())
    }

    @Test
    fun xposedInStack_isDetected() {
        val c = checker(stack = listOf("com.app.Main", "de.robv.android.xposed.XposedBridge"))
        assertTrue(c.detectStack())
    }

    @Test
    fun fridaInStack_isDetected() {
        assertTrue(checker(stack = listOf("re.frida.Agent")).detectStack())
    }

    @Test
    fun stackMatch_isCaseInsensitive() {
        assertTrue(checker(stack = listOf("com.XPOSED.Hook")).detectStack())
        assertTrue(checker(stack = listOf("com.FrIdA.Hook")).detectStack())
    }

    @Test
    fun emptyStack_isClean() {
        assertFalse(checker(stack = emptyList()).detectStack())
    }

    @Test
    fun bothSignals_yieldTwoReasons() {
        val c =
            checker(
                classes = setOf("de.robv.android.xposed.XposedBridge"),
                stack = listOf("xposed.Foo"),
            )
        assertEquals(
            listOf("Xposed framework detected", "Hooking framework detected via stack trace"),
            c.getReasons(),
        )
    }

    @Test
    fun defaultConstructor_noXposedOnJvm() {
        assertFalse(HookFrameworkChecker().detectXposed())
    }

    @Test
    fun defaultConstructor_stackIsClean() {
        assertFalse(HookFrameworkChecker().detectStack())
    }
}
