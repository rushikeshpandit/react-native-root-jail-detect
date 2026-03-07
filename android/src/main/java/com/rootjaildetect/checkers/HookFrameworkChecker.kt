package com.rootjaildetect.checkers

/**
 * HookFrameworkChecker
 *
 * Detects runtime method hooking frameworks such as Xposed.
 */
class HookFrameworkChecker {
    fun getReasons(): List<String> {
        val reasons = mutableListOf<String>()

        if (detectXposed()) {
            reasons.add("Xposed framework detected")
        }

        if (detectStack()) {
            reasons.add("Hooking framework detected via stack trace")
        }

        return reasons
    }

    fun detectXposed(): Boolean =
        try {
            Class.forName("de.robv.android.xposed.XposedBridge")
            true
        } catch (_: Exception) {
            false
        }

    fun detectStack(): Boolean =
        Throwable().stackTrace.any {
            it.className.contains("xposed", true) ||
                it.className.contains("frida", true)
        }
}
