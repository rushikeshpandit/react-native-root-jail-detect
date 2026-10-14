package com.rootjaildetect.checkers

/**
 * Detects runtime hooking frameworks such as Xposed.
 *
 * @param classExists Tells whether a class can be loaded.
 * @param stackTrace Supplies the current stack trace.
 */
class HookFrameworkChecker(
    private val classExists: (String) -> Boolean = {
        try {
            Class.forName(it)
            true
        } catch (_: Throwable) {
            false
        }
    },
    private val stackTrace: () -> Array<StackTraceElement> = { Throwable().stackTrace },
) {
    /**
     * Runs both hook checks.
     *
     * @return One message per positive check; empty when clean.
     */
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

    /**
     * Tries to load `XposedBridge`.
     *
     * @return `true` if the class is present.
     */
    fun detectXposed(): Boolean =
        classExists("de.robv.android.xposed.XposedBridge")

    /**
     * Looks for `xposed` or `frida` in class names of the current stack trace
     * (case-insensitive).
     *
     * @return `true` if any frame matches.
     */
    fun detectStack(): Boolean =
        stackTrace().any {
            it.className.contains("xposed", true) ||
                it.className.contains("frida", true)
        }
}
