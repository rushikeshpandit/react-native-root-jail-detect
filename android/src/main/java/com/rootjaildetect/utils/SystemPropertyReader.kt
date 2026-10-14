package com.rootjaildetect.utils

/**
 * Reads Android system properties through reflection on the hidden
 * `android.os.SystemProperties` class.
 */
object SystemPropertyReader {
    /**
     * Reads one system property.
     *
     * @param key Property name, for example `ro.hardware`.
     * @return The value, or `null` if the property is unset or reflection fails.
     */
    fun getProperty(key: String): String? =
        try {
            val clazz = Class.forName("android.os.SystemProperties")
            val method = clazz.getMethod("get", String::class.java)
            method.invoke(clazz, key) as? String
        } catch (_: Exception) {
            null
        }
}
