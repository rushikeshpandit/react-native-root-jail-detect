package com.rootjaildetect.utils

/**
 * Reads Android system properties via reflection.
 */
object SystemPropertyReader {
    fun getProperty(key: String): String? =
        try {
            val clazz = Class.forName("android.os.SystemProperties")
            val method = clazz.getMethod("get", String::class.java)
            method.invoke(clazz, key) as? String
        } catch (_: Exception) {
            null
        }
}
