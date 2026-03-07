package com.rootjaildetect.constants

object SecurityConstants {
    /**
     * List of well-known root management applications.
     */
    val ROOT_MANAGEMENT_PACKAGES =
        arrayOf(
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.topjohnwu.magisk",
            "com.kingroot.kinguser",
            "com.kingo.root",
            "com.smedialink.oneclickroot",
            "com.zhiqupk.rootking",
            "com.alephzain.framaroot",
        )

    /**
     * Common filesystem locations where the "su" binary may exist.
     */
    val SU_BINARY_DIRECTORIES =
        arrayOf(
            "/data/local/",
            "/data/local/bin/",
            "/data/local/xbin/",
            "/sbin/",
            "/su/bin/",
            "/system/bin/",
            "/system/bin/.ext/",
            "/system/bin/failsafe/",
            "/system/sd/xbin/",
            "/system/usr/we-need-root/",
            "/system/xbin/",
            "/cache/",
            "/data/",
            "/dev/",
        )

    /**
     * System properties that indicate an insecure or rooted device.
     */
    val DANGEROUS_SYSTEM_PROPERTIES =
        mapOf(
            "[ro.debuggable]" to "[1]",
            "[ro.secure]" to "[0]",
            "[service.adb.root]" to "[1]",
        )

    /**
     * Files and directories commonly used by root hiding frameworks.
     */
    val ROOT_CLOAKING_FILE_PATHS =
        arrayOf(
            "/system/app/Superuser.apk",
            "/system/etc/init.d/99SuperSUDaemon",
            "/dev/com.koushikdutta.superuser.daemon/",
            "/system/xbin/daemonsu",
        )

    /**
     * Files and directories commonly used by emulators.
     */
    val KNOWN_FILES =
        arrayOf(
            "/dev/socket/qemud",
            "/dev/qemu_pipe",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace",
            "/system/bin/qemu-props",
        )

    /**
     * System properties commonly used by emulators.
     */
    val EMULATOR_PROPERTIES =
        arrayOf(
            "ro.kernel.qemu" to "1",
            "ro.hardware" to "goldfish",
            "ro.product.device" to "generic",
        )

    /**
     * Commonly used Frida libraries.
     */
    val FRIDA_LIBRARIES =
        listOf(
            "frida-agent",
            "frida-gadget",
            "frida-server",
            "re.frida.server",
        )
}
