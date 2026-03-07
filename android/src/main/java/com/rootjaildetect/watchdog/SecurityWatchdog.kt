package com.rootjaildetect.watchdog

import android.os.Process
import android.util.Log
import com.rootjaildetect.RootDetection
import com.rootjaildetect.watchdog.ProtectionMode
import kotlin.concurrent.thread

object SecurityWatchdog {
    private var running = false
    private var interval: Long = 3000
    private var mode: ProtectionMode = ProtectionMode.LOG_ONLY
    private var lastRun = System.currentTimeMillis()

    fun start(
        detector: RootDetection,
        intervalMs: Long,
        protectionMode: ProtectionMode,
    ) {
        if (running) return

        interval = intervalMs
        mode = protectionMode
        running = true

        thread(
            start = true,
            name = randomThreadName(),
            isDaemon = true,
        ) {
            while (running) {
                try {
                    val now = System.currentTimeMillis()

                    if (now - lastRun > interval * 4) {
                        handleThreat(detector)
                    }

                    if (checkThreat(detector)) {
                        handleThreat(detector)
                    }

                    lastRun = now

                    Thread.sleep(randomDelay(interval))
                } catch (_: Exception) {
                }
            }
        }
    }

    private fun handleThreat(detector: RootDetection) {
        val reasons = detector.getDetectionReasons()

        when (mode) {
            ProtectionMode.LOG_ONLY -> {
                Log.e("SecurityWatchdog", "Threat: $reasons")
            }

            ProtectionMode.THROW_EXCEPTION -> {
                throw RuntimeException("Security threat detected: $reasons")
            }

            ProtectionMode.TERMINATE -> {
                Process.killProcess(Process.myPid())
            }
        }
    }

    fun stop() {
        running = false
    }

    private fun randomThreadName(): String {
        val chars = "abcdefghijklmnopqrstuvwxyz"
        return (1..12)
            .map { chars.random() }
            .joinToString("")
    }

    private fun randomDelay(base: Long): Long {
        val jitter = (base * 0.4).toLong()
        return base + (-jitter..jitter).random()
    }

    private fun checkThreat(detector: RootDetection): Boolean =
        detector.isDeviceRooted() ||
            detector.isDebuggerAttached()
}
