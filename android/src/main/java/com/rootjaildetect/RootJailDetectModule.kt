package com.rootjaildetect

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.WritableArray
import com.rootjaildetect.watchdog.ProtectionMode
import com.rootjaildetect.watchdog.SecurityWatchdog

/**
 * RootJailDetectModule
 *
 * React Native native module that exposes device security checks
 * (root detection, emulator detection, and debugger detection)
 * to the JavaScript layer.
 *
 * This module acts as a bridge between React Native and
 * native Android security APIs.
 */
class RootJailDetectModule(
    reactContext: ReactApplicationContext,
) : NativeRootJailDetectSpec(reactContext) {
    /**
     * Internal instance of RootDetection responsible for
     * performing low-level security checks.
     */
    private val rootDetection = RootDetection(reactContext)

    /**
     * Checks whether the current device is compromised (rooted).
     *
     * This method is exposed to the JavaScript layer and executes
     * multiple native root-detection heuristics internally.
     *
     * The result is returned asynchronously via a Promise.
     *
     * @param promise Promise that resolves to true if the device is rooted,
     *                or false if the device appears secure.
     */
    override fun isDeviceCompromised(promise: Promise) {
        try {
            val isRooted = rootDetection.isDeviceRooted()
            promise.resolve(isRooted)
        } catch (e: Exception) {
            promise.reject(
                "ERROR",
                "Failed to check device security: ${e.message}",
                e,
            )
        }
    }

    /**
     * Determines whether the application is running inside
     * an Android emulator environment.
     *
     * Emulators are frequently rooted by default and may
     * represent higher security risk in production systems.
     *
     * The result is returned asynchronously via a Promise.
     *
     * @param promise Promise that resolves to true if running
     *                on an emulator, false otherwise.
     */
    override fun isEmulator(promise: Promise) {
        try {
            val isEmu = rootDetection.isEmulator()
            promise.resolve(isEmu)
        } catch (e: Exception) {
            promise.reject(
                "ERROR",
                "Failed to check emulator status: ${e.message}",
                e,
            )
        }
    }

    /**
     * Checks whether a debugger is currently attached
     * to the running application process.
     *
     * This helps detect debugging, reverse engineering,
     * and runtime inspection attempts.
     *
     * The result is returned asynchronously via a Promise.
     *
     * @param promise Promise that resolves to true if a debugger
     *                is attached, false otherwise.
     */
    override fun isDebuggerAttached(promise: Promise) {
        try {
            val isDebuggerAttached = rootDetection.isDebuggerAttached()
            promise.resolve(isDebuggerAttached)
        } catch (e: Exception) {
            promise.reject(
                "ERROR",
                "Failed to check debugger status: ${e.message}",
                e,
            )
        }
    }

    override fun getDetectionReasons(promise: Promise) {
        try {
            val reasons = rootDetection.getDetectionReasons()

            val result: WritableArray = Arguments.createArray()

            reasons.forEach {
                result.pushString(it)
            }

            promise.resolve(result)
        } catch (e: Exception) {
            promise.reject("ERROR", "Failed to get detection reasons", e)
        }
    }

    /**
     * Starts a security watchdog that periodically checks the device's security status.
     *
     * The watchdog will execute the specified protection mode when a security violation is detected.
     *
     * Available protection modes:
     *   - "TERMINATE": terminates the app process immediately
     *   - "THROW_EXCEPTION": throws an exception that can be caught by the app
     *   - "LOG_ONLY": logs a warning message to the console (default)
     *
     * The interval at which the watchdog checks the device's security status is specified in milliseconds.
     *
     * @param options ReadableMap containing the following keys:
     *   - "interval": Long value specifying the interval at which the watchdog checks the device's security status
     *   - "protectionMode": String value specifying the protection mode to execute when a security violation is detected
     */

    override fun startSecurityWatchdog(options: ReadableMap) {
        val interval =
            if (options.hasKey("interval")) options.getInt("interval") else 3000

        val modeString =
            if (options.hasKey("protectionMode")) {
                options.getString("protectionMode")
            } else {
                "LOG_ONLY"
            }

        val mode =
            when (modeString) {
                "TERMINATE" -> ProtectionMode.TERMINATE
                "THROW_EXCEPTION" -> ProtectionMode.THROW_EXCEPTION
                else -> ProtectionMode.LOG_ONLY
            }

        val detector = RootDetection(reactApplicationContext)

        SecurityWatchdog.start(
            detector,
            interval.toLong(),
            mode,
        )
    }

    override fun stopSecurityWatchdog() {
        SecurityWatchdog.stop()
    }

    companion object {
        /**
         * Name of the native module exposed to React Native.
         *
         * This value is used internally by the React Native
         * bridge for module registration and lookup.
         */
        const val NAME = NativeRootJailDetectSpec.NAME
    }
}
