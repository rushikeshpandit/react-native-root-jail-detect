package com.rootjaildetect

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.LifecycleEventListener
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.WritableArray
import com.facebook.react.modules.core.DeviceEventManagerModule
import com.rootjaildetect.watchdog.ProtectionMode
import com.rootjaildetect.watchdog.SecurityWatchdog

/**
 * Bridge between JavaScript and the Android security checks. Implements the codegen spec,
 * registers itself as a lifecycle listener (so the watchdog can ignore time spent in the
 * background) and forwards watchdog threats to JavaScript as `onSecurityThreat` events.
 *
 * @param reactContext React application context.
 * @param rootDetection Detection facade; injectable so tests can replace it. Defaults to a real
 *     `RootDetection`.
 */
class RootJailDetectModule(
    reactContext: ReactApplicationContext,
    private val rootDetection: RootDetection = RootDetection(reactContext),
) : NativeRootJailDetectSpec(reactContext),
    LifecycleEventListener {
    init {
        reactContext.addLifecycleEventListener(this)
    }

    // The watchdog's pause detection must not treat backgrounding as a debugger pause.
    /**
     * Lifecycle callback: the app returned to the foreground. Tells the watchdog to skip its
     * next timing-gap check so time spent suspended is not mistaken for a debugger pause.
     *
     * @return Nothing.
     */
    override fun onHostResume() = SecurityWatchdog.onAppForegrounded()

    /**
     * Lifecycle callback: the app moved to the background. Suspends the watchdog's timing-gap
     * check until the app resumes.
     *
     * @return Nothing.
     */
    override fun onHostPause() = SecurityWatchdog.onAppBackgrounded()

    /**
     * Lifecycle callback: the host activity was destroyed. Nothing to clean up.
     *
     * @return Nothing.
     */
    override fun onHostDestroy() {}

    /**
     * Runs every root/instrumentation heuristic and resolves the combined verdict.
     *
     * @param promise Resolved with `true` if the device is rooted/instrumented, `false`
     *     otherwise. Rejected with code `ERROR` and a `Failed to check device security` message
     *     if a check throws.
     * @return Nothing; the result is delivered through `promise`.
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
     * Checks whether the app runs inside an Android emulator.
     *
     * @param promise Resolved with `true` on an emulator, `false` otherwise. Rejected with code
     *     `ERROR` if a check throws.
     * @return Nothing; the result is delivered through `promise`.
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
     * Checks whether a debugger is attached to the process (JDWP, wait-for-debugger or non-zero
     * `TracerPid`).
     *
     * @param promise Resolved with `true` if a debugger is attached. Rejected with code `ERROR`
     *     if a check throws.
     * @return Nothing; the result is delivered through `promise`.
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

    /**
     * Collects the human-readable reasons from every checker (root, emulator, debugger, Frida,
     * hooks and native probes), de-duplicated.
     *
     * @param promise Resolved with a `WritableArray` of strings (empty when nothing was found).
     *     Rejected with code `ERROR` if a check throws.
     * @return Nothing; the result is delivered through `promise`.
     */
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

    /**
     * Starts the runtime watchdog and wires its threat listener to the `onSecurityThreat` JS
     * event. Does nothing if the watchdog already runs.
     *
     * @param options Map with optional keys `interval` (number of ms, default 3000; read as a
     *     double so fractional JS numbers are accepted; the watchdog clamps it to at least 100)
     *     and `protectionMode` (`LOG_ONLY`, `THROW_EXCEPTION` or `TERMINATE`; missing, null or
     *     unknown values mean `LOG_ONLY`).
     * @return Nothing.
     */
    override fun startSecurityWatchdog(options: ReadableMap) {
        val interval =
            if (options.hasKey("interval") && !options.isNull("interval")) {
                options.getDouble("interval").toLong()
            } else {
                3000L
            }

        val modeString =
            if (options.hasKey("protectionMode") && !options.isNull("protectionMode")) {
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

        SecurityWatchdog.threatListener = { reasons -> emitThreat(reasons) }

        SecurityWatchdog.start(
            rootDetection,
            interval,
            mode,
        )
    }

    /**
     * Stops the runtime watchdog. Safe to call when it is not running.
     *
     * @return Nothing.
     */
    override fun stopSecurityWatchdog() {
        SecurityWatchdog.stop()
    }

    /**
     * Reports whether the watchdog loop is active.
     *
     * @param promise Resolved with `true` while the watchdog runs, `false` otherwise.
     * @return Nothing; the result is delivered through `promise`.
     */
    override fun isSecurityWatchdogRunning(promise: Promise) {
        promise.resolve(SecurityWatchdog.isRunning)
    }

    // Required by NativeEventEmitter; events are always emitted, so nothing to track.
    /**
     * Required by `NativeEventEmitter`. Events are always emitted, so there is nothing to
     * track.
     *
     * @param eventName Name of the event JS subscribed to.
     * @return Nothing.
     */
    override fun addListener(eventName: String) {}

    /**
     * Required by `NativeEventEmitter`. No bookkeeping is needed.
     *
     * @param count Number of listeners JS removed.
     * @return Nothing.
     */
    override fun removeListeners(count: Double) {}

    /**
     * Sends an `onSecurityThreat` event to JavaScript. Skipped when there is no active React
     * instance (for example during a reload).
     *
     * @param reasons Human-readable reasons reported by the watchdog. Delivered as `{ reasons:
     *     string[], timestamp: number }`, the timestamp being epoch milliseconds.
     * @return Nothing.
     */
    private fun emitThreat(reasons: List<String>) {
        if (!reactApplicationContext.hasActiveReactInstance()) return

        val reasonsArray: WritableArray = Arguments.createArray()
        reasons.forEach { reasonsArray.pushString(it) }

        val payload = Arguments.createMap()
        payload.putArray("reasons", reasonsArray)
        payload.putDouble("timestamp", System.currentTimeMillis().toDouble())

        reactApplicationContext
            .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter::class.java)
            .emit(THREAT_EVENT, payload)
    }

    companion object {
        /**
         * Name of the native module exposed to React Native.
         *
         * This value is used internally by the React Native
         * bridge for module registration and lookup.
         */
        const val NAME = NativeRootJailDetectSpec.NAME

        /** Event emitted to JS when the security watchdog detects a threat. */
        const val THREAT_EVENT = "onSecurityThreat"
    }
}
