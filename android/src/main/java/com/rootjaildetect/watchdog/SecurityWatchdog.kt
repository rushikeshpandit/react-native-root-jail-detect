package com.rootjaildetect.watchdog

import android.os.Handler
import android.os.Looper
import android.os.Process
import android.os.SystemClock
import android.util.Log
import com.rootjaildetect.RootDetection
import kotlin.concurrent.thread

/**
 * Singleton that periodically re-runs the security checks on a background thread and reacts to
 * threats according to a `ProtectionMode`. Loops are tracked by a generation counter so a
 * stopped loop can never run next to a new one.
 */
object SecurityWatchdog {
    private const val MIN_INTERVAL_MS = 100L

    private val lock = Any()

    /**
     * Identifies the currently active loop. Every start() bumps it and stop() invalidates it,
     * so a loop that is still sleeping from a previous start can never run alongside a new one.
     */
    @Volatile
    private var generation = 0L

    @Volatile
    private var running = false

    /**
     * Invoked with the detection reasons whenever a threat is found, before the
     * protection mode action is applied.
     */
    @Volatile
    var threatListener: ((List<String>) -> Unit)? = null

    // Seams for unit tests; production code never reassigns these.
    internal var uptimeMillis: () -> Long = { SystemClock.uptimeMillis() }
    internal var terminateProcess: () -> Unit = { Process.killProcess(Process.myPid()) }
    internal var throwOnMainThread: (RuntimeException) -> Unit = { error ->
        Handler(Looper.getMainLooper()).post { throw error }
    }
    internal var logError: (String) -> Unit = { Log.e("SecurityWatchdog", it) }

    /**
     * While the app is in the background the process can be frozen (cached-app freezer, Doze
     * throttling) for far longer than the timing-gap threshold without any debugger involved.
     * The gap check is therefore suspended while backgrounded and for one iteration after the
     * app returns to the foreground; otherwise TERMINATE mode would kill the app on resume.
     */
    @Volatile
    private var inBackground = false

    @Volatile
    private var skipNextGapCheck = false

    /**
     * Suspends the timing-gap check while the app is in the background, where the process may
     * legitimately be frozen for a long time.
     *
     * @return Nothing.
     */
    fun onAppBackgrounded() {
        inBackground = true
    }

    /**
     * Ends the background period and skips the next timing-gap check, so time spent suspended
     * is not mistaken for a debugger pause.
     *
     * @return Nothing.
     */
    fun onAppForegrounded() {
        skipNextGapCheck = true
        inBackground = false
    }

    val isRunning: Boolean
        get() = running

    /**
     * Starts the watchdog thread. Ignored if it is already running. Each iteration flags a
     * threat when the device looks rooted, a debugger is attached, or more than 4x the interval
     * passed since the last iteration; it then sleeps interval +-40%.
     *
     * @param detector Facade used for the checks and reasons.
     * @param intervalMs Base interval in milliseconds; values below 100 are raised to 100.
     * @param protectionMode Action applied on a threat.
     * @return Nothing.
     */
    fun start(
        detector: RootDetection,
        intervalMs: Long,
        protectionMode: ProtectionMode,
    ) {
        val myGeneration: Long
        synchronized(lock) {
            if (running) return
            running = true
            generation++
            myGeneration = generation
        }

        val interval = intervalMs.coerceAtLeast(MIN_INTERVAL_MS)

        thread(
            start = true,
            name = randomThreadName(),
            isDaemon = true,
        ) {
            // uptimeMillis does not advance during deep sleep, so device sleep / doze is not
            // mistaken for a debugger-induced pause.
            var lastRun = uptimeMillis()
            skipNextGapCheck = false

            while (generation == myGeneration) {
                try {
                    val now = uptimeMillis()

                    val gapExceeded =
                        if (inBackground) {
                            false
                        } else if (skipNextGapCheck) {
                            skipNextGapCheck = false
                            false
                        } else {
                            now - lastRun > interval * 4
                        }

                    if (gapExceeded || checkThreat(detector)) {
                        handleThreat(detector, protectionMode)
                    }

                    lastRun = now

                    Thread.sleep(randomDelay(interval))
                } catch (_: InterruptedException) {
                    return@thread
                } catch (_: Exception) {
                }
            }
        }
    }

    /**
     * Stops the watchdog; the running loop exits after its current iteration. Safe to call when
     * not running.
     *
     * @return Nothing.
     */
    fun stop() {
        synchronized(lock) {
            running = false
            generation++
        }
    }

    /**
     * Collects the reasons, notifies `threatListener` (errors are logged and swallowed) and
     * then applies the protection mode.
     *
     * @param detector Source of the threat reasons.
     * @param mode Action to apply.
     * @return Nothing.
     */
    private fun handleThreat(
        detector: RootDetection,
        mode: ProtectionMode,
    ) {
        val reasons = detector.getThreatReasons()

        try {
            threatListener?.invoke(reasons)
        } catch (e: Exception) {
            Log.e("SecurityWatchdog", "Threat listener failed", e)
        }

        when (mode) {
            ProtectionMode.LOG_ONLY -> {
                logError("Threat: $reasons")
            }

            ProtectionMode.THROW_EXCEPTION -> {
                // Thrown on the main thread: an exception thrown here would be swallowed
                // by the watchdog loop's catch block and never surface.
                throwOnMainThread(RuntimeException("Security threat detected: $reasons"))
            }

            ProtectionMode.TERMINATE -> {
                terminateProcess()
            }
        }
    }

    /**
     * Builds a random 12-letter lowercase thread name to make the watchdog thread harder to
     * find.
     *
     * @return The name.
     */
    private fun randomThreadName(): String {
        val chars = "abcdefghijklmnopqrstuvwxyz"
        return (1..12)
            .map { chars.random() }
            .joinToString("")
    }

    /**
     * Adds +-40% random jitter to the interval so timing is unpredictable.
     *
     * @param base Base interval in milliseconds.
     * @return A delay between 0.6x and 1.4x of `base`.
     */
    private fun randomDelay(base: Long): Long {
        val jitter = (base * 0.4).toLong()
        return base + (-jitter..jitter).random()
    }

    /**
     * One round of checks: root/instrumentation or debugger.
     *
     * @param detector Facade used for the checks.
     * @return `true` if either check reports a threat.
     */
    private fun checkThreat(detector: RootDetection): Boolean =
        detector.isDeviceRooted() ||
            detector.isDebuggerAttached()
}
