package com.rootjaildetect.watchdog

import com.rootjaildetect.RootDetection
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito.mock
import org.mockito.Mockito.`when`
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

class SecurityWatchdogTest {
    private lateinit var detector: RootDetection
    private val thrown = CopyOnWriteArrayList<RuntimeException>()
    private val logs = CopyOnWriteArrayList<String>()
    private val terminated = AtomicInteger()
    private val clock = AtomicLong(0)

    @Before
    fun setUp() {
        SecurityWatchdog.stop()
        SecurityWatchdog.onAppForegrounded()
        detector = mock(RootDetection::class.java)
        `when`(detector.getThreatReasons()).thenReturn(listOf("reason-a"))
        thrown.clear()
        logs.clear()
        terminated.set(0)
        clock.set(0)
        SecurityWatchdog.threatListener = null
        SecurityWatchdog.throwOnMainThread = { thrown += it }
        SecurityWatchdog.logError = { logs += it }
        SecurityWatchdog.terminateProcess = { terminated.incrementAndGet() }
        SecurityWatchdog.uptimeMillis = { clock.get() }
    }

    @After
    fun tearDown() {
        SecurityWatchdog.stop()
        SecurityWatchdog.threatListener = null
    }

    private fun awaitTrue(
        timeoutMs: Long = 3000,
        cond: () -> Boolean,
    ): Boolean {
        val end = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < end) {
            if (cond()) return true
            Thread.sleep(10)
        }
        return cond()
    }

    // ---------- lifecycle ----------

    @Test
    fun initially_notRunning() {
        assertFalse(SecurityWatchdog.isRunning)
    }

    @Test
    fun start_setsRunning_stop_clearsIt() {
        SecurityWatchdog.start(detector, 100, ProtectionMode.LOG_ONLY)
        assertTrue(SecurityWatchdog.isRunning)
        SecurityWatchdog.stop()
        assertFalse(SecurityWatchdog.isRunning)
    }

    @Test
    fun stop_whenNotRunning_isHarmless() {
        SecurityWatchdog.stop()
        SecurityWatchdog.stop()
        assertFalse(SecurityWatchdog.isRunning)
    }

    @Test
    fun secondStart_whileRunning_isIgnored() {
        `when`(detector.isDeviceRooted()).thenReturn(true)
        val listenerCalls = AtomicInteger()
        SecurityWatchdog.threatListener = { listenerCalls.incrementAndGet() }

        SecurityWatchdog.start(detector, 100, ProtectionMode.LOG_ONLY)
        // Different mode must NOT replace the running configuration.
        SecurityWatchdog.start(detector, 100, ProtectionMode.TERMINATE)

        assertTrue(awaitTrue { listenerCalls.get() > 0 })
        assertEquals(0, terminated.get())
    }

    @Test
    fun restart_afterStop_works() {
        `when`(detector.isDeviceRooted()).thenReturn(true)
        val calls = AtomicInteger()
        SecurityWatchdog.threatListener = { calls.incrementAndGet() }

        SecurityWatchdog.start(detector, 100, ProtectionMode.LOG_ONLY)
        assertTrue(awaitTrue { calls.get() > 0 })
        SecurityWatchdog.stop()

        calls.set(0)
        SecurityWatchdog.start(detector, 100, ProtectionMode.LOG_ONLY)
        assertTrue(SecurityWatchdog.isRunning)
        assertTrue(awaitTrue { calls.get() > 0 })
    }

    @Test
    fun stop_haltsFurtherChecks() {
        `when`(detector.isDeviceRooted()).thenReturn(true)
        val calls = AtomicInteger()
        SecurityWatchdog.threatListener = { calls.incrementAndGet() }

        SecurityWatchdog.start(detector, 100, ProtectionMode.LOG_ONLY)
        assertTrue(awaitTrue { calls.get() > 0 })
        SecurityWatchdog.stop()
        Thread.sleep(250) // let any in-flight iteration finish
        val after = calls.get()
        Thread.sleep(400)
        assertEquals(after, calls.get())
    }

    @Test
    fun rapidStopStart_neverRunsTwoLoops() {
        `when`(detector.isDeviceRooted()).thenReturn(true)
        val calls = AtomicInteger()
        SecurityWatchdog.threatListener = { calls.incrementAndGet() }

        repeat(5) {
            SecurityWatchdog.start(detector, 100, ProtectionMode.LOG_ONLY)
            SecurityWatchdog.stop()
        }
        Thread.sleep(300)
        val settled = calls.get()
        Thread.sleep(400)
        assertEquals("a stale loop kept running", settled, calls.get())
    }

    // ---------- threat detection ----------

    @Test
    fun cleanDevice_noThreat() {
        val calls = AtomicInteger()
        SecurityWatchdog.threatListener = { calls.incrementAndGet() }
        SecurityWatchdog.start(detector, 100, ProtectionMode.TERMINATE)
        Thread.sleep(400)
        assertEquals(0, calls.get())
        assertEquals(0, terminated.get())
        assertTrue(thrown.isEmpty())
    }

    @Test
    fun rootedDevice_triggersThreat() {
        `when`(detector.isDeviceRooted()).thenReturn(true)
        val seen = CopyOnWriteArrayList<List<String>>()
        SecurityWatchdog.threatListener = { seen += it }
        SecurityWatchdog.start(detector, 100, ProtectionMode.LOG_ONLY)
        assertTrue(awaitTrue { seen.isNotEmpty() })
        assertEquals(listOf("reason-a"), seen.first())
    }

    @Test
    fun debuggerAttached_triggersThreat() {
        `when`(detector.isDebuggerAttached()).thenReturn(true)
        val calls = AtomicInteger()
        SecurityWatchdog.threatListener = { calls.incrementAndGet() }
        SecurityWatchdog.start(detector, 100, ProtectionMode.LOG_ONLY)
        assertTrue(awaitTrue { calls.get() > 0 })
    }

    // ---------- protection modes ----------

    @Test
    fun logOnly_logsAndDoesNothingElse() {
        `when`(detector.isDeviceRooted()).thenReturn(true)
        SecurityWatchdog.start(detector, 100, ProtectionMode.LOG_ONLY)
        assertTrue(awaitTrue { logs.isNotEmpty() })
        assertTrue(logs.first().contains("reason-a"))
        assertEquals(0, terminated.get())
        assertTrue(thrown.isEmpty())
    }

    @Test
    fun throwException_surfacesExceptionOutsideWatchdogLoop() {
        `when`(detector.isDeviceRooted()).thenReturn(true)
        SecurityWatchdog.start(detector, 100, ProtectionMode.THROW_EXCEPTION)
        assertTrue("exception was swallowed", awaitTrue { thrown.isNotEmpty() })
        assertTrue(thrown.first().message!!.contains("reason-a"))
        assertEquals(0, terminated.get())
    }

    @Test
    fun throwException_keepsWatchdogAlive() {
        `when`(detector.isDeviceRooted()).thenReturn(true)
        SecurityWatchdog.start(detector, 100, ProtectionMode.THROW_EXCEPTION)
        assertTrue(awaitTrue { thrown.size >= 2 })
    }

    @Test
    fun terminate_killsProcess() {
        `when`(detector.isDeviceRooted()).thenReturn(true)
        SecurityWatchdog.start(detector, 100, ProtectionMode.TERMINATE)
        assertTrue(awaitTrue { terminated.get() > 0 })
        assertTrue(thrown.isEmpty())
    }

    // ---------- listener ----------

    @Test
    fun listener_isNotifiedBeforeTermination() {
        `when`(detector.isDeviceRooted()).thenReturn(true)
        val order = CopyOnWriteArrayList<String>()
        SecurityWatchdog.threatListener = { order += "listener" }
        SecurityWatchdog.terminateProcess = { order += "terminate" }
        SecurityWatchdog.start(detector, 100, ProtectionMode.TERMINATE)
        assertTrue(awaitTrue { order.size >= 2 })
        assertEquals(listOf("listener", "terminate"), order.take(2))
    }

    @Test
    fun listener_isNotifiedInEveryMode() {
        `when`(detector.isDeviceRooted()).thenReturn(true)
        ProtectionMode.values().forEach { mode ->
            val calls = AtomicInteger()
            SecurityWatchdog.threatListener = { calls.incrementAndGet() }
            SecurityWatchdog.start(detector, 100, mode)
            assertTrue(mode.name, awaitTrue { calls.get() > 0 })
            SecurityWatchdog.stop()
        }
    }

    @Test
    fun throwingListener_doesNotPreventProtectionAction() {
        `when`(detector.isDeviceRooted()).thenReturn(true)
        SecurityWatchdog.threatListener = { throw IllegalStateException("bad listener") }
        SecurityWatchdog.start(detector, 100, ProtectionMode.TERMINATE)
        assertTrue(awaitTrue { terminated.get() > 0 })
    }

    @Test
    fun noListener_isFine() {
        `when`(detector.isDeviceRooted()).thenReturn(true)
        assertNull(SecurityWatchdog.threatListener)
        SecurityWatchdog.start(detector, 100, ProtectionMode.TERMINATE)
        assertTrue(awaitTrue { terminated.get() > 0 })
    }

    // ---------- robustness ----------

    @Test
    fun detectorThrowing_doesNotKillLoop() {
        val attempts = AtomicInteger()
        `when`(detector.isDeviceRooted()).thenAnswer {
            if (attempts.incrementAndGet() == 1) throw IllegalStateException("boom") else true
        }
        val calls = AtomicInteger()
        SecurityWatchdog.threatListener = { calls.incrementAndGet() }
        SecurityWatchdog.start(detector, 100, ProtectionMode.LOG_ONLY)
        assertTrue("loop died after exception", awaitTrue { calls.get() > 0 })
    }

    @Test
    fun intervalBelowMinimum_isClamped() {
        `when`(detector.isDeviceRooted()).thenReturn(true)
        val calls = AtomicInteger()
        SecurityWatchdog.threatListener = { calls.incrementAndGet() }
        SecurityWatchdog.start(detector, 0, ProtectionMode.LOG_ONLY)
        Thread.sleep(500)
        // 0 ms would spin thousands of times; clamp to >=100ms (±40% jitter) => well under 20.
        assertTrue("calls=${calls.get()}", calls.get() in 1..20)
    }

    @Test
    fun negativeInterval_isClamped() {
        `when`(detector.isDeviceRooted()).thenReturn(true)
        val calls = AtomicInteger()
        SecurityWatchdog.threatListener = { calls.incrementAndGet() }
        SecurityWatchdog.start(detector, -500, ProtectionMode.LOG_ONLY)
        Thread.sleep(400)
        assertTrue("calls=${calls.get()}", calls.get() in 1..20)
    }

    // ---------- timing-gap tamper check ----------

    @Test
    fun largeClockJump_isTreatedAsPause() {
        val calls = AtomicInteger()
        SecurityWatchdog.threatListener = { calls.incrementAndGet() }
        SecurityWatchdog.start(detector, 100, ProtectionMode.LOG_ONLY)
        Thread.sleep(150)
        assertEquals(0, calls.get())

        clock.set(100 * 4 + 1_000) // simulated debugger pause
        assertTrue(awaitTrue { calls.get() > 0 })
    }

    @Test
    fun smallClockAdvance_isNotAPause() {
        val calls = AtomicInteger()
        SecurityWatchdog.threatListener = { calls.incrementAndGet() }
        SecurityWatchdog.start(detector, 100, ProtectionMode.LOG_ONLY)
        repeat(10) {
            clock.addAndGet(40)
            Thread.sleep(40)
        }
        assertEquals(0, calls.get())
    }

    @Test
    fun restart_resetsTimingBaseline() {
        val calls = AtomicInteger()
        SecurityWatchdog.threatListener = { calls.incrementAndGet() }
        SecurityWatchdog.start(detector, 100, ProtectionMode.LOG_ONLY)
        SecurityWatchdog.stop()

        clock.set(1_000_000) // long time passes while stopped
        SecurityWatchdog.start(detector, 100, ProtectionMode.LOG_ONLY)
        Thread.sleep(300)
        assertEquals("stale baseline caused false alarm", 0, calls.get())
    }

    // ---------- background / foreground ----------

    @Test
    fun gapWhileBackgrounded_isNotAThreat() {
        val calls = AtomicInteger()
        SecurityWatchdog.threatListener = { calls.incrementAndGet() }
        SecurityWatchdog.start(detector, 100, ProtectionMode.TERMINATE)
        Thread.sleep(150)

        SecurityWatchdog.onAppBackgrounded()
        clock.set(60_000) // process frozen for a minute
        Thread.sleep(400)

        assertEquals(0, calls.get())
        assertEquals(0, terminated.get())
    }

    @Test
    fun firstIterationAfterForeground_ignoresAccumulatedGap() {
        val calls = AtomicInteger()
        SecurityWatchdog.threatListener = { calls.incrementAndGet() }
        SecurityWatchdog.start(detector, 100, ProtectionMode.TERMINATE)
        Thread.sleep(150)

        SecurityWatchdog.onAppBackgrounded()
        clock.set(60_000)
        Thread.sleep(300)
        SecurityWatchdog.onAppForegrounded()
        Thread.sleep(400)

        assertEquals("app was killed when returning from background", 0, terminated.get())
        assertEquals(0, calls.get())
    }

    @Test
    fun gapCheckWorksAgainAfterForegroundGraceIteration() {
        val calls = AtomicInteger()
        SecurityWatchdog.threatListener = { calls.incrementAndGet() }
        SecurityWatchdog.start(detector, 100, ProtectionMode.LOG_ONLY)
        Thread.sleep(150)
        SecurityWatchdog.onAppBackgrounded()
        SecurityWatchdog.onAppForegrounded()
        Thread.sleep(300) // grace iteration consumed

        clock.set(100 * 4 + 1_000)
        assertTrue(awaitTrue { calls.get() > 0 })
    }

    @Test
    fun realThreats_stillDetectedWhileBackgrounded() {
        `when`(detector.isDeviceRooted()).thenReturn(true)
        val calls = AtomicInteger()
        SecurityWatchdog.threatListener = { calls.incrementAndGet() }
        SecurityWatchdog.onAppBackgrounded()
        SecurityWatchdog.start(detector, 100, ProtectionMode.LOG_ONLY)
        assertTrue(awaitTrue { calls.get() > 0 })
    }

    @Test
    fun latch_sanity() {
        // guards the helpers above against silently never waiting
        val l = CountDownLatch(1)
        assertFalse(l.await(10, TimeUnit.MILLISECONDS))
    }
}
