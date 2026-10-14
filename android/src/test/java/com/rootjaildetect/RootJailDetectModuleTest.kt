package com.rootjaildetect

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.WritableArray
import com.facebook.react.bridge.WritableMap
import com.facebook.react.modules.core.DeviceEventManagerModule
import com.rootjaildetect.watchdog.SecurityWatchdog
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.mockito.ArgumentMatchers.any
import org.mockito.ArgumentMatchers.anyDouble
import org.mockito.ArgumentMatchers.anyString
import org.mockito.ArgumentMatchers.eq
import org.mockito.Mockito.mock
import org.mockito.Mockito.mockStatic
import org.mockito.Mockito.never
import org.mockito.Mockito.verify
import org.mockito.Mockito.`when`
import org.mockito.MockedStatic

// Kotlin-safe matchers: Mockito's eq()/any() return null, which Kotlin rejects for non-null params.
private fun <T> eqK(value: T): T {
    eq(value)
    return value
}

@Suppress("UNCHECKED_CAST")
private fun <T> anyK(): T {
    any<T>()
    return null as T
}

class RootJailDetectModuleTest {
    private lateinit var context: ReactApplicationContext
    private lateinit var detection: RootDetection
    private lateinit var promise: Promise
    private lateinit var module: RootJailDetectModule
    private lateinit var arguments: MockedStatic<Arguments>

    @Before
    fun setUp() {
        SecurityWatchdog.stop()
        context = mock(ReactApplicationContext::class.java)
        detection = mock(RootDetection::class.java)
        promise = mock(Promise::class.java)
        arguments = mockStatic(Arguments::class.java)
        module = RootJailDetectModule(context, detection)
    }

    @After
    fun tearDown() {
        SecurityWatchdog.stop()
        SecurityWatchdog.threatListener = null
        arguments.close()
    }

    private fun options(
        interval: Double? = null,
        mode: String? = null,
        nullInterval: Boolean = false,
        nullMode: Boolean = false,
    ): ReadableMap {
        val m = mock(ReadableMap::class.java)
        `when`(m.hasKey("interval")).thenReturn(interval != null || nullInterval)
        `when`(m.isNull("interval")).thenReturn(nullInterval)
        if (interval != null) `when`(m.getDouble("interval")).thenReturn(interval)
        `when`(m.hasKey("protectionMode")).thenReturn(mode != null || nullMode)
        `when`(m.isNull("protectionMode")).thenReturn(nullMode)
        if (mode != null) `when`(m.getString("protectionMode")).thenReturn(mode)
        return m
    }

    // ---------- module metadata ----------

    @Test
    fun name_isRootJailDetect() {
        assertEquals("RootJailDetect", RootJailDetectModule.NAME)
        assertEquals("RootJailDetect", module.name)
    }

    @Test
    fun threatEventName_isStable() {
        assertEquals("onSecurityThreat", RootJailDetectModule.THREAT_EVENT)
    }

    // ---------- isDeviceCompromised ----------

    @Test
    fun isDeviceCompromised_true() {
        `when`(detection.isDeviceRooted()).thenReturn(true)
        module.isDeviceCompromised(promise)
        verify(promise).resolve(true)
    }

    @Test
    fun isDeviceCompromised_false() {
        `when`(detection.isDeviceRooted()).thenReturn(false)
        module.isDeviceCompromised(promise)
        verify(promise).resolve(false)
    }

    @Test
    fun isDeviceCompromised_error_rejects() {
        val boom = IllegalStateException("kaput")
        `when`(detection.isDeviceRooted()).thenThrow(boom)
        module.isDeviceCompromised(promise)
        verify(promise).reject("ERROR", "Failed to check device security: kaput", boom)
        verify(promise, never()).resolve(anyK<Any?>())
    }

    // ---------- isEmulator ----------

    @Test
    fun isEmulator_true_false() {
        `when`(detection.isEmulator()).thenReturn(true)
        module.isEmulator(promise)
        verify(promise).resolve(true)

        val p2 = mock(Promise::class.java)
        `when`(detection.isEmulator()).thenReturn(false)
        module.isEmulator(p2)
        verify(p2).resolve(false)
    }

    @Test
    fun isEmulator_error_rejects() {
        val boom = RuntimeException("x")
        `when`(detection.isEmulator()).thenThrow(boom)
        module.isEmulator(promise)
        verify(promise).reject("ERROR", "Failed to check emulator status: x", boom)
    }

    // ---------- isDebuggerAttached ----------

    @Test
    fun isDebuggerAttached_true_false() {
        `when`(detection.isDebuggerAttached()).thenReturn(true)
        module.isDebuggerAttached(promise)
        verify(promise).resolve(true)

        val p2 = mock(Promise::class.java)
        `when`(detection.isDebuggerAttached()).thenReturn(false)
        module.isDebuggerAttached(p2)
        verify(p2).resolve(false)
    }

    @Test
    fun isDebuggerAttached_error_rejects() {
        val boom = RuntimeException("y")
        `when`(detection.isDebuggerAttached()).thenThrow(boom)
        module.isDebuggerAttached(promise)
        verify(promise).reject("ERROR", "Failed to check debugger status: y", boom)
    }

    // ---------- getDetectionReasons ----------

    @Test
    fun getDetectionReasons_pushesEveryReason() {
        val array = mock(WritableArray::class.java)
        arguments.`when`<WritableArray> { Arguments.createArray() }.thenReturn(array)
        `when`(detection.getDetectionReasons()).thenReturn(listOf("a", "b"))

        module.getDetectionReasons(promise)

        verify(array).pushString("a")
        verify(array).pushString("b")
        verify(promise).resolve(array)
    }

    @Test
    fun getDetectionReasons_empty_resolvesEmptyArray() {
        val array = mock(WritableArray::class.java)
        arguments.`when`<WritableArray> { Arguments.createArray() }.thenReturn(array)
        `when`(detection.getDetectionReasons()).thenReturn(emptyList())

        module.getDetectionReasons(promise)

        verify(array, never()).pushString(anyString())
        verify(promise).resolve(array)
    }

    @Test
    fun getDetectionReasons_error_rejects() {
        val boom = RuntimeException("z")
        `when`(detection.getDetectionReasons()).thenThrow(boom)
        module.getDetectionReasons(promise)
        verify(promise).reject("ERROR", "Failed to get detection reasons", boom)
    }

    // ---------- watchdog ----------

    @Test
    fun startSecurityWatchdog_startsRunning() {
        module.startSecurityWatchdog(options(interval = 5000.0, mode = "LOG_ONLY"))
        assertTrue(SecurityWatchdog.isRunning)
    }

    @Test
    fun startSecurityWatchdog_emptyOptions_usesDefaults() {
        module.startSecurityWatchdog(options())
        assertTrue(SecurityWatchdog.isRunning)
    }

    @Test
    fun startSecurityWatchdog_nullValues_usesDefaults() {
        module.startSecurityWatchdog(options(nullInterval = true, nullMode = true))
        assertTrue(SecurityWatchdog.isRunning)
    }

    @Test
    fun startSecurityWatchdog_unknownMode_fallsBackToLogOnly() {
        // If this mapped to TERMINATE the test process itself would be at risk; the seam keeps it safe.
        var terminated = false
        SecurityWatchdog.terminateProcess = { terminated = true }
        `when`(detection.isDeviceRooted()).thenReturn(true)
        module.startSecurityWatchdog(options(interval = 100.0, mode = "NOT_A_MODE"))
        Thread.sleep(300)
        assertFalse(terminated)
    }

    @Test
    fun startSecurityWatchdog_terminateMode_isMapped() {
        val terminated = java.util.concurrent.atomic.AtomicBoolean(false)
        SecurityWatchdog.terminateProcess = { terminated.set(true) }
        `when`(detection.isDeviceRooted()).thenReturn(true)
        module.startSecurityWatchdog(options(interval = 100.0, mode = "TERMINATE"))
        val end = System.currentTimeMillis() + 3000
        while (!terminated.get() && System.currentTimeMillis() < end) Thread.sleep(10)
        assertTrue(terminated.get())
    }

    @Test
    fun startSecurityWatchdog_acceptsFractionalInterval() {
        // JS numbers arrive as doubles; getInt() would have thrown here.
        module.startSecurityWatchdog(options(interval = 1500.7, mode = "LOG_ONLY"))
        assertTrue(SecurityWatchdog.isRunning)
    }

    @Test
    fun stopSecurityWatchdog_stops() {
        module.startSecurityWatchdog(options())
        module.stopSecurityWatchdog()
        assertFalse(SecurityWatchdog.isRunning)
    }

    @Test
    fun stopSecurityWatchdog_whenNotRunning_isHarmless() {
        module.stopSecurityWatchdog()
        assertFalse(SecurityWatchdog.isRunning)
    }

    @Test
    fun isSecurityWatchdogRunning_reflectsState() {
        module.isSecurityWatchdogRunning(promise)
        verify(promise).resolve(false)

        module.startSecurityWatchdog(options())
        val p2 = mock(Promise::class.java)
        module.isSecurityWatchdogRunning(p2)
        verify(p2).resolve(true)
    }

    // ---------- events ----------

    // mockStatic is thread-local, so the watchdog thread cannot see the mocked Arguments;
    // the module's listener is therefore invoked directly on the test thread.
    @Test
    fun threat_isEmittedToJs() {
        val array = mock(WritableArray::class.java)
        val map = mock(WritableMap::class.java)
        arguments.`when`<WritableArray> { Arguments.createArray() }.thenReturn(array)
        arguments.`when`<WritableMap> { Arguments.createMap() }.thenReturn(map)
        val emitter = mock(DeviceEventManagerModule.RCTDeviceEventEmitter::class.java)
        `when`(context.hasActiveReactInstance()).thenReturn(true)
        `when`(context.getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter::class.java))
            .thenReturn(emitter)

        module.startSecurityWatchdog(options(interval = 60000.0, mode = "LOG_ONLY"))
        SecurityWatchdog.threatListener!!.invoke(listOf("su", "magisk"))

        verify(array).pushString("su")
        verify(array).pushString("magisk")
        verify(map).putArray("reasons", array)
        verify(map).putDouble(eqK("timestamp"), anyDouble())
        verify(emitter).emit("onSecurityThreat", map)
    }

    @Test
    fun threat_withoutActiveReactInstance_isNotEmitted() {
        val emitter = mock(DeviceEventManagerModule.RCTDeviceEventEmitter::class.java)
        `when`(context.hasActiveReactInstance()).thenReturn(false)
        `when`(context.getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter::class.java))
            .thenReturn(emitter)

        module.startSecurityWatchdog(options(interval = 60000.0, mode = "LOG_ONLY"))
        SecurityWatchdog.threatListener!!.invoke(listOf("su"))

        verify(emitter, never()).emit(anyK(), anyK())
    }

    @Test
    fun threat_emptyReasons_stillEmitsEmptyArray() {
        val array = mock(WritableArray::class.java)
        val map = mock(WritableMap::class.java)
        arguments.`when`<WritableArray> { Arguments.createArray() }.thenReturn(array)
        arguments.`when`<WritableMap> { Arguments.createMap() }.thenReturn(map)
        val emitter = mock(DeviceEventManagerModule.RCTDeviceEventEmitter::class.java)
        `when`(context.hasActiveReactInstance()).thenReturn(true)
        `when`(context.getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter::class.java))
            .thenReturn(emitter)

        module.startSecurityWatchdog(options(interval = 60000.0, mode = "LOG_ONLY"))
        SecurityWatchdog.threatListener!!.invoke(emptyList())

        verify(array, never()).pushString(anyK())
        verify(emitter).emit("onSecurityThreat", map)
    }

    @Test
    fun module_registersAsLifecycleListener() {
        verify(context).addLifecycleEventListener(module)
    }

    @Test
    fun lifecycle_backgroundSuspendsGapCheck_resumeRestoresIt() {
        var terminated = false
        SecurityWatchdog.terminateProcess = { terminated = true }
        var now = 0L
        SecurityWatchdog.uptimeMillis = { now }
        module.startSecurityWatchdog(options(interval = 100.0, mode = "TERMINATE"))
        Thread.sleep(150)

        module.onHostPause()
        now = 120_000
        Thread.sleep(300)
        module.onHostResume()
        Thread.sleep(300)
        module.onHostDestroy()

        assertFalse(terminated)
    }

    @Test
    fun addAndRemoveListeners_areNoOps() {
        module.addListener("onSecurityThreat")
        module.removeListeners(1.0)
    }
}
