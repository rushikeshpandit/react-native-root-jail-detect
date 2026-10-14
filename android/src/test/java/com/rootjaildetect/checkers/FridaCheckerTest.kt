package com.rootjaildetect.checkers

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.net.ServerSocket

class FridaCheckerTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val servers = mutableListOf<ServerSocket>()

    @After
    fun tearDown() = servers.forEach { it.close() }

    /** A free port that nothing listens on. */
    private fun closedPort(): Int = ServerSocket(0).use { it.localPort }

    private fun openPort(): Int = ServerSocket(0).also { servers += it }.localPort

    private lateinit var proc: File

    private fun checker(
        port: Int = closedPort(),
        gadget: String = File(tmp.root, "no-gadget.so").path,
    ): FridaChecker {
        if (!::proc.isInitialized) proc = tmp.newFolder("proc")
        return FridaChecker(procRoot = proc, port = port, gadgetPath = gadget)
    }

    private fun writeSelf(
        maps: String? = null,
        threadStatus: String? = null,
    ) {
        if (!::proc.isInitialized) proc = tmp.newFolder("proc")
        File(proc, "self").mkdirs()
        if (maps != null) File(proc, "self/maps").writeText(maps)
        if (threadStatus != null) {
            File(proc, "self/task/1").mkdirs()
            File(proc, "self/task/1/status").writeText(threadStatus)
        }
    }

    private fun writeProcess(
        pid: String,
        cmdline: String,
    ) {
        if (!::proc.isInitialized) proc = tmp.newFolder("proc")
        File(proc, pid).mkdirs()
        File(proc, "$pid/cmdline").writeText(cmdline)
    }

    // ---------- positive ----------

    @Test
    fun openPort_isDetected() {
        val c = checker(port = openPort())
        assertTrue(c.getReasons().contains("Frida default port 27042 open"))
        assertTrue(c.isFridaDetected())
    }

    @Test
    fun fridaAgentInMaps_isDetected() {
        writeSelf(maps = "7f00 r-xp /data/local/tmp/re.frida.server/frida-agent-64.so\n")
        assertTrue(checker().getReasons().contains("Frida library detected in process memory"))
    }

    @Test
    fun eachFridaLibraryName_isDetectedInMaps() {
        listOf("frida-agent", "frida-gadget", "frida-server", "re.frida.server").forEach {
            writeSelf(maps = "7f00 r-xp /x/$it.so\n")
            assertTrue(it, checker().getReasons().contains("Frida library detected in process memory"))
        }
    }

    @Test
    fun fridaThread_isDetected() {
        writeSelf(threadStatus = "Name:\tgum-js-loop\nName2:\tFRIDA worker")
        assertTrue(checker().getReasons().contains("Frida thread detected"))
    }

    @Test
    fun gumJsLoopThread_isDetected() {
        writeSelf(threadStatus = "Name:\tgum-js-loop\nState:\tS")
        assertTrue(checker().getReasons().contains("Frida thread detected"))
    }

    @Test
    fun glibThreadNames_alone_areNotFrida() {
        writeSelf(threadStatus = "Name:\tgmain")
        assertFalse(checker().isFridaDetected())
    }

    @Test
    fun gadgetFile_isDetected() {
        val gadget = tmp.newFile("frida-gadget.so")
        assertTrue(checker(gadget = gadget.path).getReasons().contains("Frida gadget library detected"))
    }

    @Test
    fun suspiciousProcesses_areDetected() {
        listOf("frida", "magisk", "xposed").forEachIndexed { i, name ->
            writeProcess("${100 + i}", "/data/local/tmp/$name-server\u0000--flag")
            assertTrue(name, checker().getReasons().contains("Suspicious instrumentation process detected"))
            File(proc, "${100 + i}").deleteRecursively()
        }
    }

    @Test
    fun multipleSignals_areAllReported() {
        writeSelf(maps = "frida-agent", threadStatus = "frida")
        writeProcess("5", "frida-server")
        val reasons = checker(port = openPort(), gadget = tmp.newFile("g.so").path).getReasons()
        assertEquals(5, reasons.size)
    }

    // ---------- negative ----------

    @Test
    fun cleanEnvironment_isNotDetected() {
        writeSelf(maps = "7f00 r-xp /system/lib64/libc.so\n", threadStatus = "Name:\tmain")
        writeProcess("1", "zygote64")
        val c = checker()
        assertFalse(c.isFridaDetected())
        assertTrue(c.getReasons().isEmpty())
    }

    @Test
    fun closedPort_isIgnored() {
        assertFalse(checker(port = closedPort()).getReasons().contains("Frida default port 27042 open"))
    }

    @Test
    fun unreachableHost_isIgnoredWithoutThrowing() {
        val c = FridaChecker(procRoot = tmp.newFolder("p2"), host = "256.256.256.256", port = 1)
        assertFalse(c.isFridaDetected())
    }

    @Test
    fun missingProcRoot_isIgnored() {
        val c =
            FridaChecker(
                procRoot = File(tmp.root, "nonexistent"),
                port = closedPort(),
                gadgetPath = File(tmp.root, "x").path,
            )
        assertFalse(c.isFridaDetected())
    }

    @Test
    fun mapsWithoutFrida_isIgnored() {
        writeSelf(maps = "7f00 r-xp /system/lib64/libart.so\n7f10 r-xp /system/lib64/libc.so\n")
        assertFalse(checker().isFridaDetected())
    }

    @Test
    fun emptyMaps_isIgnored() {
        writeSelf(maps = "")
        assertFalse(checker().isFridaDetected())
    }

    @Test
    fun threadWithoutFrida_isIgnored() {
        writeSelf(threadStatus = "Name:\tRenderThread")
        assertFalse(checker().isFridaDetected())
    }

    @Test
    fun taskDirWithoutStatusFile_isIgnored() {
        writeSelf()
        File(proc, "self/task/9").mkdirs()
        assertFalse(checker().isFridaDetected())
    }

    @Test
    fun missingGadget_isIgnored() {
        assertFalse(checker().getReasons().contains("Frida gadget library detected"))
    }

    @Test
    fun processWithoutCmdline_isIgnored() {
        if (!::proc.isInitialized) proc = tmp.newFolder("proc")
        File(proc, "77").mkdirs()
        assertFalse(checker().isFridaDetected())
    }

    @Test
    fun processWithBenignCmdline_isIgnored() {
        writeProcess("42", "com.example.app")
        assertFalse(checker().isFridaDetected())
    }

    @Test
    fun cmdlineUnreadable_doesNotCrash() {
        if (!::proc.isInitialized) proc = tmp.newFolder("proc")
        // A directory named "cmdline" exists() but readText() throws.
        File(proc, "88/cmdline").mkdirs()
        writeProcess("89", "benign")
        assertFalse(checker().isFridaDetected())
    }

    @Test
    fun cmdlineUnreadable_doesNotMaskLaterMatches() {
        if (!::proc.isInitialized) proc = tmp.newFolder("proc")
        File(proc, "88/cmdline").mkdirs()
        writeProcess("89", "frida-server")
        assertTrue(checker().getReasons().contains("Suspicious instrumentation process detected"))
    }

    @Test
    fun portConstant_isFridaDefault() {
        assertEquals(27042, FridaChecker.FRIDA_DEFAULT_PORT)
    }
}
