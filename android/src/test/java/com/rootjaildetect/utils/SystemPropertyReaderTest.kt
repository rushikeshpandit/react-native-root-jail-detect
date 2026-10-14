package com.rootjaildetect.utils

import org.junit.Assert.assertNull
import org.junit.Test

class SystemPropertyReaderTest {
    @Test
    fun getProperty_onJvm_returnsNullInsteadOfThrowing() {
        // android.os.SystemProperties is hidden / stubbed; failures must be swallowed.
        assertNull(SystemPropertyReader.getProperty("ro.kernel.qemu"))
    }

    @Test
    fun getProperty_emptyKey_returnsNull() {
        assertNull(SystemPropertyReader.getProperty(""))
    }
}
