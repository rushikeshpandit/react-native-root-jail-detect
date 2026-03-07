package com.rootjaildetect.utils

import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * Utility for executing shell commands.
 */
object CommandExecutor {
    fun execute(command: String): List<String> {
        val process = Runtime.getRuntime().exec(command)

        return BufferedReader(
            InputStreamReader(process.inputStream),
        ).use { reader ->
            reader.readLines()
        }
    }
}
