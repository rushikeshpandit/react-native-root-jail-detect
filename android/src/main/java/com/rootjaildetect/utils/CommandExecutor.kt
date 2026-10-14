package com.rootjaildetect.utils

import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * Runs shell commands and captures their output.
 */
object CommandExecutor {
    /**
     * Runs a command, reads all of its stdout and then destroys the child process.
     *
     * @param command Command line to execute (split on whitespace by `Runtime.exec`).
     * @return Output lines. Throws `IOException` if the command cannot be started.
     */
    fun execute(command: String): List<String> {
        val process = Runtime.getRuntime().exec(command)

        return try {
            BufferedReader(
                InputStreamReader(process.inputStream),
            ).use { reader ->
                reader.readLines()
            }
        } finally {
            process.destroy()
        }
    }
}
