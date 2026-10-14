// Pure helpers used by native_security.cpp. They have no Android dependencies so they can be
// unit-tested on the host (see android/src/test/cpp/scan_utils_test.cpp).
#pragma once

#include <cstdint>
#include <cstdlib>
#include <string>

namespace rjd {

// Markers that identify Frida in /proc/self/maps. Thread names such as "gmain" never appear
// in maps (only in /proc/self/task/<tid>/comm) and would false-positive on any GLib library
// path, so they are intentionally not included here.
/**
 * Tests text from `/proc/self/maps` for Frida markers. The match is case-sensitive; thread
 * names such as `gmain` are excluded because they never appear in maps and would
 * false-positive.
 *
 * @param text Text to search.
 * @return `true` if it contains `frida`, `gum-js-loop` or `linjector`.
 */
inline bool containsFridaMarker(const std::string &text) {
    return text.find("frida") != std::string::npos ||
           text.find("gum-js-loop") != std::string::npos ||
           text.find("linjector") != std::string::npos;
}

// Parses a "TracerPid:\t<n>" line. Returns -1 if the line is not a TracerPid line or the value
// is not a number.
/**
 * Parses one line of `/proc/self/status`.
 *
 * @param line A single line, for example `TracerPid:\t0`.
 * @return The pid, or -1 if the line is not a `TracerPid:` line or the value is not numeric.
 */
inline int parseTracerPid(const std::string &line) {
    static const std::string key = "TracerPid:";
    if (line.compare(0, key.size(), key) != 0) return -1;
    const char *start = line.c_str() + key.size();
    char *end = nullptr;
    long value = std::strtol(start, &end, 10);
    if (end == start) return -1;
    return static_cast<int>(value);
}

// True if an arm64 instruction looks like an inline-hook trampoline written over a function
// prologue: an unconditional B, or LDR X16/X17 (literal) used for absolute jumps.
/**
 * Recognises the instructions hooking engines write over a function prologue.
 *
 * @param insn First arm64 instruction word of the function.
 * @return `true` for an unconditional `B` or for `LDR X16/X17, <literal>`; `false` for
 *     everything else (including `BL`).
 */
inline bool isArm64HookPrologue(uint32_t insn) {
    if ((insn & 0xFC000000u) == 0x14000000u) return true;  // B <imm26>
    if ((insn & 0xFF000000u) == 0x58000000u &&
        ((insn & 0x1Fu) == 16u || (insn & 0x1Fu) == 17u)) {
        return true;  // LDR X16/X17, <literal>
    }
    return false;
}

}  // namespace rjd
