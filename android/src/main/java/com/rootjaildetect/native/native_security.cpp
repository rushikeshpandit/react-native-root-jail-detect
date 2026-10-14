#include <jni.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fstream>
#include <string>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>

#include "scan_utils.h"


// Reads TracerPid from /proc/self/status.
// Returns 0 if not traced, >0 if a debugger is attached, -1 on error.
/**
 * Reads the `TracerPid` field of `/proc/self/status`.
 *
 * @return The tracer's pid (0 when not traced, greater than 0 when a debugger is attached), or
 *     -1 if the file cannot be read or the field is missing/malformed.
 */
static int getTracerPid() {
    std::ifstream status("/proc/self/status");
    if (!status.is_open()) return -1;

    std::string line;
    while (std::getline(status, line)) {
        int pid = rjd::parseTracerPid(line);
        if (pid != -1 || line.rfind("TracerPid:", 0) == 0) return pid;
    }
    return -1;
}

/**
 * JNI: reports whether another process is ptrace-attached to this one. Reads `TracerPid` only
 * and deliberately avoids `ptrace(PTRACE_TRACEME)`, whose side effect cannot be undone and
 * would make later calls report a debugger.
 *
 * @param env JNI environment (unused).
 * @param thiz The `NativeSecurityChecker` instance (unused).
 * @return `JNI_TRUE` if `TracerPid` is greater than 0, otherwise `JNI_FALSE`.
 */
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_rootjaildetect_checkers_NativeSecurityChecker_detectPtrace(
        JNIEnv *env,
        jobject thiz) {

    return getTracerPid() > 0 ? JNI_TRUE : JNI_FALSE;
}

/**
 * JNI: scans `/proc/self/maps` through libc for Frida markers (`frida`, `gum-js-loop`,
 * `linjector`).
 *
 * @param env JNI environment (unused).
 * @param thiz The `NativeSecurityChecker` instance (unused).
 * @return `JNI_TRUE` if a marker is found, otherwise `JNI_FALSE`.
 */
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_rootjaildetect_checkers_NativeSecurityChecker_detectFridaNative(
        JNIEnv *env,
        jobject thiz) {

    std::ifstream maps("/proc/self/maps");
    std::string line;

    while (std::getline(maps, line)) {
        if (rjd::containsFridaMarker(line)) {
            return JNI_TRUE;
        }
    }

    return JNI_FALSE;
}

// Returns the memory protection flags (PROT_* bitmask) of the mapping that
// contains `addr`, or -1 if it cannot be determined. Parsed from the perms
// column of /proc/self/maps (e.g. "r-xp").
/**
 * Looks up the memory protection of the mapping containing an address by parsing the permission
 * column of `/proc/self/maps`.
 *
 * @param addr Address to look up.
 * @return A `PROT_*` bit mask, or -1 if the mapping cannot be found.
 */
static int getPageProtection(uintptr_t addr) {
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return -1;

    std::string line;
    while (std::getline(maps, line)) {
        unsigned long start = 0, end = 0;
        char perms[5] = {0};
        // Format: "start-end perms offset dev inode pathname"
        if (std::sscanf(line.c_str(), "%lx-%lx %4s", &start, &end, perms) != 3) {
            continue;
        }
        if (addr >= start && addr < end) {
            int prot = 0;
            if (perms[0] == 'r') prot |= PROT_READ;
            if (perms[1] == 'w') prot |= PROT_WRITE;
            if (perms[2] == 'x') prot |= PROT_EXEC;
            return prot;
        }
    }
    return -1;
}

// Safely copies `len` bytes from `src` into `dst`, temporarily adding read
// permission when the source page is not readable.
//
// On Android 10 (arm64) the .text of system libraries such as libc is mapped
// execute-only (XOM). Reading it directly raises SIGSEGV (SEGV_ACCERR:
// "execute-only (no-read) memory access error; likely due to data in .text"),
// which is an uncatchable native signal that crashes the whole process. XOM
// was enabled by default in Android 10 only and removed again in Android 11.
//
// The page is remapped read+execute only when it is genuinely non-readable,
// then restored to its original protection so the OS hardening is not
// permanently weakened. On Android 11+ (already readable) no protection change
// is made. Returns false — rather than risking a crash — whenever the page
// cannot be confirmed readable.
/**
 * Copies bytes out of code memory without crashing. Android 10 maps libc execute-only, so
 * reading it raises SIGSEGV; the page is temporarily made readable and its original protection
 * restored afterwards.
 *
 * @param src Source address (possibly execute-only).
 * @param dst Destination buffer.
 * @param len Number of bytes to copy.
 * @return `true` if the bytes were copied, `false` if the page could not be confirmed readable.
 */
static bool safeRead(const void *src, void *dst, size_t len) {
    uintptr_t addr = reinterpret_cast<uintptr_t>(src);
    long pageSize = sysconf(_SC_PAGESIZE);
    if (pageSize <= 0) pageSize = 4096;
    uintptr_t mask = static_cast<uintptr_t>(pageSize) - 1;
    uintptr_t pageStart = addr & ~mask;
    size_t span = (addr + len) - pageStart;
    void *page = reinterpret_cast<void *>(pageStart);

    int origProt = getPageProtection(addr);
    if (origProt == -1) return false;

    bool remapped = false;
    if (!(origProt & PROT_READ)) {
        if (mprotect(page, span, origProt | PROT_READ) != 0) return false;
        remapped = true;
    }

    std::memcpy(dst, src, len);

    if (remapped) mprotect(page, span, origProt);
    return true;
}

/**
 * JNI: reads the first instruction of libc `open` and checks for an inline-hook trampoline
 * (arm64: `B` or `LDR X16/X17`; arm32: `B`/`BL`; Thumb functions are skipped).
 *
 * @param env JNI environment (unused).
 * @param thiz The `NativeSecurityChecker` instance (unused).
 * @return `JNI_TRUE` if the prologue looks patched, otherwise `JNI_FALSE` (also when libc or
 *     the symbol cannot be loaded or read).
 */
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_rootjaildetect_checkers_NativeSecurityChecker_detectInlineHook(
        JNIEnv *env,
        jobject thiz) {

    void *handle = dlopen("libc.so", RTLD_NOW);
    if (!handle) return JNI_FALSE;

    void *symbol = dlsym(handle, "open");

    if (!symbol) {
        dlclose(handle);
        return JNI_FALSE;
    }

#if defined(__arm__)
    // bionic on 32-bit ARM is built as Thumb-2, so dlsym returns Thumb
    // symbols with bit 0 set. The A32 branch patterns below don't apply to
    // Thumb encodings — treat those as not hooked instead of misreading
    // misaligned bytes.
    if (reinterpret_cast<uintptr_t>(symbol) & 1u) {
        dlclose(handle);
        return JNI_FALSE;
    }
#endif

    // Read the function prologue safely — dereferencing execute-only .text
    // directly would crash on Android 10 arm64 (see safeRead).
    unsigned char code[4] = {0};
    if (!safeRead(symbol, code, sizeof(code))) {
        dlclose(handle);
        return JNI_FALSE;
    }

    // An inline hook replaces the prologue with a branch to the trampoline.
    // The signature is architecture specific: the previous code only tested
    // ARM (32-bit) branch opcodes, so it never matched — and could false
    // positive — on the arm64 ABI that ships today.
    bool hooked = false;
#if defined(__aarch64__)
    uint32_t insn = static_cast<uint32_t>(code[0]) |
                    (static_cast<uint32_t>(code[1]) << 8) |
                    (static_cast<uint32_t>(code[2]) << 16) |
                    (static_cast<uint32_t>(code[3]) << 24);
    // Unconditional B, or the LDR X16/X17 + BR absolute-jump trampoline that
    // Frida/Xposed commonly write over a prologue.
    hooked = rjd::isArm64HookPrologue(insn);
#elif defined(__arm__)
    // ARM (32-bit): the first instruction becomes an unconditional B (0xEA)
    // or BL (0xEB). A32 instructions are stored little-endian, so the
    // condition/opcode byte is code[3]; code[0] is the low immediate byte.
    if (code[3] == 0xEA || code[3] == 0xEB) hooked = true;
#endif

    dlclose(handle);
    return hooked ? JNI_TRUE : JNI_FALSE;
}

/**
 * JNI: scans `/proc/self/maps` using raw `openat`/`read` syscalls in 4 KiB chunks (with an
 * overlap so markers split across chunks are found). Because libc is bypassed, it still sees
 * Frida when libc `open`/`read` are hooked to hide it.
 *
 * @param env JNI environment (unused).
 * @param thiz The `NativeSecurityChecker` instance (unused).
 * @return `JNI_TRUE` if a Frida marker is found, otherwise `JNI_FALSE`.
 */
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_rootjaildetect_checkers_NativeSecurityChecker_detectFridaSyscall(
        JNIEnv *env,
        jobject thiz) {

    long fd = syscall(__NR_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return JNI_FALSE;

    // Read in chunks and keep a tail so a marker split across two reads is still found.
    const size_t kChunk = 4096;
    const size_t kOverlap = 32;
    char buf[kChunk];
    std::string window;
    bool found = false;

    while (!found) {
        long n = syscall(__NR_read, static_cast<int>(fd), buf, kChunk);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;

        window.append(buf, static_cast<size_t>(n));
        if (rjd::containsFridaMarker(window)) {
            found = true;
            break;
        }
        if (window.size() > kOverlap) {
            window.erase(0, window.size() - kOverlap);
        }
    }

    syscall(__NR_close, static_cast<int>(fd));
    return found ? JNI_TRUE : JNI_FALSE;
}
