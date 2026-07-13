#include <jni.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fstream>
#include <string>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <errno.h>


// Reads TracerPid from /proc/self/status.
// Returns 0 if not traced, >0 if a debugger is attached, -1 on error.
static int getTracerPid() {
    std::ifstream status("/proc/self/status");
    if (!status.is_open()) return -1;

    std::string line;
    while (std::getline(status, line)) {
        if (line.rfind("TracerPid:", 0) == 0) {
            try {
                return std::stoi(line.substr(10));
            } catch (...) {
                return -1;
            }
        }
    }
    return -1;
}

/**
 * ptrace anti-debug detection
 *
 * If ptrace fails it means another debugger
 * already attached to the process.
 */
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_rootjaildetect_checkers_NativeSecurityChecker_detectPtrace(
        JNIEnv *env,
        jobject thiz) {

    // Primary check: /proc/self/status TracerPid
    // A non-zero TracerPid reliably means a debugger is attached.
    int tracerPid = getTracerPid();
    if (tracerPid > 0) {
        return JNI_TRUE;
    }

    // Secondary check: ptrace TRACEME
    // Only treat EPERM as a definitive "already being traced" signal.
    // Other errno values (ENOSYS, EPERM from SELinux) are ambiguous — skip them.
    errno = 0;
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        if (errno == EPERM) {
            // Confirm with TracerPid before flagging, to avoid SELinux false positives
            return (tracerPid > 0) ? JNI_TRUE : JNI_FALSE;
        }
        // Other errors (ENOSYS etc.) = not debugger-related
        return JNI_FALSE;
    }

    // Successfully attached to self — no debugger present. Clean up.
    ptrace(PTRACE_DETACH, 0, NULL, NULL);
    return JNI_FALSE;
}

/**
 * Detect Frida using native techniques
 *
 * Methods used:
 * - scan /proc/self/maps
 * - scan loaded libraries
 */
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_rootjaildetect_checkers_NativeSecurityChecker_detectFridaNative(
        JNIEnv *env,
        jobject thiz) {

    std::ifstream maps("/proc/self/maps");
    std::string line;

    while (std::getline(maps, line)) {

        if (line.find("frida") != std::string::npos ||
            line.find("gum-js-loop") != std::string::npos ||
            line.find("gmain") != std::string::npos ||
            line.find("linjector") != std::string::npos) {

            return JNI_TRUE;
        }
    }

    return JNI_FALSE;
}

// Returns the memory protection flags (PROT_* bitmask) of the mapping that
// contains `addr`, or -1 if it cannot be determined. Parsed from the perms
// column of /proc/self/maps (e.g. "r-xp").
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

/*
 * Detect inline hooks inside libc
 * Used by Frida and Xposed
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
    // Unconditional branch: B <imm26>, opcode bits [31:26] == 0b000101.
    if ((insn & 0xFC000000u) == 0x14000000u) hooked = true;
    // Absolute-jump trampoline: LDR X16/X17, <literal> (0x58...) followed by
    // BR — a very common Frida/Xposed prologue shape.
    if ((insn & 0xFF000000u) == 0x58000000u &&
        ((insn & 0x1Fu) == 16u || (insn & 0x1Fu) == 17u)) {
        hooked = true;
    }
#elif defined(__arm__)
    // ARM (32-bit): the first instruction becomes an unconditional B (0xEA)
    // or BL (0xEB). A32 instructions are stored little-endian, so the
    // condition/opcode byte is code[3]; code[0] is the low immediate byte.
    if (code[3] == 0xEA || code[3] == 0xEB) hooked = true;
#endif

    dlclose(handle);
    return hooked ? JNI_TRUE : JNI_FALSE;
}

/*
 * Detect Frida using syscall behaviour
 */
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_rootjaildetect_checkers_NativeSecurityChecker_detectFridaSyscall(
        JNIEnv *env,
        jobject thiz) {

    FILE *fp = fopen("/proc/self/status", "r");

    if (!fp) return JNI_FALSE;

    char line[256];

    while (fgets(line, sizeof(line), fp)) {

        if (strstr(line, "TracerPid")) {

            int tracer = atoi(line + 10);

            if (tracer != 0) {
                fclose(fp);
                return JNI_TRUE;
            }
        }
    }

    fclose(fp);
    return JNI_FALSE;
}