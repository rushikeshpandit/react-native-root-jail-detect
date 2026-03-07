#include <jni.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <fstream>
#include <string>
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

    unsigned char *addr = (unsigned char *) symbol;

    /*
     * Inline hook often replaces first instruction with jump
     */
    if (addr[0] == 0xEA || addr[0] == 0xE9) {
        dlclose(handle);
        return JNI_TRUE;
    }

    dlclose(handle);
    return JNI_FALSE;
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