// Host-side unit tests for scan_utils.h. Run with: yarn test:native
#include <cstdio>
#include <cstdlib>
#include <string>

#include "../../main/java/com/rootjaildetect/native/scan_utils.h"

static int failures = 0;
#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);  \
            failures++;                                                  \
        }                                                                \
    } while (0)

int main() {
    using namespace rjd;

    // containsFridaMarker: positive
    CHECK(containsFridaMarker("7f00-7f10 r-xp /data/local/tmp/re.frida.server/frida-agent-64.so"));
    CHECK(containsFridaMarker("7f00 rw-p [anon:gum-js-loop]"));
    CHECK(containsFridaMarker("/data/local/tmp/linjector.so"));
    CHECK(containsFridaMarker("multi\nline\nfrida-gadget.so\n"));
    // negative
    CHECK(!containsFridaMarker(""));
    CHECK(!containsFridaMarker("7f00-7f10 r-xp /system/lib64/libc.so"));
    CHECK(!containsFridaMarker("/usr/lib/libgmain-glib.so"));  // GLib thread name, not Frida
    CHECK(!containsFridaMarker("FRIDA"));                      // case-sensitive on purpose

    // parseTracerPid: positive
    CHECK(parseTracerPid("TracerPid:\t0") == 0);
    CHECK(parseTracerPid("TracerPid:\t1234") == 1234);
    CHECK(parseTracerPid("TracerPid:   42") == 42);
    // negative
    CHECK(parseTracerPid("Name:\tapp") == -1);
    CHECK(parseTracerPid("TracerPid:") == -1);
    CHECK(parseTracerPid("TracerPid:\tabc") == -1);
    CHECK(parseTracerPid("") == -1);
    CHECK(parseTracerPid("  TracerPid:\t5") == -1);

    // isArm64HookPrologue: positive
    CHECK(isArm64HookPrologue(0x14000010u));  // B +0x40
    CHECK(isArm64HookPrologue(0x17FFFFFFu));  // B -4
    CHECK(isArm64HookPrologue(0x58000050u));  // LDR X16, #8
    CHECK(isArm64HookPrologue(0x58000051u));  // LDR X17, #8
    // negative
    CHECK(!isArm64HookPrologue(0xD503201Fu));  // NOP
    CHECK(!isArm64HookPrologue(0xD65F03C0u));  // RET
    CHECK(!isArm64HookPrologue(0x94000010u));  // BL (call, not a prologue patch)
    CHECK(!isArm64HookPrologue(0x58000040u));  // LDR X0 (not x16/x17)
    CHECK(!isArm64HookPrologue(0xA9BF7BFDu));  // STP x29,x30,[sp,#-16]!
    CHECK(!isArm64HookPrologue(0u));

    if (failures == 0) std::printf("native tests passed\n");
    return failures == 0 ? 0 : 1;
}
