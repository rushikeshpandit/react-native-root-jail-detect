# React Native Root/Jail Detect

[![npm version](https://img.shields.io/npm/v/react-native-root-jail-detect.svg)](https://www.npmjs.com/package/react-native-root-jail-detect)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/rushikeshpandit/react-native-root-jail-detect/pulls)

A React Native security module that detects **rooted Android devices**, **jailbroken iOS
devices**, **runtime instrumentation (Frida, Xposed, Substrate)**, **debuggers** and
**emulators / simulators**, and can keep watching for them while the app runs.

Written in TypeScript, Kotlin (+ a small C++ library) and Swift. It has no third-party
dependencies.

> **Client-side checks can be bypassed.** Treat the result as one signal in a layered
> security strategy, not as proof. See [Important notes](#important-notes).

------------------------------------------------------------------------

## Table of contents

- [Features](#features)
- [Installation](#installation)
- [Quick start](#quick-start)
- [API reference](#api-reference)
- [Runtime security watchdog](#runtime-security-watchdog)
- [What is checked](#what-is-checked)
- [Behaviour you should know about](#behaviour-you-should-know-about)
- [Testing](#testing)
- [Example screenshots](#example-screenshots)
- [Important notes](#important-notes)
- [Contributing](#contributing)
- [License](#license)

------------------------------------------------------------------------

## Features

- Root (Android) and jailbreak (iOS) detection
- Frida, Xposed, Substrate / fishhook, inline-hook and DYLD-injection detection
- Debugger detection
- Emulator / simulator detection
- Human-readable detection reasons
- Runtime watchdog with three protection modes and a JavaScript threat event
- TurboModule on Android (codegen spec); the iOS module is loaded through the React Native
  interop layer
- Fully typed API (named exports and a default export)

------------------------------------------------------------------------

## Installation

```bash
npm install react-native-root-jail-detect
# or
yarn add react-native-root-jail-detect
```

**iOS**

```bash
cd ios && pod install
```

**Android** – nothing to do, autolinking picks the module up. The package ships a native
library (`librootjaildetect.so`, 16 KB page-size aligned) that is built with CMake/NDK as
part of your normal Gradle build.

Requirements: built for the React Native New Architecture (the Android module is a
codegen TurboModule); Android `minSdkVersion` 24.

------------------------------------------------------------------------

## Quick start

```typescript
import {
  isDeviceCompromised,
  getDetectionReasons,
} from 'react-native-root-jail-detect';

const compromised = await isDeviceCompromised();

if (compromised) {
  const reasons = await getDetectionReasons();
  console.warn('Device is rooted/jailbroken', reasons);
}
```

Every function is also available on the default export:

```typescript
import RootJailDetect from 'react-native-root-jail-detect';

await RootJailDetect.isDeviceCompromised();
```

------------------------------------------------------------------------

## API reference

### `isDeviceCompromised(): Promise<boolean>`

Resolves `true` when the device is rooted / jailbroken or instrumented (Frida, Xposed,
hooks, tracer, DYLD injection). Emulators/simulators and attached debuggers **do not** make
it return `true` on their own.

**Rejects** (after logging with `console.error`) if the native check itself fails. This is
the only detection function that rejects.

### `isEmulator(): Promise<boolean>`

Resolves `true` on an Android emulator or an iOS simulator. Resolves `false` on a real
device, on unsupported platforms, if the native method is missing, or if the native call
throws (the error is logged). Never rejects.

### `isDebuggerAttached(): Promise<boolean>`

Resolves `true` while a debugger is attached. On **iOS debug builds the check is disabled**
(Xcode always attaches a debugger) and returns `false`. Never rejects.

### `getDetectionReasons(): Promise<string[]>`

Resolves the human-readable reasons from every checker, de-duplicated, for example:

```json
["Magisk detected", "Frida default port 27042 open", "Debugger is connected"]
```

The list also contains emulator/simulator and debugger findings, so it can be non-empty even
when `isDeviceCompromised()` is `false`. Resolves `[]` when nothing was found or the call
fails.

### `startSecurityWatchdog(options?): void`

Starts the [runtime watchdog](#runtime-security-watchdog).

| Option           | Type             | Default      | Description                                  |
| ---------------- | ---------------- | ------------ | -------------------------------------------- |
| `interval`       | `number` (ms)    | `3000`       | Time between checks (native minimum 100 ms)  |
| `protectionMode` | `ProtectionMode` | `'LOG_ONLY'` | What to do when a threat is found            |

Calling it while the watchdog already runs is a no-op: the running configuration is kept.

### `stopSecurityWatchdog(): void`

Stops the watchdog. Safe to call when it is not running.

### `isSecurityWatchdogRunning(): Promise<boolean>`

Resolves `true` while the watchdog loop is active. Never rejects.

### `addSecurityThreatListener(listener): { remove(): void }`

Subscribes to threats found by the watchdog.

```typescript
const subscription = addSecurityThreatListener(({ reasons, timestamp }) => {
  reportToBackend(reasons, new Date(timestamp));
});

// later
subscription.remove();
```

The listener receives a `SecurityThreatEvent`:

| Field       | Type       | Description                          |
| ----------- | ---------- | ------------------------------------ |
| `reasons`   | `string[]` | Why the watchdog flagged the device  |
| `timestamp` | `number`   | Detection time, epoch milliseconds   |

Throws a `TypeError` if `listener` is not a function.

### Types and enums

```typescript
enum ProtectionMode {
  LOG_ONLY = 'LOG_ONLY',
  THROW_EXCEPTION = 'THROW_EXCEPTION',
  TERMINATE = 'TERMINATE',
}

interface SecurityWatchdogOptions {
  interval?: number;
  protectionMode?: ProtectionMode;
}

interface SecurityThreatEvent {
  reasons: string[];
  timestamp: number;
}

interface SecurityThreatSubscription {
  remove(): void;
}
```

------------------------------------------------------------------------

## Runtime security watchdog

A device can look clean at launch and be compromised later (a debugger attaches, Frida is
started). The watchdog keeps checking in a background thread:

1. every `interval` ±40 % (the jitter makes the timing harder to predict) it re-runs the
   root/jailbreak/instrumentation checks and the debugger check;
2. it also treats a **gap of more than 4× the interval between two iterations** as a
   debugger pause (breakpoints stall the loop);
3. on a threat it calls your listeners first, then applies the protection mode.

```typescript
import {
  startSecurityWatchdog,
  stopSecurityWatchdog,
  addSecurityThreatListener,
  ProtectionMode,
} from 'react-native-root-jail-detect';

const subscription = addSecurityThreatListener(({ reasons }) => {
  console.warn('Threat detected', reasons);
});

startSecurityWatchdog({
  interval: 5000,
  protectionMode: ProtectionMode.LOG_ONLY,
});

// when you no longer need it
stopSecurityWatchdog();
subscription.remove();
```

### Protection modes

| Mode              | What happens on a threat                                                        |
| ----------------- | ------------------------------------------------------------------------------- |
| `LOG_ONLY`        | Writes to the native log (Android Logcat / iOS `NSLog`). The app keeps running. |
| `THROW_EXCEPTION` | Crashes the app: an uncaught `RuntimeException` on the Android main thread, a `fatalError` on iOS. |
| `TERMINATE`       | Kills the process immediately (`killProcess` / `SIGKILL`).                      |

With `TERMINATE` the process can die before JavaScript receives the threat event. Use
`LOG_ONLY` plus your own reaction if you need to report the incident.

------------------------------------------------------------------------

## What is checked

### Android

| Area               | Techniques                                                                                                  |
| ------------------ | ----------------------------------------------------------------------------------------------------------- |
| Root               | `su` binary in known directories, root-management apps (SuperSU, Magisk, KingRoot, …), `test-keys` build tag, `which su`, dangerous properties (`ro.debuggable=1`, `ro.secure=0`, `service.adb.root=1`), writable `/system`, root-cloaking files, Magisk, KernelSU, Zygisk |
| Frida              | Default port 27042, Frida libraries in `/proc/self/maps`, `frida` / `gum-js-loop` thread names, frida-gadget file, suspicious processes, native maps scan, **raw-syscall maps scan** (sees Frida even when libc `open`/`read` are hooked) |
| Hooks              | Xposed bridge class, `xposed`/`frida` frames in the stack trace, inline-hook trampoline at the start of libc `open` (arm64 and arm32) |
| Debugger           | Java debugger connected, waiting-for-debugger, non-zero `TracerPid` (Java and native)                       |
| Emulator           | `generic` build strings, QEMU device files, emulator system properties                                      |

### iOS

| Area               | Techniques                                                                                                  |
| ------------------ | ----------------------------------------------------------------------------------------------------------- |
| Jailbreak          | Known jailbreak files (Cydia, Sileo, Zebra, palera1n, Dopamine, TrollStore, …), writable `/private`, jailbreak URL schemes, restricted paths. File checks are skipped on the simulator |
| Frida              | Loaded `frida` libraries, Frida/Gum threads, exported Frida symbols, Frida directories, default port 27042 (non-blocking, 100 ms timeout), Frida in loaded images |
| Hooks              | `MSHookFunction` / `fishhook` symbols, redirected `malloc`, inline hook on `open` (branch that leaves its image), Objective-C method swizzling, Mach-O header integrity |
| Injection          | `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`, `DYLD_FRAMEWORK_PATH` (skipped in debug builds)               |
| Debugger           | `P_TRACED` flag via `sysctl`, Mach breakpoint exception port (both skipped in debug builds)                 |
| Simulator          | Simulator build flag, `SIMULATOR_DEVICE_NAME` environment variable                                          |

------------------------------------------------------------------------

## Behaviour you should know about

- **Backgrounding is not a threat.** While the app is in the background the process can be
  suspended or frozen for far longer than the watchdog's pause threshold. The pause check is
  suspended in the background and skipped for one iteration after the app returns, so
  `TERMINATE` mode does not kill the app when the user comes back to it. Real threats
  (root, Frida, debugger) are still detected in the background.
- **Debug builds on iOS** skip debugger and DYLD checks, because Xcode sets those up itself.
- **Emulators / simulators** are reported by `isEmulator()` and `getDetectionReasons()` but
  never trigger the watchdog and do not affect `isDeviceCompromised()`.
- **`ro.debuggable=1` counts as rooted**: a device where `adb` can run as root is treated as
  compromised, so `userdebug` builds are flagged.
- **Fail-safe natives.** The native layer never crashes the app because of a probe: unreadable
  `/proc` entries are skipped, execute-only memory (Android 10) is read safely, and shell
  commands that fail count as "no finding".
- **Minimum interval.** Watchdog intervals below 100 ms are raised to 100 ms.

------------------------------------------------------------------------

## Testing

| What                         | Command                                              |
| ---------------------------- | ---------------------------------------------------- |
| JavaScript / TypeScript      | `npm test` (Jest), `npm run typecheck`, `npm run lint` |
| Android (Kotlin, JUnit)      | `npm run test:android`                               |
| Android native helpers (C++) | `npm run test:native`                                |
| iOS (Swift, XCTest)          | `npm run test:ios` (needs an iOS simulator)          |

`npm run test:ios` builds the root `Package.swift`, a test-only Swift package that compiles
the React-free part of `ios/`. The library itself is still distributed through CocoaPods.

------------------------------------------------------------------------

## Example screenshots

### Android emulator

![Android Emulator](.github/media/Emulator%20Android.png)

### Android real device

![Android Real Device](.github/media/Real%20Device%20Android.png)

### iOS real device

![iOS Real Device](.github/media/Real%20Device%20iOS.png)

### iOS simulator

![iOS Simulator](.github/media/Simulator%20iOS.png)

------------------------------------------------------------------------

## Important notes

- **Not foolproof.** Root/jailbreak hiding tools and a determined attacker with control of the
  device can bypass client-side checks. Frida can hook this library too.
- **Use as part of a security strategy.** Combine with server-side attestation (Play Integrity,
  App Attest), SSL pinning, code obfuscation and similar measures.
- **Avoid blocking legitimate users unnecessarily.** Heuristics can produce false positives
  (custom ROMs with test keys, developer devices). Prefer degrading features over hard
  blocking where you can.
- **Keep the library updated.** Root and jailbreak techniques evolve.

------------------------------------------------------------------------

## Contributing

PRs are welcome!

1. Fork the repo
2. Create a feature branch
3. Run the tests (see [Testing](#testing))
4. Commit your changes
5. Open a pull request

------------------------------------------------------------------------

## License

MIT © Rushikesh Pandit

Built with ❤️ for the React Native community.
