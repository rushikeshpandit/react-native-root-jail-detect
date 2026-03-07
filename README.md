# React Native Root/Jail Detect

[![npm
version](https://img.shields.io/npm/v/react-native-root-jail-detect.svg)](https://www.npmjs.com/package/react-native-root-jail-detect)
[![License:
MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![PRs
Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/rushikeshpandit/react-native-root-jail-detect/pulls)

A lightweight, blazing‑fast **React Native security module** to detect
rooted (Android) and jailbroken (iOS) devices, runtime instrumentation
tools (Frida), debuggers, and emulators.

Perfect for apps that require **strong client‑side integrity checks**
such as:

-   Banking apps
-   Fintech platforms
-   Enterprise apps
-   Gaming anti‑cheat systems
-   Security‑sensitive applications

------------------------------------------------------------------------

# Features

-   **Fast** -- Native implementation (Swift + Kotlin + C/C++)
-   **Cross‑platform** -- Works on both Android and iOS
-   **New Architecture Ready** -- Supports Fabric & TurboModules
-   **Runtime Protection** -- Includes a security watchdog
-   **Frida Detection** -- Detects dynamic instrumentation
-   **Debugger Detection** -- Detects runtime debugging
-   **Emulator / Simulator Detection**
-   **Zero Dependencies**
-   **MIT Licensed**

------------------------------------------------------------------------

# Advanced Security Features

## Frida Detection

The module detects runtime instrumentation tools such as Frida commonly
used for reverse engineering and bypassing security checks.

Detection techniques include:

-   Frida server port detection
-   Frida thread detection
-   Frida memory scanning
-   Frida runtime symbol detection
-   Frida dynamic library inspection

This helps protect apps from **runtime tampering and reverse
engineering**.

------------------------------------------------------------------------

## Runtime Security Watchdog

The module includes a **runtime watchdog** that continuously monitors
the environment even after the app launches.

Example scenario:

App launches → device appears safe\
Attacker attaches debugger later\
Watchdog detects it → action triggered

Protection modes:

  Mode              Behavior
  ----------------- ----------------------------
  LOG_ONLY          Logs detection events
  THROW_EXCEPTION   Throws runtime exception
  TERMINATE         Terminates the application

------------------------------------------------------------------------

# Installation

``` bash
npm install react-native-root-jail-detect
```

or

``` bash
yarn add react-native-root-jail-detect
```

------------------------------------------------------------------------

# iOS Setup

``` bash
cd ios
pod install
cd ..
npx react-native run-ios
```

------------------------------------------------------------------------

# Android Setup

For React Native 0.60+ autolinking works automatically.

``` bash
npx react-native run-android
```

------------------------------------------------------------------------

# Basic Usage

``` typescript
import RootJailDetect from 'react-native-root-jail-detect';

const checkDeviceSecurity = async () => {
  const compromised = await RootJailDetect.isDeviceCompromised();

  if (compromised) {
    console.warn("Device is rooted/jailbroken");
  } else {
    console.log("Device is secure");
  }
};
```

------------------------------------------------------------------------

# Advanced Usage

## Get Detection Reasons

Retrieve detailed detection reasons.

``` typescript
const reasons = await RootJailDetect.getDetectionReasons();
console.log(reasons);
```

Example output:

    [
     "Frida instrumentation detected",
     "Debugger attached",
     "Root management app detected"
    ]

------------------------------------------------------------------------

## Enable Security Watchdog

``` typescript
RootJailDetect.startSecurityWatchdog({
  interval: 3000,
  protectionMode: "TERMINATE"
});
```

Stop watchdog:

``` typescript
RootJailDetect.stopSecurityWatchdog();
```

------------------------------------------------------------------------

# API Reference

## isDeviceCompromised()

Returns whether device is rooted or jailbroken.

``` typescript
const compromised = await RootJailDetect.isDeviceCompromised();
```

------------------------------------------------------------------------

## isEmulator()

Detects emulator (Android) or simulator (iOS).

``` typescript
const emulator = await RootJailDetect.isEmulator();
```

------------------------------------------------------------------------

## isDebuggerAttached()

Detects whether a debugger is attached.

``` typescript
const debug = await RootJailDetect.isDebuggerAttached();
```

------------------------------------------------------------------------

## getDetectionReasons()

Returns array of human‑readable security warnings.

``` typescript
const reasons = await RootJailDetect.getDetectionReasons();
```

------------------------------------------------------------------------

# Comprehensive Security Checks

## Android

Root detection techniques include:

-   Root management app detection
-   su binary detection
-   writable system partition checks
-   dangerous system properties
-   root cloaking files
-   build tag inspection

### Emulator Detection

-   Build fingerprint analysis
-   emulator system properties
-   QEMU file detection

### Debugger Detection

-   Java debugger detection
-   ptrace detection
-   TracerPid inspection

### Runtime Instrumentation Detection

-   runtime thread detection
-   memory map scanning
-   runtime symbol detection

------------------------------------------------------------------------

## iOS

### Jailbreak Detection

-   Cydia / Sileo / Zebra detection
-   MobileSubstrate detection
-   suspicious filesystem artifacts
-   sandbox escape attempts

### Debugger Detection

-   sysctl inspection
-   ptrace anti‑debug

### Runtime Instrumentation Detection

-   injected dylib detection
-   suspicious thread detection
-   runtime symbol detection

------------------------------------------------------------------------

# Example Screenshots

## Android Emulator

![Android Emulator](.github/media/Emulator%20Android.png)

## Android Real Device

![Android Real Device](.github/media/Real%20Device%20Android.png)

## iOS Real Device

![iOS Real Device](.github/media/Real%20Device%20iOS.png)

## iOS Simulator

![iOS Simulator](.github/media/Simulator%20iOS.png)

------------------------------------------------------------------------

# Use Cases

This module is useful for:

-   Banking apps
-   Payment gateways
-   Gaming anti‑cheat
-   Enterprise security policies
-   VPN and security apps

------------------------------------------------------------------------

# Security Strength

This module combines:

-   multiple detection heuristics
-   native runtime checks
-   debugger detection
-   instrumentation detection
-   watchdog runtime monitoring

This layered approach significantly increases difficulty for attackers
attempting to bypass checks.

------------------------------------------------------------------------

# Important Notes

- **Not Foolproof:** Sophisticated root/jailbreak concealment tools may bypass detection
- **Use as Part of Security Strategy:** Combine with other security measures (SSL pinning, code obfuscation, etc.)
- **Graceful Degradation:** Consider UX - don't block legitimate users unnecessarily
- **Regular Updates:** Root/jailbreak methods evolve; keep the library updated

------------------------------------------------------------------------

# Contributing

PRs are welcome!

1.  Fork the repo
2.  Create a feature branch
3.  Commit changes
4.  Open a pull request

------------------------------------------------------------------------

# License

MIT © Rushikesh Pandit

Built with ❤️ for the React Native community.
