import { NativeEventEmitter, Platform } from 'react-native';
import RootJailDetect from './NativeRootJailDetect';

export enum ProtectionMode {
  LOG_ONLY = 'LOG_ONLY',
  THROW_EXCEPTION = 'THROW_EXCEPTION',
  TERMINATE = 'TERMINATE',
}

export interface SecurityWatchdogOptions {
  interval?: number;
  protectionMode?: ProtectionMode;
}

export interface SecurityThreatEvent {
  /** Human-readable reasons the watchdog flagged the device */
  reasons: string[];
  /** Detection time, in milliseconds since the Unix epoch */
  timestamp: number;
}

export interface SecurityThreatSubscription {
  remove(): void;
}

const THREAT_EVENT = 'onSecurityThreat';

let emitter: NativeEventEmitter | null = null;

/**
 * Checks whether the device is compromised: rooted on Android, jailbroken on iOS.
 *
 * Runs every native heuristic (root/jailbreak artifacts, Frida, hooking frameworks,
 * ptrace/tracer checks, inline hooks) and combines them. Emulators/simulators and
 * attached debuggers on their own do NOT make this return true; use `isEmulator()` and
 * `isDebuggerAttached()` for those.
 *
 * @returns Promise that resolves to `true` if any compromise indicator was found, `false`
 *     otherwise. The value is coerced with `Boolean()`. The promise REJECTS (after logging with
 *     console.error) when the native check itself fails.
 */
export async function isDeviceCompromised(): Promise<boolean> {
  try {
    const result = await RootJailDetect.isDeviceCompromised();
    return Boolean(result);
  } catch (error) {
    console.error('Error checking device security:', error);
    throw error;
  }
}

/**
 * Checks whether the app runs inside an emulator (Android) or a simulator (iOS).
 *
 * Calls the native `isEmulator` on Android and `isSimulator` on iOS. Never rejects.
 *
 * @returns Promise that resolves to `true` when running on an emulator/simulator. Resolves to
 *     `false` on a real device, on unsupported platforms, when the native method is
 *     unavailable, or when the native call throws (the error is logged).
 */
export async function isEmulator(): Promise<boolean> {
  try {
    if (Platform.OS === 'android' && RootJailDetect.isEmulator) {
      return Boolean(await RootJailDetect.isEmulator());
    } else if (Platform.OS === 'ios' && RootJailDetect.isSimulator) {
      return Boolean(await RootJailDetect.isSimulator());
    }
    return false;
  } catch (error) {
    console.error('Error checking emulator status:', error);
    return false;
  }
}

/**
 * Checks whether a debugger is attached to the app process.
 *
 * Android combines the Java debugger flag, wait-for-debugger state and `TracerPid`; iOS reads
 * the
 * `P_TRACED` flag via sysctl. On iOS debug builds the check is skipped (Xcode always attaches a
 * debugger) and returns `false`. Never rejects.
 *
 * @returns Promise that resolves to `true` when a debugger is attached, otherwise `false` (also
 *     `false` if the native method is unavailable or throws; the error is logged).
 */
export async function isDebuggerAttached(): Promise<boolean> {
  try {
    if (RootJailDetect.isDebuggerAttached) {
      return Boolean(await RootJailDetect.isDebuggerAttached());
    }
    return false;
  } catch (error) {
    console.error('Error checking debugger status:', error);
    return false;
  }
}

/**
 * Gives the reason for whether the device is compromised
 * (rooted on Android or jailbroken on iOS).
 *
 * This method invokes native security heuristics
 * and returns the result asynchronously.
 *
 * @returns Promise that resolves to array of string if the device
 *          is compromised, empty otherwise
 */

/**
 * Returns human-readable explanations for everything the native checkers flagged.
 *
 * The list also contains emulator/simulator and debugger findings, so it can be non-empty even
 * when `isDeviceCompromised()` is `false`. Duplicates are removed natively. Never rejects.
 *
 * @returns Promise that resolves to an array of reason strings (for example `"Magisk
 *     detected"`). Resolves to `[]` when nothing was found, when the native method is
 *     unavailable, or when the call throws (the error is logged).
 */
export async function getDetectionReasons(): Promise<string[]> {
  try {
    if (RootJailDetect.getDetectionReasons) {
      let reasons = await RootJailDetect.getDetectionReasons();

      return reasons;
    } else {
      return [];
    }
  } catch (error) {
    console.error('Error getting detection reasons:', error);
    return [];
  }
}

/**
 * Starts the runtime security watchdog.
 *
 * The watchdog re-runs the compromise and debugger checks on a randomised interval (+-40%) in a
 * background thread, and treats an abnormally long gap between iterations as a debugger pause.
 * On a threat it notifies `addSecurityThreatListener` subscribers and then applies the
 * protection
 * mode. Calling this while the watchdog already runs is a no-op (the running configuration is
 * kept).
 * Native code clamps the interval to a minimum of 100 ms.
 *
 * @param options Optional configuration object.
 * @param options.interval Milliseconds between checks. Defaults to `3000`.
 * @param options.protectionMode What to do on a threat: `LOG_ONLY` (default), `THROW_EXCEPTION`
 *     (crashes the app) or `TERMINATE` (kills the process).
 * @returns Nothing (`void`). Native errors are not caught and propagate to the caller.
 */
export function startSecurityWatchdog(
  options: SecurityWatchdogOptions = {}
): void {
  const interval = options.interval ?? 3000;
  const protectionMode = options.protectionMode ?? 'LOG_ONLY';

  RootJailDetect.startSecurityWatchdog({ interval, protectionMode });
}

/**
 * Stops the runtime security watchdog. Safe to call when it is not running; any in-flight
 * iteration finishes, then the background loop exits.
 *
 * @returns Nothing (`void`).
 */
export function stopSecurityWatchdog(): void {
  RootJailDetect.stopSecurityWatchdog();
}

/**
 * Reports whether the security watchdog is currently running. Never rejects.
 *
 * @returns Promise that resolves to `true` while the watchdog runs, `false` otherwise (also
 *     `false` if the native method is unavailable or throws; the error is logged).
 */
export async function isSecurityWatchdogRunning(): Promise<boolean> {
  try {
    if (RootJailDetect.isSecurityWatchdogRunning) {
      return Boolean(await RootJailDetect.isSecurityWatchdogRunning());
    }
    return false;
  } catch (error) {
    console.error('Error checking watchdog status:', error);
    return false;
  }
}

/**
 * Subscribes to threats found by the security watchdog (event `onSecurityThreat`).
 *
 * The listener fires in every protection mode, before the protection action runs. With
 * `TERMINATE` the process may die before JavaScript receives the event. The underlying
 * `NativeEventEmitter` is created lazily on first use.
 *
 * @param listener Callback invoked with a `SecurityThreatEvent` (`reasons` and a millisecond
 *     `timestamp`) for every detected threat.
 * @returns A subscription whose `remove()` unsubscribes the listener. Throws a `TypeError` if
 *     `listener` is not a function.
 */
export function addSecurityThreatListener(
  listener: (event: SecurityThreatEvent) => void
): SecurityThreatSubscription {
  if (typeof listener !== 'function') {
    throw new TypeError('addSecurityThreatListener expects a function');
  }
  if (!emitter) {
    emitter = new NativeEventEmitter(RootJailDetect as any);
  }
  const subscription = emitter.addListener(THREAT_EVENT, (event: any) =>
    listener(event as SecurityThreatEvent)
  );
  return { remove: () => subscription.remove() };
}

export type { RootJailDetect };
export default {
  isDeviceCompromised,
  isEmulator,
  isDebuggerAttached,
  getDetectionReasons,
  startSecurityWatchdog,
  stopSecurityWatchdog,
  isSecurityWatchdogRunning,
  addSecurityThreatListener,
};
