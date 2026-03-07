import { Platform } from 'react-native';
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

/**
 * Checks if the device is compromised (rooted on Android, jailbroken on iOS)
 * @returns {Promise<boolean>} A promise that resolves
 * to true if the device is compromised, false otherwise
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
 * Checks if the app is running in an emulator/simulator
 * @returns {Promise<boolean>} A promise that resolves
 * to true if running in emulator/simulator, false otherwise
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
 * Checks if a debugger is attached to the app
 * @returns {Promise<boolean>} A promise that resolves
 * to true if a debugger is attached, false otherwise
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

export async function getDetectionReasons(): Promise<string[]> {
  try {
    if (RootJailDetect.getDetectionReasons) {
      let reasons = await RootJailDetect.getDetectionReasons();

      return reasons;
    } else {
      return [];
    }
  } catch (error) {
    console.error('Error checking debugger status:', error);
    return [];
  }
}

/**
 * Starts the runtime security watchdog with the specified interval and protection mode.
 *
 * @param {SecurityWatchdogOptions} [options] - Object containing the options for the security watchdog
 * @param {number} [options.interval=3000] - Interval in milliseconds between each security check
 * @param {string} [options.protectionMode='LOG_ONLY'] - Protection mode to use. Can be either 'LOG_ONLY' or 'TERMINATE'
 *
 * @example
 * RootJailDetect.startSecurityWatchdog({
 *   interval: 5000,
 *   protectionMode: "TERMINATE"
 * })
 */
export function startSecurityWatchdog(
  options: SecurityWatchdogOptions = {}
): void {
  const interval = options.interval ?? 3000;
  const protectionMode = options.protectionMode ?? 'LOG_ONLY';

  RootJailDetect.startSecurityWatchdog({ interval, protectionMode });
}

/**
 * Stop runtime watchdog
 *
 * @example
 * RootJailDetect.stopSecurityWatchdog()
 */
export function stopSecurityWatchdog(): void {
  RootJailDetect.stopSecurityWatchdog();
}

export type { RootJailDetect };
export default {
  isDeviceCompromised,
  isEmulator,
  isDebuggerAttached,
  getDetectionReasons,
  startSecurityWatchdog,
  stopSecurityWatchdog,
};
