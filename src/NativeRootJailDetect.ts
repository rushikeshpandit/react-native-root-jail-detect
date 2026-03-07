import { TurboModuleRegistry, type TurboModule } from 'react-native';

/**
 * Spec
 *
 * TypeScript interface that defines the contract between
 * the JavaScript layer and the native RootJailDetect module.
 *
 * This interface describes all security-related APIs
 * exposed by the native implementation.
 */
export interface Spec extends TurboModule {
  /**
   * Checks whether the current device is compromised
   * (rooted on Android or jailbroken on iOS).
   *
   * This method invokes native security heuristics
   * and returns the result asynchronously.
   *
   * @returns Promise that resolves to true if the device
   *          is compromised, false otherwise
   */
  isDeviceCompromised(): Promise<boolean>;

  /**
   * Determines whether the application is running
   * inside an Android emulator environment.
   *
   * This method is primarily used on Android devices.
   *
   * @returns Promise that resolves to true if running
   *          on an emulator, false otherwise
   */
  isEmulator?(): Promise<boolean>;

  /**
   * Determines whether the application is running
   * inside an iOS simulator environment.
   *
   * This method is primarily used on iOS devices.
   *
   * @returns Promise that resolves to true if running
   *          on a simulator, false otherwise
   */
  isSimulator?(): Promise<boolean>;

  /**
   * Checks whether a debugger is currently attached
   * to the running application process.
   *
   * This helps detect debugging, reverse engineering,
   * and runtime inspection attempts.
   *
   * @returns Promise that resolves to true if a debugger
   *          is attached, false otherwise
   */
  isDebuggerAttached?(): Promise<boolean>;

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
  getDetectionReasons?(): Promise<string[]>;

  /**
   * Start runtime security watchdog
   *
   * This method starts the runtime security watchdog with
   * the specified interval and protection mode.
   *
   * @param {Object} options - Object containing the options for the security watchdog
   * @param {number} [options.interval=3000] - Interval in milliseconds between each security check
   * @param {string} [options.protectionMode='LOG_ONLY'] - Protection mode to use. Can be either 'LOG_ONLY' or 'TERMINATE'
   */
  startSecurityWatchdog(options: {
    interval?: number;
    protectionMode?: string;
  }): void;

  /**
   * Stop runtime security watchdog
   *
   * This method stops the runtime security watchdog if it is currently running.
   */
  stopSecurityWatchdog(): void;
}

/**
 * RootJailDetect Native Module
 *
 * Retrieves and enforces the native RootJailDetect
 * TurboModule implementation at runtime.
 *
 * If the native module is not properly linked,
 * this call will throw an error.
 */
export default TurboModuleRegistry.getEnforcing<Spec>('RootJailDetect');
