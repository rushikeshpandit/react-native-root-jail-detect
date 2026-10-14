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
   * Native: checks whether the device is rooted/jailbroken.
   *
   * @returns Promise resolving to `true` if compromised; rejects with code `ERROR` on a native
   *     failure.
   */
  isDeviceCompromised(): Promise<boolean>;

  /**
   * Native (Android): checks whether the app runs on an emulator.
   *
   * @returns Promise resolving to `true` on an emulator; rejects with code `ERROR` on a native
   *     failure.
   */
  isEmulator?(): Promise<boolean>;

  /**
   * Native (iOS): checks whether the app runs on a simulator.
   *
   * @returns Promise resolving to `true` on a simulator; rejects on a native failure.
   */
  isSimulator?(): Promise<boolean>;

  /**
   * Native: checks whether a debugger is attached to the process.
   *
   * @returns Promise resolving to `true` if a debugger is attached; rejects on a native
   *     failure.
   */
  isDebuggerAttached?(): Promise<boolean>;

  /**
   * Native: lists human-readable reasons produced by all checkers.
   *
   * @returns Promise resolving to the de-duplicated reason strings (empty when nothing was
   *     found).
   */
  getDetectionReasons?(): Promise<string[]>;

  /**
   * Native: starts the runtime watchdog. Ignored if it is already running.
   *
   * @param options.interval Milliseconds between checks (default 3000, native minimum 100).
   * @param options.protectionMode `LOG_ONLY`, `THROW_EXCEPTION` or `TERMINATE`; unknown values
   *     fall back to `LOG_ONLY`.
   * @returns Nothing (`void`).
   */
  startSecurityWatchdog(options: {
    interval?: number;
    protectionMode?: string;
  }): void;

  /**
   * Native: stops the runtime watchdog if it is running.
   *
   * @returns Nothing (`void`).
   */
  stopSecurityWatchdog(): void;

  /**
   * Native: reports whether the watchdog loop is active.
   *
   * @returns Promise resolving to `true` while the watchdog runs.
   */
  isSecurityWatchdogRunning(): Promise<boolean>;

  /**
   * Required by `NativeEventEmitter`; called when JS subscribes to an event. Not meant to be
   * called directly.
   *
   * @param eventName Name of the event being subscribed to (`onSecurityThreat`).
   * @returns Nothing (`void`).
   */
  addListener(eventName: string): void;

  /**
   * Required by `NativeEventEmitter`; called when JS unsubscribes. Not meant to be called
   * directly.
   *
   * @param count Number of listeners removed.
   * @returns Nothing (`void`).
   */
  removeListeners(count: number): void;
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
