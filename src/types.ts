export interface RootJailDetectModule {
  /**
   * Check if the device is compromised (rooted on Android, jailbroken on iOS)
   * @returns Promise that resolves to true if device is compromised, false otherwise
   */
  isDeviceCompromised(): Promise<boolean>;

  /**
   * Check if the app is running in an emulator
   * @returns Promise that resolves to true if running in emulator
   */
  isEmulator?(): Promise<boolean>;

  /**
   * Check if the app is running in an simulator
   * @returns Promise that resolves to true if running in simulator
   */
  isSimulator?(): Promise<boolean>;

  /**
   * Check if a debugger is attached
   * @returns Promise that resolves to true if debugger is attached
   */
  isDebuggerAttached?(): Promise<boolean>;

  /**
   * Gives the reason for whether the device is compromised
   * @returns Promise that resolves to array of string if the device
   *  is compromised, empty otherwise
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
  startSecurityWatchdog(options: {}): void;

  /**
   * Stop runtime security watchdog
   *
   * This method stops the runtime security watchdog if it is currently running.
   */
  stopSecurityWatchdog(): void;
}
