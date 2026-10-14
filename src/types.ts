export interface RootJailDetectModule {
  /**
   * Checks whether the device is rooted (Android) or jailbroken (iOS).
   *
   * @returns Promise resolving to `true` if compromised.
   */
  isDeviceCompromised(): Promise<boolean>;

  /**
   * Checks whether the app runs on an Android emulator (optional).
   *
   * @returns Promise resolving to `true` on an emulator.
   */
  isEmulator?(): Promise<boolean>;

  /**
   * Checks whether the app runs on an iOS simulator (optional).
   *
   * @returns Promise resolving to `true` on a simulator.
   */
  isSimulator?(): Promise<boolean>;

  /**
   * Checks whether a debugger is attached (optional).
   *
   * @returns Promise resolving to `true` if a debugger is attached.
   */
  isDebuggerAttached?(): Promise<boolean>;

  /**
   * Lists the reasons the device was flagged (optional).
   *
   * @returns Promise resolving to the reason strings (empty when clean).
   */
  getDetectionReasons?(): Promise<string[]>;

  /**
   * Starts the runtime security watchdog.
   *
   * @param options.interval Milliseconds between checks (default 3000).
   * @param options.protectionMode `LOG_ONLY`, `THROW_EXCEPTION` or `TERMINATE`.
   * @returns Nothing (`void`).
   */
  startSecurityWatchdog(options: {
    interval?: number;
    protectionMode?: string;
  }): void;

  /**
   * Stops the runtime security watchdog.
   *
   * @returns Nothing (`void`).
   */
  stopSecurityWatchdog(): void;

  /**
   * Reports whether the watchdog is running.
   *
   * @returns Promise resolving to `true` while it runs.
   */
  isSecurityWatchdogRunning(): Promise<boolean>;
}
