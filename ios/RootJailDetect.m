#import <React/RCTBridgeModule.h>
#import <React/RCTEventEmitter.h>

/**
 * Objective-C bridge that exposes the Swift `RootJailDetect` module (an `RCTEventEmitter`) to
 * React Native.
 */
@interface RCT_EXTERN_MODULE(RootJailDetect, RCTEventEmitter)

/**
 * Checks whether the device is jailbroken.
 *
 * @param resolve Called with YES if jailbroken, NO otherwise.
 * @param reject Unused; this call does not fail.
 */
RCT_EXTERN_METHOD(isDeviceCompromised:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

/**
 * Checks whether the app runs in the simulator.
 *
 * @param resolve Called with YES in the simulator.
 * @param reject Unused; this call does not fail.
 */
RCT_EXTERN_METHOD(isSimulator:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

/**
 * Checks whether a debugger is attached (always NO in DEBUG builds).
 *
 * @param resolve Called with YES if the process is traced.
 * @param reject Unused; this call does not fail.
 */
RCT_EXTERN_METHOD(isDebuggerAttached:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

/**
 * Returns the human-readable reasons from all detectors.
 *
 * @param resolve Called with an NSArray of unique strings (empty when clean).
 * @param reject Unused; this call does not fail.
 */
RCT_EXTERN_METHOD(getDetectionReasons:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

/**
 * Starts the runtime watchdog.
 *
 * @param options NSDictionary with optional `interval` (milliseconds, default 3000) and
 *     `protectionMode` (`LOG_ONLY`, `THROW_EXCEPTION`, `TERMINATE`).
 */
RCT_EXTERN_METHOD(startSecurityWatchdog:(NSDictionary *)options)

/**
 * Stops the runtime watchdog.
 */
RCT_EXTERN_METHOD(stopSecurityWatchdog)

/**
 * Reports whether the watchdog loop is active.
 *
 * @param resolve Called with YES while it runs.
 * @param reject Unused; this call does not fail.
 */
RCT_EXTERN_METHOD(isSecurityWatchdogRunning:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

/**
 * Tells React Native the module needs no main-thread initialisation.
 *
 * @return Always NO.
 */
+ (BOOL)requiresMainQueueSetup
{
  return NO;
}

@end
