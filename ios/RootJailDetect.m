#import <React/RCTBridgeModule.h>

/**
 * RootJailDetect
 *
 * Objective-C bridge interface that exposes native iOS
 * security detection APIs to the React Native JavaScript layer.
 *
 * This file enables communication between React Native
 * and the underlying Swift implementation.
 */
@interface RCT_EXTERN_MODULE(RootJailDetect, NSObject)

/**
 * Checks whether the current device is compromised (jailbroken).
 *
 * This method executes multiple native jailbreak-detection
 * heuristics and returns the result asynchronously.
 *
 * @param resolve Promise resolver that receives YES if the device
 *                is jailbroken, NO otherwise
 * @param reject  Promise rejecter used when an error occurs
 */
RCT_EXTERN_METHOD(isDeviceCompromised:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

/**
 * Determines whether the application is running inside
 * an iOS simulator environment.
 *
 * Simulators are commonly rooted/jailbroken by default and
 * may represent a higher security risk.
 *
 * @param resolve Promise resolver that receives YES if running
 *                on a simulator, NO otherwise
 * @param reject  Promise rejecter used when an error occurs
 */
RCT_EXTERN_METHOD(isSimulator:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

/**
 * Checks whether a debugger is currently attached
 * to the running application process.
 *
 * This helps detect reverse engineering, debugging,
 * and runtime inspection attempts.
 *
 * @param resolve Promise resolver that receives YES if a debugger
 *                is attached, NO otherwise
 * @param reject  Promise rejecter used when an error occurs
 */
RCT_EXTERN_METHOD(isDebuggerAttached:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

/**
 Returns all detection reasons
 */
RCT_EXTERN_METHOD(getDetectionReasons:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

/**
 Starts watchdog
 */
RCT_EXTERN_METHOD(startSecurityWatchdog:(NSDictionary *)options)

/**
 Stops watchdog
 */
RCT_EXTERN_METHOD(stopSecurityWatchdog)

/**
 * Indicates whether the module must be initialized
 * on the main (UI) thread.
 *
 * Returning NO allows React Native to initialize
 * this module on a background thread for better performance.
 */
+ (BOOL)requiresMainQueueSetup
{
  return NO;
}

@end
