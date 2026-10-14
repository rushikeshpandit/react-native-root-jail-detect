package com.rootjaildetect

import com.facebook.react.BaseReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.module.model.ReactModuleInfo
import com.facebook.react.module.model.ReactModuleInfoProvider

/**
 * React Native package that registers the `RootJailDetect` TurboModule so autolinking can find
 * it.
 */
class RootJailDetectPackage : BaseReactPackage() {
    /**
     * Creates the native module when React Native asks for it by name.
     *
     * @param name Module name requested by React Native.
     * @param reactContext Application context handed to the module.
     * @return A new `RootJailDetectModule` when `name` equals `RootJailDetectModule.NAME`,
     *     otherwise `null`.
     */
    override fun getModule(
        name: String,
        reactContext: ReactApplicationContext,
    ): NativeModule? =
        if (name == RootJailDetectModule.NAME) {
            RootJailDetectModule(reactContext)
        } else {
            null
        }

    /**
     * Describes the module to React Native (TurboModule, lazily initialised, cannot override an
     * existing module).
     *
     * @return A provider mapping `RootJailDetectModule.NAME` to its `ReactModuleInfo`.
     */
    override fun getReactModuleInfoProvider(): ReactModuleInfoProvider =
        ReactModuleInfoProvider {
            mapOf(
                RootJailDetectModule.NAME to
                    ReactModuleInfo(
                        name = RootJailDetectModule.NAME,
                        className = RootJailDetectModule.NAME,
                        canOverrideExistingModule = false,
                        needsEagerInit = false,
                        isCxxModule = false,
                        isTurboModule = true,
                    ),
            )
        }
}
