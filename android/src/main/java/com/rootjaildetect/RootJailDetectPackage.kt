package com.rootjaildetect

import com.facebook.react.BaseReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.module.model.ReactModuleInfo
import com.facebook.react.module.model.ReactModuleInfoProvider

/**
 * RootJailDetectPackage
 *
 * React Native package responsible for registering the
 * RootJailDetect native module with the React Native bridge.
 *
 * This class enables React Native to discover and load
 * the native security module at runtime.
 */
class RootJailDetectPackage : BaseReactPackage() {
    /**
     * Creates and returns an instance of the requested native module.
     *
     * This method is invoked by the React Native runtime
     * when it needs to load a native module.
     *
     * @param name Name of the requested native module
     * @param reactContext React application context
     *
     * @return Instance of RootJailDetectModule if the name matches,
     *         otherwise null
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
     * Provides metadata information about the native module.
     *
     * This information is used internally by React Native
     * for module registration, initialization, and optimization,
     * especially when using TurboModules.
     *
     * @return ReactModuleInfoProvider containing module configuration
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
