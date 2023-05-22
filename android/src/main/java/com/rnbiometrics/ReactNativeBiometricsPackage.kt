package com.rnbiometrics

import com.facebook.react.ReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.uimanager.ViewManager
import com.rnbiometrics.ReactNativeBiometrics
import java.util.ArrayList

/**
 * Created by brandon on 4/5/18.
 */
class ReactNativeBiometricsPackage : ReactPackage {
    override fun createViewManagers(reactContext: ReactApplicationContext): List<ViewManager<*, *>> {
        return emptyList()
    }

    override fun createNativeModules(
        reactContext: ReactApplicationContext
    ): List<NativeModule> {
        val modules: MutableList<NativeModule> = ArrayList()
        modules.add(ReactNativeBiometrics(reactContext))
        return modules
    }
}