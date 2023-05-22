package com.rnbiometrics

import androidx.biometric.BiometricPrompt
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.WritableMap
import com.facebook.react.bridge.WritableNativeMap

class SimplePromptCallback(private val promise: Promise) :
    BiometricPrompt.AuthenticationCallback() {
    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
        super.onAuthenticationError(errorCode, errString)
        if (errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON || errorCode == BiometricPrompt.ERROR_USER_CANCELED) {
            val resultMap: WritableMap = WritableNativeMap()
            resultMap.putBoolean("success", false)
            resultMap.putString("error", "User cancellation")
            promise.resolve(resultMap)
        } else {
            promise.reject(errString.toString(), errString.toString())
        }
    }

    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
        super.onAuthenticationSucceeded(result)
        val resultMap: WritableMap = WritableNativeMap()
        resultMap.putBoolean("success", true)
        promise.resolve(resultMap)
    }
}