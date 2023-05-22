package com.rnbiometrics

import androidx.biometric.BiometricPrompt
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.WritableMap
import com.facebook.react.bridge.WritableNativeMap

class CreateSignatureCallback(private val promise: Promise, private val payload: String) :
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
        try {
            val cryptoObject = result.cryptoObject

            if (cryptoObject == null) {
                promise.reject("Error creating signature: ", "Error creating signature")
                return
            }

            val signedString = KeychainHelper.sign(cryptoObject, payload)
            val resultMap: WritableMap = WritableNativeMap()
            resultMap.putBoolean("success", true)
            resultMap.putString("signature", signedString)
            promise.resolve(resultMap)
        } catch (e: Exception) {
            promise.reject("Error creating signature: " + e.message, "Error creating signature")
        }
    }
}