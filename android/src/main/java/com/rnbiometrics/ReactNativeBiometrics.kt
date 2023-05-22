package com.rnbiometrics

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricPrompt.PromptInfo
import androidx.fragment.app.FragmentActivity
import com.facebook.react.bridge.*
import com.rnbiometrics.KeychainHelper.Companion.decryptCredentials
import com.rnbiometrics.KeychainHelper.Companion.deleteBiometricKey
import com.rnbiometrics.KeychainHelper.Companion.doesBiometricKeyExist
import com.rnbiometrics.KeychainHelper.Companion.encryptCredentials
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.RSAKeyGenParameterSpec
import java.util.concurrent.Executors

/**
 * Created by brandon on 4/5/18.
 */
class ReactNativeBiometrics(reactContext: ReactApplicationContext?) :
    ReactContextBaseJavaModule(reactContext) {

    private val KEYSTORE_TYPE = "AndroidKeyStore"

    private val BIOMETRICS = "Biometrics"
    private val AVAILABLE = "available"
    private val BIOMETRIC_TYPE = "biometryType"
    private val KEYS_EXIST = "keysExist"
    private val PUBLIC_KEY = "publicKey"
    private val KEYS_DELETED = "keysDeleted"
    private val SUCCESS = "success"
    private val SIGNATURE = "signature"
    private val ERROR = "error"
    private val KEY_TAG = "keyTag"
    private val KEY_PASSWORD = "keyPassword"

    override fun getName(): String {
        return "ReactNativeBiometrics"
    }

    @ReactMethod
    fun isSensorAvailable(promise: Promise) {
        try {
            val resultMap: WritableMap = WritableNativeMap()
            resultMap.putBoolean(AVAILABLE, isStrongBiometricAuthAvailable(reactApplicationContext))
            resultMap.putString(BIOMETRIC_TYPE, getBiometricType(reactApplicationContext))
            promise.resolve(resultMap)
        } catch (e: java.lang.Exception) {
            promise.reject("E_SUPPORTED_BIOMETRY_ERROR", e)
        } catch (fail: Throwable) {
            promise.reject("E_UNKNOWN_ERROR", fail)
        }
    }

    @ReactMethod
    fun createKeys(options: ReadableMap, promise: Promise) {
        try {
            val keyTag = options.getString(KEY_TAG)
            val pinCode = options.getString(KEY_PASSWORD)

            if (keyTag == null || pinCode == null) {
                promise.reject(
                    "KeyTag and or pincode is null",
                    "key tag: $keyTag pincode: $pinCode"
                )
                return
            }

            deleteBiometricKey(pinCode)

            val decryptionResult = loadPin(keyTag)
            val pinCodeDecrypted = decryptionResult?.pinCode
            if (pinCodeDecrypted == null || pinCodeDecrypted != pinCode) {
                savePin(keyTag, pinCode)
            }

            //TODO (original code but in kotlin) Refactor using KeychainHelper, we stay simple for now
            val keyPairGenerator =
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE_TYPE)
            val keyGenParameterSpec =
                KeyGenParameterSpec.Builder(pinCode, KeyProperties.PURPOSE_SIGN)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    .setAlgorithmParameterSpec(
                        RSAKeyGenParameterSpec(
                            2048,
                            RSAKeyGenParameterSpec.F4
                        )
                    )
                    .setRandomizedEncryptionRequired(false)
                    .build()
            keyPairGenerator.initialize(keyGenParameterSpec)
            val keyPair = keyPairGenerator.generateKeyPair()
            val publicKey = keyPair.public
            val encodedPublicKey = publicKey.encoded
            var publicKeyString = Base64.encodeToString(encodedPublicKey, Base64.DEFAULT)
            publicKeyString =
                publicKeyString.replace("\r".toRegex(), "").replace("\n".toRegex(), "")
            val resultMap: WritableMap = WritableNativeMap()
            resultMap.putString(PUBLIC_KEY, publicKeyString)
            promise.resolve(resultMap)
        } catch (e: Exception) {
            promise.reject("Error generating public private keys: ", e.message)
        }
    }

    @ReactMethod
    fun deleteKeys(params: ReadableMap, promise: Promise) {
        val keyTag = params.getString(KEY_TAG)
        if (keyTag == null) {
            promise.reject(
                "Error deleting biometric key from keystore",
                "keytag is null"
            )
            return
        }
        val decryptionResult = loadPin(keyTag)
        val pinCode = decryptionResult?.pinCode
        val resultMap: WritableMap = WritableNativeMap()
        if (pinCode != null && doesBiometricKeyExist(pinCode)) {
            Storage.removeEncryptedPinCode(reactApplicationContext, keyTag)
            val deletionSuccessful = deleteBiometricKey(pinCode)
            if (deletionSuccessful) {
                resultMap.putBoolean(KEYS_DELETED, true)
                promise.resolve(resultMap)
            } else {
                promise.reject(
                    "Error deleting biometric key from keystore",
                    "Error deleting biometric key from keystore"
                )
            }
        } else {
            resultMap.putBoolean(KEYS_DELETED, false)
            promise.resolve(resultMap)
        }
    }

    @ReactMethod
    fun createSignature(params: ReadableMap, promise: Promise) {
        UiThreadUtil.runOnUiThread {
            try {
                val cancelBottomText = params.getString("cancelButtonText")
                val promptMessage = params.getString("promptMessage")
                val payload = params.getString("payload")
                val keyTag = params.getString(KEY_TAG)
                val keyPassword = params.getString(KEY_PASSWORD)

                val signature = Signature.getInstance("SHA256withRSA")
                val keyStore = KeyStore.getInstance(KEYSTORE_TYPE)
                keyStore.load(null)

                val useBiometrics = useBiometrics(keyPassword)

                val key = getKeyPassword(keyPassword, keyTag!!, useBiometrics)
                if (key == null) {
                    promise.reject(ERROR, "Error generating signature: no pin saved or loaded")
                }

                val privateKey = keyStore.getKey(key, null) as PrivateKey
                signature.initSign(privateKey)
                val cryptoObject = BiometricPrompt.CryptoObject(signature)

                if (useBiometrics) {
                    val authCallback = CreateSignatureCallback(promise, payload!!)
                    val fragmentActivity = currentActivity as FragmentActivity
                    val executor = Executors.newSingleThreadExecutor()
                    val prompt = BiometricPrompt(fragmentActivity, executor, authCallback)
                    val promptInfo = PromptInfo.Builder()
                        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                        .setConfirmationRequired(false)
                        .setNegativeButtonText(cancelBottomText.toString())
                        .setTitle(promptMessage.toString())
                        .build()
                    prompt.authenticate(promptInfo, cryptoObject)
                } else {
                    val signedString = KeychainHelper.sign(cryptoObject, payload!!)
                    val resultMap: WritableMap = WritableNativeMap()
                    resultMap.putBoolean(SUCCESS, true)
                    resultMap.putString(SIGNATURE, signedString)
                    promise.resolve(resultMap)
                }
            } catch (e: Exception) {
                promise.reject(
                    "Error signing payload: " + e.message,
                    "Error generating signature: " + e.message
                )
            }
        }
    }

    @ReactMethod
    fun simplePrompt(params: ReadableMap, promise: Promise) {
        // Not used - original code from the lib but in kotlin
        UiThreadUtil.runOnUiThread {
            try {
                val cancelBottomText = params.getString("cancelButtonText")
                val promptMessage = params.getString("promptMessage")
                val authCallback = SimplePromptCallback(promise)
                val fragmentActivity = currentActivity as FragmentActivity?
                val executor = Executors.newSingleThreadExecutor()
                val biometricPrompt = BiometricPrompt(fragmentActivity!!, executor, authCallback)
                val promptInfo: PromptInfo = PromptInfo.Builder()
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    .setNegativeButtonText(cancelBottomText.toString())
                    .setTitle(promptMessage.toString())
                    .build()
                biometricPrompt.authenticate(promptInfo)
            } catch (e: Exception) {
                promise.reject(
                    "Error displaying local biometric prompt: " + e.message,
                    "Error displaying local biometric prompt: " + e.message
                )
            }
        }
    }

    @ReactMethod
    fun biometricKeysExist(readableMap: ReadableMap, promise: Promise) {
        try {
            val keyTag = readableMap.getString(KEY_TAG)
            if (keyTag == null) {
                promise.reject(
                    "Error checking if biometric key exists",
                    "keyTag value: $keyTag"
                )
                return
            }
            val decryptionResult = loadPin(keyTag)
            val pinCode = decryptionResult?.pinCode

            val resultMap: WritableMap = WritableNativeMap()
            resultMap.putBoolean(KEYS_EXIST, doesBiometricKeyExist(pinCode))
            promise.resolve(resultMap)
        } catch (e: Exception) {
            promise.reject("Error checking if biometric key exists: ", e.message)
        }
    }

    private fun getBiometricType(context: Context): String? {
        return if (isStrongBiometricAuthAvailable(context)) {
            BIOMETRICS
        } else null
    }

    private fun savePin(keyTag: String, pinCode: String) {
        val encryptionResult = encryptCredentials(keyTag, pinCode)
        Storage.storeEncryptedEntry(reactApplicationContext, keyTag, encryptionResult.pinCode)
    }

    private fun loadPin(keyTag: String): StorageHandler.DecryptionResult? {
        val pinCode = Storage.getPinCodeFromSharedPrefs(reactApplicationContext, keyTag)
        if (pinCode != null) {
            return decryptCredentials(keyTag, pinCode)
        }
        return null
    }

    private fun getKeyPassword(
        keyPassword: String?, keyTag: String, useBiometrics: Boolean
    ): String? {
        return if (useBiometrics) {
            val decryptionResult = loadPin(keyTag)
            decryptionResult?.pinCode
        } else {
            keyPassword
        }
    }

    private fun useBiometrics(keyPassword: String?): Boolean {
        return keyPassword == null && isStrongBiometricAuthAvailable(
            reactApplicationContext
        )
    }

    private fun isStrongBiometricAuthAvailable(context: Context): Boolean {
        return BiometricManager.from(context)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS
    }
}