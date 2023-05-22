package com.rnbiometrics

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricPrompt
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.charset.Charset
import java.security.*
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Cipher
import javax.crypto.CipherOutputStream
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec

class KeychainHelper {
    companion object {

        private val LOG_TAG = KeychainHelper::class.java.simpleName
        private val KEYSTORE_TYPE = "AndroidKeyStore"
        private val ALGORITHM_AES = KeyProperties.KEY_ALGORITHM_AES
        private val BLOCK_MODE_CBC = KeyProperties.BLOCK_MODE_CBC
        private val PADDING_PKCS7 = KeyProperties.ENCRYPTION_PADDING_PKCS7
        private val AES_ENCRYPTION_TRANSFORMATION = "$ALGORITHM_AES/$BLOCK_MODE_CBC/$PADDING_PKCS7"
        private val ENCRYPTION_KEY_SIZE = 256
        val IV_LENGTH = 16
        val UTF8 = Charset.forName("UTF-8")

        fun decryptCredentials(
            keyTag: String,
            pinCode: ByteArray
        ): StorageHandler.DecryptionResult {
            val retries = AtomicInteger(1)
            try {
                val key: Key = generateKey(keyTag, retries, ALGORITHM_AES)
                return StorageHandler.DecryptionResult(
                    decryptAESBytes(key, pinCode)
                )
            } catch (fail: Throwable) {
                throw Exception(
                    "Unknown error with alias: " + keyTag + ", error: " + fail.message, fail
                )
            }
        }

        private fun decryptAESBytes(key: Key, bytes: ByteArray): String? {
            val cipher = Cipher.getInstance(AES_ENCRYPTION_TRANSFORMATION)
            return try {
                // read the initialization vector from bytes array
                val iv = readIV(bytes)
                cipher.init(Cipher.DECRYPT_MODE, key, iv)

                // decrypt the bytes using cipher.doFinal(). Using a CipherInputStream for decryption has historically led to issues
                // on the Pixel family of devices.
                val decryptedBytes = cipher.doFinal(
                    bytes, IV_LENGTH,
                    bytes.size - IV_LENGTH
                )
                String(decryptedBytes, UTF8)
            } catch (fail: Throwable) {
                Log.e(LOG_TAG, fail.message, fail)
                return null
            }
        }

        private fun generateKey(keyTag: String, retries: AtomicInteger, algorithm: String): Key {
            val keyStore = KeyStore.getInstance(KEYSTORE_TYPE)
            keyStore.load(null)
            var key: Key?

            do {
                // if key is not available yet, try to generate one
                if (!keyStore.containsAlias(keyTag)) {
                    generateKeyAndStoreUnderAlias(keyTag, algorithm)
                }

                // throw exception if cannot extract key in several retries
                key = extractKey(keyStore, keyTag, retries)
            } while (null == key)
            return key
        }

        fun encryptCredentials(
            alias: String,
            password: String
        ): StorageHandler.EncryptionResult {
            val retries = AtomicInteger(1)
            try {
                val key: Key = generateKey(alias, retries, ALGORITHM_AES)
                return StorageHandler.EncryptionResult(encryptString(key, password))
            } catch (fail: Throwable) {
                throw Exception(
                    "Unknown error with alias: " + alias + ", error: " + fail.message,
                    fail
                )
            }
        }

        private fun encryptString(key: Key, value: String): ByteArray {
            val cipher = Cipher.getInstance(AES_ENCRYPTION_TRANSFORMATION)

            // encrypt the value using a CipherOutputStream
            try {
                ByteArrayOutputStream().use { output ->

                    // write initialization vector to the beginning of the stream
                    cipher.init(Cipher.ENCRYPT_MODE, key)
                    val iv = cipher.iv
                    output.write(iv, 0, iv.size)
                    output.flush()

                    CipherOutputStream(output, cipher).use { encrypt ->
                        encrypt.write(value.toByteArray(Charset.forName("UTF-8")))
                    }
                    return output.toByteArray()
                }
            } catch (fail: Throwable) {
                throw fail
            }
        }

        /** Extract initialization vector from provided bytes array.  */
        private fun readIV(bytes: ByteArray): IvParameterSpec {
            val iv = ByteArray(IV_LENGTH)
            if (IV_LENGTH >= bytes.size) throw IOException("Insufficient length of input data for IV extracting.")
            System.arraycopy(bytes, 0, iv, 0, IV_LENGTH)
            return IvParameterSpec(iv)
        }

        /** Try to extract key by alias from keystore, in case of 'known android bug' reduce retry counter.  */
        private fun extractKey(keyStore: KeyStore, safeAlias: String, retry: AtomicInteger): Key? {

            // Fix for android.security.KeyStoreException: Invalid key blob
            // more info: https://stackoverflow.com/questions/36488219/android-security-keystoreexception-invalid-key-blob/36846085#36846085
            val key: Key = try {
                keyStore.getKey(safeAlias, null)
            } catch (ex: UnrecoverableKeyException) {
                // try one more time
                if (retry.getAndDecrement() > 0) {
                    keyStore.deleteEntry(safeAlias)
                    return null
                }
                throw ex
            } ?: throw Exception("Empty key extracted!")

            // null if the given alias does not exist or does not identify a key-related entry.
            return key
        }

        private fun generateKey(spec: KeyGenParameterSpec, algorithm: String): Key {
            val generator = KeyGenerator.getInstance(algorithm, KEYSTORE_TYPE)
            // initialize key generator
            generator.init(spec)
            return generator.generateKey()
        }

        @RequiresApi(Build.VERSION_CODES.M)
        private fun generateKeyAndStoreUnderAlias(alias: String, algorithm: String): Key {

            // Generate the key in a regular way in hardware, but not in StrongBox (need to implement it later for api >= 28)
            val secretKey: Key
            try {
                secretKey = tryGenerateRegularSecurityKey(alias, algorithm)
            } catch (fail: GeneralSecurityException) {
                throw fail
            }
            return secretKey
        }

        fun doesBiometricKeyExist(pinCode: String?): Boolean {
            return try {
                val keyStore = KeyStore.getInstance(KEYSTORE_TYPE)
                keyStore.load(null)
                return keyStore.containsAlias(pinCode)
            } catch (e: Exception) {
                false
            }
        }

        fun deleteBiometricKey(pinCode: String): Boolean {
            return try {
                val keyStore = KeyStore.getInstance(KEYSTORE_TYPE)
                keyStore.load(null)
                keyStore.deleteEntry(pinCode)
                true
            } catch (e: Exception) {
                false
            }
        }

        @RequiresApi(Build.VERSION_CODES.M)
        private fun tryGenerateRegularSecurityKey(alias: String, algorithm: String): Key {
            val specification: KeyGenParameterSpec = getAESKeyGenSpecBuilder(alias).build()
            return generateKey(specification, algorithm)
        }

        @RequiresApi(Build.VERSION_CODES.M)
        private fun getAESKeyGenSpecBuilder(alias: String): KeyGenParameterSpec.Builder {
            val purposes = KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_ENCRYPT
            return KeyGenParameterSpec.Builder(alias, purposes)
                .setBlockModes(BLOCK_MODE_CBC)
                .setEncryptionPaddings(PADDING_PKCS7)
                .setRandomizedEncryptionRequired(false)
                .setKeySize(ENCRYPTION_KEY_SIZE)
        }

        fun sign(cryptoObject: BiometricPrompt.CryptoObject, payload: String): String {
            val cryptoSignature = cryptoObject.signature
            cryptoSignature!!.update(payload.toByteArray())
            val signed = cryptoSignature.sign()
            val signedString = Base64.encodeToString(signed, Base64.DEFAULT)
            return signedString.replace("\r".toRegex(), "").replace("\n".toRegex(), "")
        }
    }
}