package com.rnbiometrics

import android.content.Context
import android.util.Base64
import android.util.Log
import java.nio.charset.StandardCharsets

class Storage {
    companion object {
        private val ONEY_DATA = "ONEY_DATA"

        fun getPinCodeFromSharedPrefs(context: Context, key: String): ByteArray? {
            val sharedPrefs = context.getSharedPreferences(ONEY_DATA, Context.MODE_PRIVATE)
            val value = sharedPrefs.getString(key, null)
            return if (value != null) Base64.decode(value, Base64.DEFAULT) else null
        }

        fun storeEncryptedEntry(context: Context, key: String, pinCode: ByteArray) {
            val sharedPrefs = context.getSharedPreferences(ONEY_DATA, Context.MODE_PRIVATE)
            val value = Base64.encodeToString(pinCode, Base64.DEFAULT)
            sharedPrefs.edit().putString(key, value).commit()
        }

        fun removeEncryptedPinCode(context: Context, keyTag: String) {
            val sharedPrefs = context.getSharedPreferences(ONEY_DATA, Context.MODE_PRIVATE)
            sharedPrefs.edit().remove(keyTag)?.commit()
        }
    }
}