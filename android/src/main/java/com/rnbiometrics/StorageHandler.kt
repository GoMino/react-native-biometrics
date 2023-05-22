package com.rnbiometrics

interface StorageHandler {

    abstract class StorageResult<T>(val pinCode: T)

    class EncryptionResult(pinCode: ByteArray) : StorageResult<ByteArray>(pinCode)

    class DecryptionResult(pinCode: String?) :
        StorageResult<String?>(pinCode)
}

