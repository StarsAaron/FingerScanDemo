package com.aaron.fingerscandemo.utils

import android.annotation.TargetApi
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat

import java.security.Key
import java.security.KeyStore

import javax.crypto.Cipher
import javax.crypto.KeyGenerator

/**
 * 描述：生成指纹安全验证CryptoObject类工具
 *
 * 对称加密Key
 */
class CryptoObjectUtils:BaseCryptoObjectUtils{
    private val _keystore: KeyStore

    init {
        _keystore = KeyStore.getInstance(KEYSTORE_NAME)
        _keystore.load(null)
    }

    /**
     * 提供一个CryptoObject对象，用于指纹的安全验证
     */
    @Throws(Exception::class)
    override fun buildCryptoObject(): FingerprintManagerCompat.CryptoObject {
        val cipher = createCipher(true)
        return FingerprintManagerCompat.CryptoObject(cipher)
    }

    /**
     * 获取一个Cipher
     * @param Boolean 是否重新创建一个Key
     */
    @TargetApi(Build.VERSION_CODES.M)
    private fun createCipher(retry: Boolean): Cipher {
        val key = getKey()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        try {
            cipher.init(Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE, key)
        } catch (e: KeyPermanentlyInvalidatedException) {
            //  1. 一个新的指纹image已经注册到系统中
            //  2. 当前设备中的曾经注册过的指纹现在不存在了，可能是被全部删除了
            //  3. 用户关闭了屏幕锁功能
            //  4. 用户改变了屏幕锁的方式
            //  当上面的情况发生了，会抛出KeyPermanentlyInvalidatedException异常

            // 尝试删除无效的Key，重新创建一个新Key
            _keystore.deleteEntry(KEY_NAME)
            if (retry) {
                createCipher(false)
            } else {
                throw Exception("无法创建Cipher", e)
            }
        }

        return cipher
    }

    /**
     * 从keystore类中获取存储在设备上的对称加密Key
     */
    private fun getKey(): Key {
        if (!_keystore.isKeyEntry(KEY_NAME)) {
            createKey()
        }
        return _keystore.getKey(KEY_NAME, null)
    }

    /**
     * KeyGenerator 创建一个对称密钥，存放在 KeyStore 里。
     */
    @TargetApi(Build.VERSION_CODES.M)
    private fun createKey() {
        val keyGen = KeyGenerator.getInstance(KEY_ALGORITHM, KEYSTORE_NAME)
        val keyGenSpec = KeyGenParameterSpec.Builder(KEY_NAME
                , KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(BLOCK_MODE)
                .setEncryptionPaddings(ENCRYPTION_PADDING)
                .setUserAuthenticationRequired(true) // 获取key需要先通过身份认证
                .build()         // KeyGenParameterSpec 完成参数配置
        keyGen.init(keyGenSpec)  // KeyGenerator 初始化参数配置KeyGenParameterSpec
        keyGen.generateKey()     // KeyGenerator 创建一个对称密钥，存放在 KeyStore 里。
    }

    companion object {
        private const val KEY_NAME = "com.aaron.fingerscandemo.fingerprint_authentication_key"   // Key的名称，保证唯一性
        private const val KEYSTORE_NAME = "AndroidKeyStore"                                      // keystore名称
        private const val KEY_ALGORITHM = KeyProperties.KEY_ALGORITHM_AES                        // AES算法获取KEY
        private const val BLOCK_MODE = KeyProperties.BLOCK_MODE_CBC                              // 分组模式
        private const val ENCRYPTION_PADDING = KeyProperties.ENCRYPTION_PADDING_PKCS7            // PKCS7分组填充方式
        private const val TRANSFORMATION = KEY_ALGORITHM + "/" +
                BLOCK_MODE + "/" +
                ENCRYPTION_PADDING
    }
}