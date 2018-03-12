package com.aaron.fingerscandemo.utils

import android.annotation.TargetApi
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat
import java.io.IOException
import java.security.*
import java.security.cert.CertificateException
import java.security.spec.ECGenParameterSpec

/**
 * 描述：生成指纹安全验证CryptoObject类工具
 *
 * 对称加密Key
 */
class AsymCryptoObjectUtils :BaseCryptoObjectUtils{
    private val mKeyStore: KeyStore
    private var mKeyPairGenerator:KeyPairGenerator? = null
    private var mSignature:Signature? = null

    init {
        mKeyStore = KeyStore.getInstance(KEYSTORE_NAME)
        mKeyStore.load(null)
    }

    /**
     * 提供一个CryptoObject对象，用于指纹的安全验证
     */
    override fun buildCryptoObject(): FingerprintManagerCompat.CryptoObject {
        createKeyPair()
        initSignature()
        // 使用签名创建CryptoObject
        return FingerprintManagerCompat.CryptoObject(mSignature)
    }

    /**
     * 获取非对称加密密钥
     */
    @TargetApi(Build.VERSION_CODES.M)
    private fun createKeyPair() {
        // 非对称加密，创建 KeyPairGenerator 对象
        try {
            mKeyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC
                    , "AndroidKeyStore")
            mKeyPairGenerator?.initialize(
                    KeyGenParameterSpec.Builder(KEY_NAME,
                            KeyProperties.PURPOSE_SIGN)
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                            // Require the user to authenticate with a fingerprint to authorize
                            // every use of the private key
                            .setUserAuthenticationRequired(true)
                            .build())
            mKeyPairGenerator?.generateKeyPair()
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException("Failed to get an instance of KeyPairGenerator", e)
        } catch (e: NoSuchProviderException) {
            throw RuntimeException("Failed to get an instance of KeyPairGenerator", e)
        }catch (e: InvalidAlgorithmParameterException) {
            throw RuntimeException(e)
        }
    }

    /**
     * 用私钥加密签名
     */
    @TargetApi(Build.VERSION_CODES.M)
    private fun initSignature(): Boolean {
        try {
            mSignature = Signature.getInstance("SHA256withECDSA")
            mKeyStore?.load(null)
            val key = mKeyStore?.getKey(KEY_NAME, null) as PrivateKey
            mSignature?.initSign(key)
            return true
        } catch (e: KeyPermanentlyInvalidatedException) {
            return false
        } catch (e: KeyStoreException) {
            throw RuntimeException("Failed to init Cipher", e)
        } catch (e: CertificateException) {
            throw RuntimeException("Failed to init Cipher", e)
        } catch (e: UnrecoverableKeyException) {
            throw RuntimeException("Failed to init Cipher", e)
        } catch (e: IOException) {
            throw RuntimeException("Failed to init Cipher", e)
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException("Failed to init Cipher", e)
        } catch (e: InvalidKeyException) {
            throw RuntimeException("Failed to init Cipher", e)
        }
    }

    companion object {
        private const val KEY_NAME = "com.aaron.fingerscandemo.fingerprint_authentication_asymkey"   // Key的名称，保证唯一性
        private const val KEYSTORE_NAME = "AndroidKeyStore"                                          // keystore名称
    }
}