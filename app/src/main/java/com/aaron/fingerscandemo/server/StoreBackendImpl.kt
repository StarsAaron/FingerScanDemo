/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

package com.aaron.fingerscandemo.server


import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.PublicKey
import java.security.Signature
import java.security.SignatureException
import java.util.HashMap
import java.util.HashSet

/**
 * A fake backend implementation of [StoreBackend].
 */
class StoreBackendImpl : StoreBackend {

    private val mPublicKeys = HashMap<String, PublicKey>()
    private val mReceivedTransactions = HashSet<Transaction>()

    /**
     * 使用公钥在后端验证已签名的数据
     * @param transaction          the contents of the purchase transaction, its contents are
     * signed
     * by the
     * private key in the client side.
     * @param transactionSignature the signature of the transaction's contents.
     * @return
     */
    override fun verify(transaction: Transaction, transactionSignature: ByteArray): Boolean {
        try {
            if (mReceivedTransactions.contains(transaction)) {
                // It verifies the equality of the transaction including the client nonce
                // So attackers can't do replay attacks.
                return false
            }
            mReceivedTransactions.add(transaction)
            val publicKey = mPublicKeys[transaction.userId]
            val verificationFunction = Signature.getInstance("SHA256withECDSA")
            verificationFunction.initVerify(publicKey)
            verificationFunction.update(transaction.toByteArray())
            if (verificationFunction.verify(transactionSignature)) {
                // Transaction is verified with the public key associated with the user
                // Do some post purchase processing in the server
                return true
            }
        } catch (e: NoSuchAlgorithmException) {
            // In a real world, better to send some error message to the user
        } catch (e: InvalidKeyException) {
        } catch (e: SignatureException) {
        }
        return false
    }

    override fun verify(transaction: Transaction, password: String): Boolean {
        // As this is just a sample, we always assume that the password is right.
        return true
    }

    /**
     * 模拟后台服务器接收用户信息和公钥
     * @param userId    the unique ID of the user within the app including server side
     * implementation
     * @param password  the password for the user for the server side
     * @param publicKey the public key object to verify the signature from the user
     * @return
     */
    override fun enroll(userId: String, password: String, publicKey: PublicKey): Boolean {
        if (publicKey != null) {
            mPublicKeys[userId] = publicKey
        }
        // We just ignore the provided password here, but in real life, it is registered to the
        // backend.
        return true
    }
}
