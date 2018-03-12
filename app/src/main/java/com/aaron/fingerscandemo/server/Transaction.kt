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

import android.annotation.TargetApi
import android.os.Build

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.IOException
import java.util.Objects

/**
 * An entity that represents a single transaction (purchase) of an item.
 */
class Transaction(
        /** The unique user ID who made the transaction  */
        val userId: String,
        /** The unique ID of the item of the purchase  */
        private val mItemId: Long?,
        /**
         * The random long value that will be also signed by the private key and verified in the server
         * that the same nonce can't be reused to prevent replay attacks.
         */
        private val mClientNonce: Long?) {

    /**
     * 获取Transaction对象的字节数组
     */
    fun toByteArray(): ByteArray {
        val byteArrayOutputStream = ByteArrayOutputStream()
        var dataOutputStream: DataOutputStream? = null
        try {
            dataOutputStream = DataOutputStream(byteArrayOutputStream)
            dataOutputStream.writeLong(mItemId!!)
            dataOutputStream.writeUTF(userId)
            dataOutputStream.writeLong(mClientNonce!!)
            return byteArrayOutputStream.toByteArray()
        } catch (e: IOException) {
            throw RuntimeException(e)
        } finally {
            try {
                if (dataOutputStream != null) {
                    dataOutputStream.close()
                }
                byteArrayOutputStream.close()
            } catch (ignore: IOException) {
            }
        }
    }

    @TargetApi(Build.VERSION_CODES.KITKAT)
    override fun equals(o: Any?): Boolean {
        if (this === o) {
            return true
        }
        if (o == null || javaClass != o.javaClass) {
            return false
        }

        val that = o as Transaction?
        return mItemId == that!!.mItemId && userId == that.userId &&
                mClientNonce == that.mClientNonce
    }

    @TargetApi(Build.VERSION_CODES.KITKAT)
    override fun hashCode(): Int {
        return Objects.hash(mItemId, userId, mClientNonce)
    }
}
