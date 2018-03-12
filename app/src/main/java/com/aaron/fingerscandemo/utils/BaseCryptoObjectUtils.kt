package com.aaron.fingerscandemo.utils

import android.support.v4.hardware.fingerprint.FingerprintManagerCompat

/**
 * Created by Aaron on 2018/3/11.
 */

interface BaseCryptoObjectUtils {
    fun buildCryptoObject(): FingerprintManagerCompat.CryptoObject
}
