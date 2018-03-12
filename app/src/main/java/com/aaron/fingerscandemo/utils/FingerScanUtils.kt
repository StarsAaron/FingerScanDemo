package com.aaron.fingerscandemo.utils

import android.annotation.TargetApi
import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat
import android.support.v4.os.CancellationSignal

/**
 * 描述：指纹扫描帮助类
 */
object FingerScanUtils {

    /**
     * 用于判断是否支持指纹识别
     *
     * @param context
     * @return
     */
    fun isHardWareDetected(context: Context): Boolean {
        return FingerprintManagerCompat.from(context).isHardwareDetected
    }

    /**
     * 当前手机是否设置过指纹
     *
     * @param context
     * @return
     */
    fun hasEnrolledFingerPrint(context: Context): Boolean {
        return FingerprintManagerCompat.from(context).hasEnrolledFingerprints()
    }

    /**
     * 设备是否有屏幕锁保护 可以是password，PIN或者图案都行
     * google原生的逻辑就是：想要使用指纹识别的话，必须首先使能屏幕锁才行
     *
     * @param context
     * @return
     */
    @TargetApi(Build.VERSION_CODES.JELLY_BEAN)
    fun isKeyguardSecure(context: Context): Boolean {
        return (context.getSystemService(Context.KEYGUARD_SERVICE)
                as KeyguardManager).isKeyguardSecure
    }

    /**
     * 开始进行指纹识别
     *
     * @param context
     * @param cancellationSignal 指纹识别取消的控制器
     * @param callback           指纹识别回调函数
     */
    fun doFingerPrint(context: Context, co: FingerprintManagerCompat.CryptoObject
                      , cancellationSignal: CancellationSignal
                      , callback: FingerprintManagerCompat.AuthenticationCallback) {
        val managerCompat = FingerprintManagerCompat.from(context)
        managerCompat.authenticate(co, 0, cancellationSignal, callback, null)
    }
}
