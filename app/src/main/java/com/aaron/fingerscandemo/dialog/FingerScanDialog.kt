package com.aaron.fingerscandemo.dialog

import android.content.Context
import android.os.Handler
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat
import android.support.v4.os.CancellationSignal
import android.support.v7.app.AlertDialog
import android.view.View
import android.widget.ImageView
import android.widget.TextView

import com.aaron.fingerscandemo.R
import com.aaron.fingerscandemo.server.StoreBackend
import com.aaron.fingerscandemo.server.StoreBackendImpl
import com.aaron.fingerscandemo.server.Transaction
import com.aaron.fingerscandemo.utils.*
import java.security.SecureRandom
import java.security.SignatureException


/**
 * 描述：指纹弹窗
 */
class FingerScanDialog(private val context: Context) {
    private var dialog: AlertDialog? = null
    private var ivDialogIcon: ImageView? = null
    private var tvDialogText: TextView? = null

    private var cancellationSignal: CancellationSignal? = null
    private var cryptoObjectUtils: BaseCryptoObjectUtils? = null

    private var cryptoObject: FingerprintManagerCompat.CryptoObject? = null

    /**
     * 指纹弹窗
     */
    fun showDialog() {
        val viewFinger = View.inflate(context, R.layout.dialog_finger, null)
        ivDialogIcon = viewFinger.findViewById(R.id.iv_dialog_finger_icon)
        tvDialogText = viewFinger.findViewById(R.id.tv_dialog_finger_text)

        val builder = AlertDialog.Builder(context, R.style.up_dialog)
        dialog = builder.create()
        dialog?.setView(viewFinger)
        dialog?.setCanceledOnTouchOutside(true)
        dialog?.setOnDismissListener { dialog ->
            cancellationSignal?.cancel()
            cancellationSignal = null
            dialog.dismiss()
        }
        dialog?.show()

        // 清除样式
        DrawableKitUtils.removeDrawableTintColor(ivDialogIcon!!.drawable)

        startFingerPrint()
    }

    /**
     * 指纹回调
     */
    private fun startFingerPrint() {
        try {
            cancellationSignal = CancellationSignal()
//            cryptoObjectUtils = CryptoObjectUtils()
            cryptoObjectUtils = AsymCryptoObjectUtils()
            cryptoObject = cryptoObjectUtils!!.buildCryptoObject()

            FingerScanUtils.doFingerPrint(context, cryptoObject!!
                    , cancellationSignal!!, object : FingerprintManagerCompat.AuthenticationCallback() {
                // 验证出错回调指纹传感器会关闭一段时间,在下次调用authenticate时,会出现禁用期(时间
                // 依厂商不同30,1分都有)
                // 这个接口会在系统指纹认证出现不可恢复的错误的时候才会调用，并且参数errorCode就给
                // 出了错误码，标识了错误的原因。
                override fun onAuthenticationError(errMsgId: Int, errString: CharSequence?) {
                    super.onAuthenticationError(errMsgId, errString)
                    setStyle("请重新尝试指纹识别", STYLE_VERI)
                }

                // 出现了可以恢复的异常才会调用的。什么是可以恢复的异常呢？
                // 一个常见的例子就是：手指移动太快，当我们把手指放到传感器上的时候，如果我们很
                // 快地将手指移走的话，那么指纹传感器可能只采集了部分的信息，因此认证会失败。但
                // 是这个错误是可以恢复的，因此只要提示用户再次按下指纹，并且不要太快移走就可以
                // 解决。
                override fun onAuthenticationHelp(helpMsgId: Int, helpString: CharSequence?) {
                    super.onAuthenticationHelp(helpMsgId, helpString)
                    setStyle(helpString!!.toString(), STYLE_WARN)
                }

                // 认证成功回调
                override fun onAuthenticationSucceeded(result: FingerprintManagerCompat.AuthenticationResult?) {
                    super.onAuthenticationSucceeded(result)
                    // 对称方式认证
                    Authentication()

                    // 非对称方式认证
                    // AsymAuthentication()
                }

                // 认证失败是指所有的信息都采集完整，并且没有任何异常，但是这个指纹和之前注册的
                // 指纹是不相符的；但是认证错误是指在采集或者认证的过程中出现了错误，比如指纹传
                // 感器工作异常等。也就是说认证失败是一个可以预期的正常情况，而认证错误是不可预
                // 期的异常情况。
                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    setStyle("指纹识别失败", STYLE_ERROR)
                }
            })
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    /**
     * 对称方式认证
     * 身份认证成功之后对加密的数据进行数据校验。
     */
    private fun Authentication(){
        try {
            // CryptoObject不是null的话，那么我们在这个方法中可以通过AuthenticationResult
            // 来获得Cypher对象然后调用它的doFinal方法。
            // doFinal方法会检查结果是不是拦截或者篡改过，如果是的话会抛出一个异常。
            // 当我们发现这些异常的时候都应该将认证当做是失败来来处理
//                        result?.cryptoObject?.cipher?.doFinal()

            setStyle("指纹识别成功", STYLE_SUCCESS)

            // 延迟关闭指纹扫描
            Handler().postDelayed({
                cancellationSignal?.cancel()
                cancellationSignal = null
                dialog!!.dismiss()
            }, 1000)
        } catch (e: Exception) {
            e.printStackTrace()
            setStyle("指纹识别失败", STYLE_ERROR)
        }
    }

    /**
     * 非对称方式认证
     * 身份认证成功之后把加密的数据发送给服务器进行数据校验。
     */
    private fun AsymAuthentication(){
        var mStoreBackend: StoreBackend = StoreBackendImpl()
        val signature = cryptoObject!!.getSignature()
        // Include a client nonce in the transaction so that the nonce is also signed by the private
        // key and the backend can verify that the same nonce can't be used to prevent replay
        // attacks.
        // Transaction 是发送到后台的数据类，最后一个参数是为了避免重复。
        val transaction = Transaction("user", 1, SecureRandom().nextLong())
        try {
            signature.update(transaction.toByteArray())
            val sigBytes = signature.sign()// 生产签名后的数据
            if (mStoreBackend.verify(transaction, sigBytes)) { // 模拟后端使用公钥验证已签名的数据

            } else {

            }
        } catch (e: SignatureException) {
            throw RuntimeException(e)
        }

    }

    /**
     * 弹窗样式
     *
     * @param msg
     * @param style
     */
    private fun setStyle(msg: String, style: Int) {
        tvDialogText!!.text = msg
        when (style) {
            STYLE_ERROR -> {
                tvDialogText!!.setTextColor(DrawableKitUtils.getColorSrc(context, COLOR_ERROR))
                DrawableKitUtils.setDrawableTintColor(context, ivDialogIcon!!.drawable, COLOR_ERROR)
            }
            STYLE_WARN -> {
                tvDialogText!!.setTextColor(DrawableKitUtils.getColorSrc(context, COLOR_WARN))
                DrawableKitUtils.removeDrawableTintColor(ivDialogIcon!!.drawable)
            }
            STYLE_SUCCESS -> {
                tvDialogText!!.setTextColor(DrawableKitUtils.getColorSrc(context, COLOR_SUCCESS))
                DrawableKitUtils.setDrawableTintColor(context, ivDialogIcon!!.drawable, COLOR_SUCCESS)
            }
            STYLE_VERI -> {
                tvDialogText!!.setTextColor(DrawableKitUtils.getColorSrc(context, R.color.white_gray))
                DrawableKitUtils.removeDrawableTintColor(ivDialogIcon!!.drawable)
            }
            else -> {
                tvDialogText!!.setTextColor(DrawableKitUtils.getColorSrc(context, R.color.white_gray))
                DrawableKitUtils.removeDrawableTintColor(ivDialogIcon!!.drawable)
            }
        }
    }

    companion object {
        // 指纹识别成功
        private const val STYLE_SUCCESS = 1
        // 指纹识别失败
        private const val STYLE_ERROR = 2
        // 指纹重试多次
        private const val STYLE_WARN = 3
        // 指纹验证
        private const val STYLE_VERI = 4

        private const val COLOR_SUCCESS = R.color.green
        private const val COLOR_ERROR = R.color.red
        private const val COLOR_WARN = R.color.yellow
    }
}
