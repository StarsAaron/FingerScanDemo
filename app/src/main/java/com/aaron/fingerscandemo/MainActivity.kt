package com.aaron.fingerscandemo

import android.os.Build
import android.os.Bundle
import android.support.v7.app.AppCompatActivity

import com.aaron.fingerscandemo.dialog.FingerScanDialog
import com.aaron.fingerscandemo.utils.FingerScanUtils
import kotlinx.android.synthetic.main.activity_main.*
import org.jetbrains.anko.toast


class MainActivity : AppCompatActivity(){

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        initListener()
    }

    private fun initListener() {
        btn_main_finger_support.setOnClickListener{
            // 检查是否支持指纹
            if (FingerScanUtils.isHardWareDetected(this)) toast("支持") else toast("不支持")
        }
        btn_main_finger_set.setOnClickListener{
            // 检查是否设置指纹
            if (FingerScanUtils.hasEnrolledFingerPrint(this)) toast("已设置") else toast("未设置")
        }
        btn_main_finger_sdk.setOnClickListener{
            // 检查当前手机版本
            if (Build.VERSION.SDK_INT > Build.VERSION_CODES.LOLLIPOP_MR1) toast("大于22") else toast("小于22")
        }
        btn_main_finger_pin.setOnClickListener{
            // 检查是否设置图案锁
            if (FingerScanUtils.isKeyguardSecure(this)) toast("已设置图案锁") else toast("未设置图案锁")
        }
        btn_main_finger_veri.setOnClickListener{
            // 检查指纹
            if (!FingerScanUtils.isHardWareDetected(this)) {
                toast("暂不支持指纹")
                return@setOnClickListener
            }

            if (!FingerScanUtils.hasEnrolledFingerPrint(this)) {
                toast("请先设置指纹")
                return@setOnClickListener
            }

            FingerScanDialog(this).showDialog()
        }
    }
}
