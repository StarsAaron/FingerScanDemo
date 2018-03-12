package com.aaron.fingerscandemo.utils

import android.content.Context
import android.graphics.Color
import android.graphics.PorterDuff
import android.graphics.drawable.Drawable
import android.os.Build
import android.support.v4.graphics.drawable.DrawableCompat

/**
 * 描述：DrawableCompat图片变颜色工具
 */
object DrawableKitUtils {

    fun getImgDrawable(context: Context, drawableSrc: Int): Drawable? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            context.getDrawable(drawableSrc)
        } else {
            context.resources.getDrawable(drawableSrc)
        }
    }

    /**
     * 给指定的drawable进行着色
     *
     * @param drawable  待着色的drawable
     * @param tintColor 需要着色的颜色
     */
    fun setDrawableTintColor(context: Context, drawable: Drawable, tintColor: Int) {
        drawable?.let {
            //经测试，安卓4.4以上和一下设置着色的方式不一样
            if (Build.VERSION.SDK_INT > Build.VERSION_CODES.KITKAT) {
                DrawableCompat.setTint(drawable, getColorSrc(context, tintColor))
                DrawableCompat.setTintMode(drawable, PorterDuff.Mode.SRC_ATOP)
            } else {
                drawable.setColorFilter(getColorSrc(context, tintColor), PorterDuff.Mode.SRC_ATOP)
            }
        }
    }

    /**
     * 去掉指定的drawable的着色
     *
     * @param drawable
     */
    fun removeDrawableTintColor(drawable: Drawable) {
        drawable?.let {
            if (Build.VERSION.SDK_INT > Build.VERSION_CODES.KITKAT) {
                DrawableCompat.setTint(drawable, Color.TRANSPARENT)
                DrawableCompat.setTintMode(drawable, PorterDuff.Mode.SRC_ATOP)
            } else {
                drawable.setColorFilter(Color.TRANSPARENT, PorterDuff.Mode.SRC_ATOP)
            }
        }
    }

    fun getColorSrc(context: Context, colorSrc: Int): Int {
        return context.resources.getColor(colorSrc)
    }
}
