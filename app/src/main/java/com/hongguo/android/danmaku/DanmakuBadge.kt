// SPDX-License-Identifier: GPL-3.0-only
package com.hongguo.android.danmaku

import java.util.Locale

/**
 * 高赞弹幕的点赞数展示规则：50 起显示，并分档压缩，避免长数字占满屏幕。
 *
 * 50~99 显示 `50+`；100~999 向下取整到百位加号（456 → `400+`）；
 * 1000 以上用 k（3485 → `3.5k`）；10000 以上用 w（12333 → `1.2w`）。
 */
internal object DanmakuBadge {
    /** 展示门槛：低于这个数不显示。 */
    const val MIN_COUNT = 50

    fun show(count: Int): Boolean = count >= MIN_COUNT

    /** 展示用的文案；低于门槛返回 null，调用方据此决定是否画徽章。 */
    fun label(count: Int): String? = if (show(count)) format(count) else null

    fun format(count: Int): String = when {
        count < 100 -> "${(count / 10) * 10}+"
        count < 1_000 -> "${(count / 100) * 100}+"
        count < 10_000 -> String.format(Locale.ROOT, "%.1fk", count / 1_000f)
        else -> String.format(Locale.ROOT, "%.1fw", count / 10_000f)
    }
}
