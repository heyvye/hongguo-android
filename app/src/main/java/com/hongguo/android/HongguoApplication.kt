package com.hongguo.android

import android.app.Application
import com.hongguo.account.AccountRepository
import com.hongguo.api.util.Config
import java.security.SecureRandom

class HongguoApplication : Application() {
    /** The media and account requesters share lifecycle, never credentials or device identity. */
    val accountRepository: AccountRepository by lazy { AccountRepository(this) }

    override fun onCreate() {
        super.onCreate()
        val preferences = getSharedPreferences("installation", MODE_PRIVATE)
        val deviceId = preferences.getString("device_id", null) ?: run {
            val random = SecureRandom()
            val number = (random.nextLong().ushr(1) % 9_000_000_000_000_000L) + 1_000_000_000_000_000L
            number.toString().also { preferences.edit().putString("device_id", it).apply() }
        }
        val config = assets.open("upstream.json").bufferedReader().use { it.readText() }
        Config.initialize(config, cacheDir.resolve("media").absolutePath, deviceId)
        // 播放身份落盘目录：一次注册长期复用，避免反复注册消耗身份信誉。
        com.hongguo.api.service.PlaybackDevice.setStoreDir(filesDir)
        // 诊断日志落盘（部分机型会吞掉 logcat）：filesDir/diag.log
        com.hongguo.api.util.Diag.init(filesDir)
    }
}
