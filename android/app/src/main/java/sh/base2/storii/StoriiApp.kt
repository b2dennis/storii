package sh.base2.storii

import android.app.Application
import android.content.Context
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import sh.base2.storii.data.Vault

/** Holds the vault for the app, its autofill service and activities, and locks it after time in the background. */
class StoriiApp : Application() {
    lateinit var vault: Vault
        private set
    /** Outlives activities and the autofill service, which Android unbinds as soon as it has answered. */
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var backgroundSince = 0L

    override fun onCreate() {
        super.onCreate()
        vault = Vault(this)
        ProcessLifecycleOwner.get().lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onStop(owner: LifecycleOwner) {
                backgroundSince = System.currentTimeMillis()
            }

            override fun onStart(owner: LifecycleOwner) {
                checkLock()
            }
        })
    }

    /** Lock when the app has been in the background longer than the timeout. Called again by autofill requests. */
    fun checkLock() {
        val minutes = lockMinutes(this)
        if (backgroundSince > 0 && minutes > 0 && System.currentTimeMillis() - backgroundSince > minutes * 60_000L) vault.lock()
    }

    companion object {
        fun lockMinutes(ctx: Context) = ctx.getSharedPreferences("settings", MODE_PRIVATE).getInt("lockMinutes", 5)
        fun setLockMinutes(ctx: Context, m: Int) = ctx.getSharedPreferences("settings", MODE_PRIVATE).edit().putInt("lockMinutes", m).apply()
    }
}

val Context.vault: Vault get() = (applicationContext as StoriiApp).vault
