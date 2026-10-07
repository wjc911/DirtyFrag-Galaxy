package dirtyfrag.galaxy.core

import android.content.Context
import android.content.SharedPreferences

/** Simple SharedPreferences-backed settings store. */
class Settings(context: Context) {

    private val sp: SharedPreferences =
        context.applicationContext.getSharedPreferences("dirtyfrag_galaxy", Context.MODE_PRIVATE)

    var autoRootOnBoot: Boolean
        get() = sp.getBoolean(KEY_AUTO_ROOT, false)
        set(v) = sp.edit().putBoolean(KEY_AUTO_ROOT, v).apply()

    /**
     * Default OFF for a fresh install, but fully persisted once the user flips it.
     * (The previous default=ON caused a soft-reboot loop on devices where the
     * exploit leaves SELinux enforcing and the old permissive gate could never pass.)
     */
    var autoSoftRestart: Boolean
        get() = sp.getBoolean(KEY_AUTO_SOFT_RESTART, false)
        set(v) = sp.edit().putBoolean(KEY_AUTO_SOFT_RESTART, v).apply()

    /** Restore SELinux to Enforcing once root + modules + LSPosed are confirmed. Default ON. */
    var restoreEnforcing: Boolean
        get() = sp.getBoolean(KEY_RESTORE_ENFORCING, true)
        set(v) = sp.edit().putBoolean(KEY_RESTORE_ENFORCING, v).apply()

    /** How many soft reboots we have issued while trying to activate LSPosed. */
    var activationAttempts: Int
        get() = sp.getInt(KEY_ACTIVATION_ATTEMPTS, 0)
        // commit() (synchronous): the app is killed by the soft reboot right after, so an
        // async apply() can be lost and the activation loop would never terminate.
        set(v) { sp.edit().putInt(KEY_ACTIVATION_ATTEMPTS, v).commit() }

    /** Preferred root backend. AUTO prefers KernelSU Next when installed. */
    var backend: RootBackend
        get() = runCatching { RootBackend.valueOf(sp.getString(KEY_BACKEND, RootBackend.AUTO.name)!!) }
            .getOrDefault(RootBackend.AUTO)
        set(v) = sp.edit().putString(KEY_BACKEND, v.name).apply()

    /**
     * Absolute path of the Samsung-patched ksud staged by the exploit. Persisted so a
     * cold app launch / notification soft restart can restore OUR ksud instead of the
     * manager's bundled one (which lacks the rescue-party fix and NeoZygisk wait).
     */
    var stagedKsudPath: String
        get() = sp.getString(KEY_STAGED_KSUD, "") ?: ""
        set(v) = sp.edit().putString(KEY_STAGED_KSUD, v).apply()

    fun options() = Options(
        autoRootOnBoot = autoRootOnBoot,
        autoSoftRestart = autoSoftRestart,
        restoreEnforcing = restoreEnforcing
    )

    companion object {
        private const val KEY_AUTO_ROOT = "auto_root_on_boot"
        private const val KEY_AUTO_SOFT_RESTART = "auto_soft_restart"
        private const val KEY_RESTORE_ENFORCING = "restore_enforcing"
        private const val KEY_ACTIVATION_ATTEMPTS = "activation_attempts"
        private const val KEY_BACKEND = "root_backend"
        private const val KEY_STAGED_KSUD = "staged_ksud_path"
    }
}
