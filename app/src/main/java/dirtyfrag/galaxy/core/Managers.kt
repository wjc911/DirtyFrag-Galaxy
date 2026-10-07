package dirtyfrag.galaxy.core

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import java.security.MessageDigest

/** Supported root backends. */
enum class RootBackend(val label: String, val ksudAsset: String) {
    AUTO("자동", "ksud"),
    KERNELSU("KernelSU", "ksud"),
    KSU_NEXT("KernelSU Next", "ksud_next")
}

/**
 * A detected manager app. `pkg` is the installed package name (random for
 * KernelSU Next "spoofed" builds), `backend` is the family, `spoof` marks a
 * randomized-package build.
 */
data class ManagerInfo(
    val pkg: String,
    val backend: RootBackend,
    val spoof: Boolean = false
) {
    val ksudAsset: String get() = backend.ksudAsset
}

object Managers {

    const val PKG_KERNELSU = "me.weishu.kernelsu"
    const val PKG_KSUNEXT = "com.rifsxd.ksunext"

    /** Signing certificate SHA-256 shared by KernelSU Next standard *and* spoofed builds. */
    const val KSUNEXT_SIGNER_SHA256 =
        "79e590113c4c4c0c222978e413a5faa801666957b1212a328e46c00c69821bf7"

    private fun signerSha256(pi: PackageInfo): String? {
        val cert = try {
            val si = if (android.os.Build.VERSION.SDK_INT >= 28) pi.signingInfo else null
            val signers = if (si != null) si.apkContentsSigners
            else @Suppress("DEPRECATION") pi.signatures
            signers?.firstOrNull() ?: return null
        } catch (_: Throwable) {
            return null
        }
        return MessageDigest.getInstance("SHA-256").digest(cert.toByteArray())
            .joinToString("") { "%02x".format(it) }
    }

    private fun installed(ctx: Context): List<PackageInfo> = try {
        @Suppress("DEPRECATION")
        ctx.packageManager.getInstalledPackages(PackageManager.GET_SIGNING_CERTIFICATES)
    } catch (_: Throwable) {
        emptyList()
    }

    /** Process-lifetime cache: the full signing-cert package scan is expensive and the
     *  manager set does not change while this app is alive. */
    @Volatile
    private var cache: List<ManagerInfo>? = null

    fun invalidate() {
        cache = null
    }

    /** All installed KernelSU-family managers on the device (cached). */
    @JvmStatic
    fun detect(ctx: Context): List<ManagerInfo> {
        cache?.let { return it }
        synchronized(this) {
            cache?.let { return it }
            return scan(ctx).also { cache = it }
        }
    }

    private fun scan(ctx: Context): List<ManagerInfo> {
        val out = ArrayList<ManagerInfo>()
        for (pi in installed(ctx)) {
            val pkg = pi.packageName
            when {
                pkg == PKG_KERNELSU ->
                    out += ManagerInfo(pkg, RootBackend.KERNELSU)
                pkg == PKG_KSUNEXT ->
                    out += ManagerInfo(pkg, RootBackend.KSU_NEXT, spoof = false)
                else -> if (signerSha256(pi) == KSUNEXT_SIGNER_SHA256)
                    out += ManagerInfo(pkg, RootBackend.KSU_NEXT, spoof = true)
            }
        }
        // Prefer a real (non-spoof) KernelSU Next manager over a spoofed one.
        return out.sortedWith(compareByDescending<ManagerInfo> { it.backend == RootBackend.KSU_NEXT && !it.spoof }
            .thenByDescending { it.backend == RootBackend.KSU_NEXT })
    }

    /**
     * Resolve which manager to target. With AUTO, prefer KernelSU Next (standard then
     * spoofed), falling back to KernelSU, then to a sensible default so a first-run
     * user is guided to install one.
     */
    @JvmStatic
    @JvmOverloads
    fun resolve(ctx: Context, backend: RootBackend = Settings(ctx).backend): ManagerInfo {
        val found = detect(ctx)
        val chosen = when (backend) {
            RootBackend.KERNELSU -> found.firstOrNull { it.backend == RootBackend.KERNELSU }
            RootBackend.KSU_NEXT -> found.firstOrNull { it.backend == RootBackend.KSU_NEXT }
            RootBackend.AUTO -> found.firstOrNull { it.backend == RootBackend.KSU_NEXT }
                ?: found.firstOrNull { it.backend == RootBackend.KERNELSU }
        }
        return chosen ?: when (backend) {
            RootBackend.KSU_NEXT -> ManagerInfo(PKG_KSUNEXT, RootBackend.KSU_NEXT)
            else -> ManagerInfo(PKG_KERNELSU, RootBackend.KERNELSU)
        }
    }

    fun anyInstalled(ctx: Context): Boolean = detect(ctx).isNotEmpty()

    /** Human label for a manager package ("KernelSU" / "KernelSU Next"). */
    @JvmStatic
    fun labelFor(pkg: String?): String =
        if (pkg == PKG_KERNELSU) "KernelSU" else "KernelSU Next"
}
