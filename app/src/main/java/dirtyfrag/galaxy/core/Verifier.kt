package dirtyfrag.galaxy.core

import android.content.Context
import java.io.File

/** Health / module detection. Detection only — this app never downloads or installs. */
class Verifier(private val ctx: Context) {

    /**
     * One detection snapshot. Everything is derived from a SINGLE batch `su` probe
     * (~150ms on the test device) instead of 20-30 separate su spawns, and every row
     * builder below consumes the snapshot rather than re-probing.
     *
     * `zn` is the parsed `zygiskd status` output (Zygisk-Next only); `lspHits` is the
     * durable LSPosedFramework hit count for the CURRENT system_server pid.
     */
    data class Snapshot(
        val rootPresent: Boolean,
        val su: Boolean,
        val selinux: String,
        val modules: Set<String>,
        val ssPid: String,
        val zn: Map<String, String>,
        val lspHits: Int
    )

    fun device(): DeviceInfo = SysUtil.deviceInfo()

    /** True when the KernelSU-family su userspace is granted to this app (uid 0). */
    fun suGranted(): Boolean {
        // Only used for explicit user re-checks (recheckGrant): a cold boot installs su
        // asynchronously, so retry briefly to avoid a transient false "권한 없음".
        repeat(3) { i ->
            if (SysUtil.isRootGranted()) return true
            if (i < 2) runCatching { Thread.sleep(1500) }
        }
        return false
    }

    /** Ephemeral root present (exploit hook active). */
    fun rootPresent(): Boolean = File("/dev/df").exists()

    fun isInstalled(pkg: String): Boolean = try {
        ctx.packageManager.getPackageInfo(pkg, 0)
        true
    } catch (_: Throwable) {
        false
    }

    /**
     * Fast-fail aware probe. When su is denied the batch script produces no markers, so
     * module / zygisk / LSPosed statuses degrade to their "su 미허용" rows without any
     * further probing (the old 1.5s x3 retry sleeps are gone).
     *
     * `deep` adds a bounded post-soft-restart poll for the LSPosed durable line
     * (0.3s x2) and falls back to a single logcat scan (1.1s) as the last resort.
     */
    fun snapshot(deep: Boolean = true): Snapshot {
        val s = probeOnce()
        if (!deep || !s.su || s.lspHits > 0) return s
        if (s.modules.none { it.contains("lsposed", true) }) return s
        repeat(2) {
            Thread.sleep(300)
            val hits = verboseHits()
            if (hits > 0) return s.copy(lspHits = hits)
        }
        val live = logcatHits(s.ssPid)
        return if (live > 0) s.copy(lspHits = live) else s
    }

    private fun probeOnce(): Snapshot {
        val rootPresent = rootPresent()
        val r = SysUtil.su(PROBE_SCRIPT, 15_000)
        val sec = sections(r.out)
        val su = r.code == 0 && sec["ID"]?.firstOrNull()?.trim() == "0"
        if (!su) return Snapshot(rootPresent, false, "", emptySet(), "", emptyMap(), 0)

        val sel = sec["SEL"].orEmpty().map { it.trim() }
            .firstOrNull { it.equals("Enforcing", true) || it.equals("Permissive", true) }.orEmpty()
        val mods = sec["MODS"].orEmpty().map { it.trim() }.filter { it.isNotEmpty() }.toSet()
        val ssPid = sec["SS"].orEmpty()
            .firstOrNull { it.isNotBlank() }?.trim()?.split(Regex("\\s+"))?.firstOrNull().orEmpty()
        val zn = HashMap<String, String>()
        for (line in sec["ZN"].orEmpty()) {
            val i = line.indexOf(':')
            if (i <= 0) continue
            val k = line.substring(0, i).trim()
            if (k.isEmpty() || k.contains(' ')) continue
            zn[k] = line.substring(i + 1).trim()
        }
        return Snapshot(rootPresent, true, sel, mods, ssPid, zn, parseLsp(sec["LSP"].orEmpty()))
    }

    private fun verboseHits(): Int = parseLsp(SysUtil.su(LSP_SCRIPT, 15_000).out.lineSequence().toList())

    private fun logcatHits(pid: String): Int {
        if (pid.isEmpty()) return 0
        val r = SysUtil.su("logcat -d -s LSPosedFramework:V 2>/dev/null | grep -c \" $pid \"", 10_000)
        return r.out.trim().toIntOrNull() ?: 0
    }

    /**
     * Parse the LSP section (pid/v/up/vm/hits) and apply the mtime >= boot-time guard.
     * `up` (uptime) is captured inside the su script: untrusted_app cannot read
     * /proc/uptime directly on this firmware, which would zero out the freshness check.
     */
    private fun parseLsp(lines: List<String>): Int {
        val m = HashMap<String, String>()
        for (l in lines) {
            val i = l.indexOf('=')
            if (i > 0) m[l.substring(0, i).trim()] = l.substring(i + 1).trim()
        }
        val vm = m["vm"]?.toLongOrNull() ?: 0L
        val up = m["up"]?.toLongOrNull() ?: (android.os.SystemClock.elapsedRealtime() / 1000)
        val bootEpoch = System.currentTimeMillis() / 1000 - up
        val fresh = vm > 0 && vm >= bootEpoch - 5
        return if (fresh) m["hits"]?.toIntOrNull() ?: 0 else 0
    }

    /** Split "#MARK" delimited output into sections. */
    private fun sections(out: String): Map<String, List<String>> {
        val map = LinkedHashMap<String, MutableList<String>>()
        var cur: MutableList<String>? = null
        for (raw in out.lineSequence()) {
            val line = raw.trimEnd()
            if (line.length in 2..6 && line.startsWith("#") && line.drop(1).all { it.isUpperCase() }) {
                cur = map.getOrPut(line.drop(1)) { mutableListOf() }
            } else cur?.add(line)
        }
        return map
    }

    fun root(s: Snapshot): HealthStatus {
        val ok = s.rootPresent || s.su
        val detail = when {
            s.rootPresent && s.su -> "/dev/df + su uid=0"
            s.rootPresent -> "/dev/df present (su 미허용)"
            s.su -> "su uid=0"
            else -> "no root"
        }
        return HealthStatus(Health.ROOT, ok, detail)
    }

    /**
     * SELinux state — informational, NOT a success gate. The su probe captures
     * `getenforce`; the app (unprivileged) may still fall back to reading the
     * sysfs node, and "unknown" is surfaced rather than treated as a failure.
     */
    fun selinux(s: Snapshot): HealthStatus {
        val ge = s.selinux
        val enf = SysUtil.readFile("/sys/fs/selinux/enforce")?.trim()
        val enforcing = ge.equals("Enforcing", true) || enf == "1"
        val permissive = ge.equals("Permissive", true) || enf == "0"
        val detail = when {
            ge.isNotEmpty() -> ge
            permissive -> "Permissive"
            enforcing -> "Enforcing"
            else -> "미확인"
        }
        return HealthStatus(Health.PERMISSIVE, enforcing || permissive, detail)
    }

    /** Module ids that indicate a zygisk provider. Zygisk-Next ships as "zygisksu". */
    private val zygiskModIds = setOf("zygisksu", "rezygisk", "zygisk")

    private fun isZygiskModule(name: String) =
        zygiskModIds.any { name.equals(it, true) } || isUnsupportedZygisk(name)

    /** Light detection only (no injection tracking): known non-supported providers. */
    private fun isUnsupportedZygisk(name: String) =
        name.equals("neozygisk", true) || name.contains("vector", true)

    private fun readModuleName(id: String): String =
        SysUtil.su("grep -m1 '^name=' /data/adb/modules/$id/module.prop 2>/dev/null")
            .out.substringAfter('=', "").trim()

    /**
     * Provider label. Zygisk-Next is the only supported provider and is detected via
     * `zygiskd status` (batch probe) with a ps fallback. Anything else only gets a
     * light name-based label for the "미지원 — 교체 권장" display; no runtime tracking.
     */
    fun zygiskProvider(s: Snapshot): String {
        if (s.zn.isNotEmpty()) return "Zygisk-Next"
        if (!s.su) return ""
        val ps = SysUtil.su("ps -A -o NAME 2>/dev/null | grep -iE 'zygiskd|zn-' | head -1").out
        if (ps.isNotBlank()) return "Zygisk-Next"
        for (id in s.modules) {
            if (!isZygiskModule(id)) continue
            val nm = readModuleName(id)
            return nm.ifBlank { "Zygisk" }
        }
        return ""
    }

    fun zygisk(s: Snapshot): HealthStatus {
        if (!s.su) return HealthStatus(Health.ZYGISK, false, "su 미허용")
        val provider = zygiskProvider(s)
        val mod = s.modules.any { isZygiskModule(it) }
        return when {
            s.zn.isNotEmpty() && s.zn["inject_state"]?.trim() == "1" ->
                HealthStatus(Health.ZYGISK, true, "Zygisk-Next 주입됨")
            s.zn.isNotEmpty() ->
                HealthStatus(Health.ZYGISK, false, "Zygisk-Next 미주입")
            provider == "Zygisk-Next" ->
                HealthStatus(Health.ZYGISK, true, "Zygisk-Next (미주입)")
            provider.isNotEmpty() && mod ->
                HealthStatus(Health.ZYGISK, false, "$provider — 미지원, Zygisk-Next 권장")
            mod ->
                HealthStatus(Health.ZYGISK, true, "모듈 (미주입)")
            else -> HealthStatus(Health.ZYGISK, false, "없음")
        }
    }

    /**
     * LSPosed injected into the CURRENT system_server. Reliable signal: the framework
     * logs under "LSPosedFramework" with the current pid (durable verbose log first,
     * logcat as fallback), matched in the batch probe. The manager app is optional and
     * is never a success gate. Vector is detected light-only and never tracked.
     */
    fun lsposed(s: Snapshot): HealthStatus {
        val hasManager = isInstalled(LSPOSED_MANAGER_PKG)
        val lsposedMod = s.modules.any { it.contains("lsposed", true) }
        val vector = s.modules.any { it.contains("vector", true) }
        if (!s.su) {
            return HealthStatus(
                Health.LSPOSED, false,
                when {
                    lsposedMod -> "미활성 (su 미허용)"
                    vector -> "Vector — 미지원, LSPosed 권장"
                    hasManager -> "manager만 설치 (미활성)"
                    else -> "미설치"
                }
            )
        }
        if (vector && !lsposedMod) {
            return HealthStatus(Health.LSPOSED, false, "Vector — 미지원, LSPosed 권장")
        }
        if (!lsposedMod && !hasManager) return HealthStatus(Health.LSPOSED, false, "미설치")
        return if (s.lspHits > 0) {
            HealthStatus(Health.LSPOSED, true, "LSPosed system_server 주입됨")
        } else {
            HealthStatus(
                Health.LSPOSED, false,
                if (lsposedMod) "LSPosed system_server 미주입" else "manager만 설치 (미활성)"
            )
        }
    }

    fun hook(s: Snapshot): HealthStatus {
        val ok = s.su && s.lspHits > 0
        return HealthStatus(Health.HOOK, ok, if (ok) "framework active" else "미주입")
    }

    fun healthAll(s: Snapshot): List<HealthStatus> =
        listOf(root(s), selinux(s), zygisk(s), lsposed(s), hook(s))

    /** Detected LSPosed-family framework name: "LSPosed" / "Vector(미지원)" / "". */
    fun lsposedFramework(s: Snapshot): String = when {
        s.modules.any { it.contains("lsposed", true) } -> "LSPosed"
        s.modules.any { it.contains("vector", true) } -> "Vector(미지원)"
        isInstalled(LSPOSED_MANAGER_PKG) -> "LSPosed"
        else -> ""
    }

    /** Replacement guidance when an unsupported stack is detected; null when supported. */
    fun unsupportedNote(s: Snapshot): String? {
        if (s.modules.any { it.contains("vector", true) } && s.modules.none { it.contains("lsposed", true) }) {
            return "Vector 감지 — 미지원. Zygisk-Next + LSPosed로 교체 권장"
        }
        val p = zygiskProvider(s)
        if (p.isNotEmpty() && p != "Zygisk-Next" && p != "Zygisk") {
            return "$p 감지 — 미지원. Zygisk-Next + LSPosed로 교체 권장"
        }
        return null
    }

    /** Detection of the 3 recommended modules (manager / LSPosed / Zygisk-Next). */
    fun moduleStatuses(s: Snapshot): List<ModuleStatus> {
        val mgr = Managers.resolve(ctx)
        val manager = isInstalled(mgr.pkg) || Managers.anyInstalled(ctx)
        val lsposedMod = s.modules.any { it.contains("lsposed", true) }
        val vector = s.modules.any { it.contains("vector", true) }
        val zygisk = s.modules.any { isZygiskModule(it) }
        val provider = zygiskProvider(s)
        val noSu = if (s.su) "미설치" else "su 필요"
        val unsupported = "미지원 — Zygisk-Next + LSPosed 권장"
        return listOf(
            ModuleStatus(
                ModuleKind.MANAGER,
                if (manager) ModuleState.INSTALLED else ModuleState.NOT_INSTALLED,
                if (manager) mgr.pkg else "미설치"
            ),
            ModuleStatus(
                ModuleKind.LSPOSED,
                if (lsposedMod) ModuleState.INSTALLED else ModuleState.NOT_INSTALLED,
                when {
                    lsposedMod -> "LSPosed 모듈"
                    vector -> "Vector 감지 — $unsupported"
                    isInstalled(LSPOSED_MANAGER_PKG) -> "모듈 설치 필요"
                    else -> noSu
                }
            ),
            ModuleStatus(
                ModuleKind.ZYGISK,
                if (zygisk) ModuleState.INSTALLED else ModuleState.NOT_INSTALLED,
                when {
                    !zygisk -> noSu
                    provider == "Zygisk-Next" -> "Zygisk-Next"
                    provider.isNotEmpty() -> "$provider — $unsupported"
                    else -> "Zygisk — $unsupported"
                }
            )
        )
    }

    private companion object {
        /** Batch probe: uid / SELinux / modules / system_server pid / ZN status / LSP hits. */
        val PROBE_SCRIPT = """
            echo "#ID"; id -u
            echo "#SEL"; getenforce 2>/dev/null
            echo "#MODS"; ls /data/adb/modules 2>/dev/null
            echo "#SS"; pidof system_server 2>/dev/null
            echo "#ZN"; if [ -x /data/adb/modules/zygisksu/bin/zygiskd ]; then /data/adb/modules/zygisksu/bin/zygiskd status 2>/dev/null | head -20; fi
            echo "#LSP"
            pid=${'$'}(pidof system_server 2>/dev/null)
            v=${'$'}(ls -t /data/adb/lspd/log/verbose_*.log 2>/dev/null | head -1)
            echo "pid=${'$'}pid"
            echo "v=${'$'}v"
            echo "up=${'$'}(cut -d. -f1 /proc/uptime 2>/dev/null)"
            if [ -n "${'$'}pid" ] && [ -n "${'$'}v" ]; then
              echo "vm=${'$'}(stat -c %Y "${'$'}v" 2>/dev/null)"
              echo "hits=${'$'}(grep -c " ${'$'}pid: .*LSPosedFramework" "${'$'}v" 2>/dev/null)"
            fi
            echo "#END"
        """.trimIndent()

        /** Durable LSPosed re-check only (post-soft-restart poll). */
        val LSP_SCRIPT = """
            pid=${'$'}(pidof system_server 2>/dev/null)
            v=${'$'}(ls -t /data/adb/lspd/log/verbose_*.log 2>/dev/null | head -1)
            echo "pid=${'$'}pid"
            echo "v=${'$'}v"
            echo "up=${'$'}(cut -d. -f1 /proc/uptime 2>/dev/null)"
            if [ -n "${'$'}pid" ] && [ -n "${'$'}v" ]; then
              echo "vm=${'$'}(stat -c %Y "${'$'}v" 2>/dev/null)"
              echo "hits=${'$'}(grep -c " ${'$'}pid: .*LSPosedFramework" "${'$'}v" 2>/dev/null)"
            fi
        """.trimIndent()
    }
}
