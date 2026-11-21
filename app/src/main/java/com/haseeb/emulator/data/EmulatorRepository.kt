package com.haseeb.emulator.data

import android.app.ActivityManager
import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.haseeb.emulator.model.AppLanguage
import com.haseeb.emulator.model.AppSettingsState
import com.haseeb.emulator.model.AppThemeMode
import com.haseeb.emulator.model.DeviceProfile
import com.haseeb.emulator.model.GameProfile
import com.haseeb.emulator.model.GamingLaunchConfig
import com.haseeb.emulator.model.HomeUiState
import com.haseeb.emulator.model.QualityPreset
import com.haseeb.emulator.model.RefreshRateOption
import com.haseeb.emulator.model.VmSystem
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.TimeUnit
import kotlin.math.roundToInt

private val Context.emulatorDataStore by preferencesDataStore(name = "haseeb_emulator_settings")

data class HostMemoryBudget(
    val targetRamMb: Int,
    val availableMb: Long,
    val totalMb: Long,
    val lowMemory: Boolean,
)

class EmulatorRepository(private val context: Context) {

    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .build()

    private val profilesFile: File
        get() = File(context.filesDir, "game_profiles.json")

    private object Keys {
        val LANGUAGE = stringPreferencesKey("app_language")
        val THEME_MODE = stringPreferencesKey("theme_mode")
        val DEFAULT_PROFILE = stringPreferencesKey("default_device_profile")
        val DEFAULT_QUALITY = stringPreferencesKey("default_quality")
        val DEFAULT_HZ = intPreferencesKey("default_hz")
        val DEFAULT_RAM_MB = intPreferencesKey("default_ram_mb")
        val MAGISK_PROMPT = booleanPreferencesKey("magisk_su_prompt")
        val FPS_OVERLAY = booleanPreferencesKey("fps_overlay_default")
        val GITHUB_REPO = stringPreferencesKey("github_repo_slug")
        val ROM_TAG = stringPreferencesKey("rom_release_tag")
    }

    val settingsFlow: Flow<AppSettingsState> = context.emulatorDataStore.data.map { prefs ->
        AppSettingsState(
            language = AppLanguage.entries.firstOrNull { it.code == prefs[Keys.LANGUAGE] }
                ?: AppLanguage.ENGLISH,
            themeMode = AppThemeMode.entries.firstOrNull { it.name == prefs[Keys.THEME_MODE] }
                ?: AppThemeMode.DARK_GLASS,
            defaultDeviceProfileId = prefs[Keys.DEFAULT_PROFILE] ?: DeviceProfile.ALL.first().id,
            defaultQuality = QualityPreset.entries.firstOrNull { it.name == prefs[Keys.DEFAULT_QUALITY] }
                ?: QualityPreset.P720,
            defaultRefreshRate = RefreshRateOption.entries.firstOrNull { it.hz == prefs[Keys.DEFAULT_HZ] }
                ?: RefreshRateOption.HZ_60,
            defaultRamMb = prefs[Keys.DEFAULT_RAM_MB] ?: 1024,
            magiskPromptEnabled = prefs[Keys.MAGISK_PROMPT] ?: true,
            fpsOverlayDefault = prefs[Keys.FPS_OVERLAY] ?: true,
            githubRepoSlug = prefs[Keys.GITHUB_REPO] ?: HomeUiState.DEFAULT_GITHUB_REPO,
            romReleaseTag = prefs[Keys.ROM_TAG] ?: HomeUiState.DEFAULT_ROM_TAG,
        )
    }

    suspend fun updateLanguage(language: AppLanguage) {
        context.emulatorDataStore.edit { it[Keys.LANGUAGE] = language.code }
    }

    suspend fun updateThemeMode(mode: AppThemeMode) {
        context.emulatorDataStore.edit { it[Keys.THEME_MODE] = mode.name }
    }

    suspend fun updateDefaultGamingPreset(
        profileId: String,
        quality: QualityPreset,
        refreshRate: RefreshRateOption,
    ) {
        context.emulatorDataStore.edit {
            it[Keys.DEFAULT_PROFILE] = profileId
            it[Keys.DEFAULT_QUALITY] = quality.name
            it[Keys.DEFAULT_HZ] = refreshRate.hz
        }
    }

    suspend fun setMagiskPromptEnabled(enabled: Boolean) {
        context.emulatorDataStore.edit { it[Keys.MAGISK_PROMPT] = enabled }
    }

    suspend fun setFpsOverlayDefault(enabled: Boolean) {
        context.emulatorDataStore.edit { it[Keys.FPS_OVERLAY] = enabled }
    }

    suspend fun updateGitHubSource(repoSlug: String, releaseTag: String) {
        context.emulatorDataStore.edit {
            it[Keys.GITHUB_REPO] = repoSlug.trim()
            it[Keys.ROM_TAG] = releaseTag.trim()
        }
    }

    suspend fun loadGameProfiles(): List<GameProfile> = withContext(Dispatchers.IO) {
        if (!profilesFile.exists()) {
            val defaults = listOf(
                GameProfile(
                    packageName = "com.tencent.ig",
                    appLabel = "PUBG Mobile / BGMI",
                    deviceProfileId = "redmagic_10_pro",
                    quality = QualityPreset.P720,
                    refreshRate = RefreshRateOption.HZ_120,
                    showFpsOverlay = true,
                ),
                GameProfile(
                    packageName = "com.activision.callofduty.shooter",
                    appLabel = "Call of Duty: Mobile",
                    deviceProfileId = "rog_phone_9",
                    quality = QualityPreset.P720,
                    refreshRate = RefreshRateOption.HZ_90,
                    showFpsOverlay = true,
                ),
            )
            saveGameProfiles(defaults)
            return@withContext defaults
        }

        runCatching {
            val arr = JSONArray(profilesFile.readText())
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                GameProfile(
                    packageName = o.getString("packageName"),
                    appLabel = o.optString("appLabel", o.getString("packageName")),
                    deviceProfileId = o.optString("deviceProfileId", DeviceProfile.ALL.first().id),
                    quality = QualityPreset.entries.firstOrNull { it.name == o.optString("quality") }
                        ?: QualityPreset.P720,
                    refreshRate = RefreshRateOption.entries.firstOrNull { it.hz == o.optInt("refreshRate") }
                        ?: RefreshRateOption.HZ_60,
                    showFpsOverlay = o.optBoolean("showFpsOverlay", true),
                )
            }
        }.getOrElse { emptyList() }
    }

    suspend fun upsertGameProfile(profile: GameProfile): List<GameProfile> = withContext(Dispatchers.IO) {
        val current = loadGameProfiles().filterNot { it.packageName == profile.packageName }
        val updated = listOf(profile) + current
        saveGameProfiles(updated)
        updated
    }

    suspend fun deleteGameProfile(packageName: String): List<GameProfile> = withContext(Dispatchers.IO) {
        val updated = loadGameProfiles().filterNot { it.packageName == packageName }
        saveGameProfiles(updated)
        updated
    }

    private fun saveGameProfiles(profiles: List<GameProfile>) {
        val arr = JSONArray()
        profiles.forEach { p ->
            arr.put(
                JSONObject().apply {
                    put("packageName", p.packageName)
                    put("appLabel", p.appLabel)
                    put("deviceProfileId", p.deviceProfileId)
                    put("quality", p.quality.name)
                    put("refreshRate", p.refreshRate.hz)
                    put("showFpsOverlay", p.showFpsOverlay)
                },
            )
        }
        profilesFile.writeText(arr.toString(2))
    }

    suspend fun markLastBoot(system: VmSystem) = withContext(Dispatchers.IO) {
        val metaFile = File(system.rootDirectory, "vm_system.json")
        if (!metaFile.exists()) return@withContext
        runCatching {
            val json = JSONObject(metaFile.readText())
            json.put("lastBootEpochMs", System.currentTimeMillis())
            metaFile.writeText(json.toString(2))
        }
    }

    suspend fun readLogTail(systemRootDir: String?, fileName: String, maxLines: Int = 120): String =
        withContext(Dispatchers.IO) {
            val candidates = buildList {
                if (!systemRootDir.isNullOrBlank()) {
                    add(File(systemRootDir, "logs/$fileName"))
                }
                val systemsDir = File(context.filesDir, "systems")
                systemsDir.listFiles { f -> f.isDirectory }?.forEach { dir ->
                    add(File(dir, "logs/$fileName"))
                }
            }
            val target = candidates.firstOrNull { it.exists() }
                ?: return@withContext "No $fileName entries yet. Boot a VM to stream live logs."
            val lines = target.readLines()
            lines.takeLast(maxLines).joinToString("\n").ifBlank { "(log file is empty)" }
        }

    suspend fun checkRomUpdate(repoSlug: String, currentTag: String): String = withContext(Dispatchers.IO) {
        runCatching {
            val url = "https://api.github.com/repos/$repoSlug/releases/latest"
            val req = Request.Builder()
                .url(url)
                .header("Accept", "application/vnd.github+json")
                .header("User-Agent", "HaseebGaming-Android/1.0")
                .build()
            httpClient.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) {
                    return@use "Unable to check updates (HTTP ${resp.code})"
                }
                val json = JSONObject(resp.body?.string().orEmpty())
                val latestTag = json.optString("tag_name", "")
                if (latestTag.isBlank()) {
                    "No releases published yet at $repoSlug"
                } else if (latestTag == currentTag) {
                    "Up to date ($latestTag)"
                } else {
                    "New ROM release available: $latestTag"
                }
            }
        }.getOrElse { err -> "Update check failed: ${err.message ?: "Network error"}" }
    }

    fun computeAutoTunedRamBudget(requestedRamMb: Int): HostMemoryBudget {
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
        val info = ActivityManager.MemoryInfo()
        val hasInfo = runCatching {
            if (am != null) {
                am.getMemoryInfo(info)
                true
            } else {
                false
            }
        }.getOrDefault(false)

        if (!hasInfo || info.totalMem <= 0L) {
            val safeFallback = requestedRamMb.coerceIn(512, 1024)
            return HostMemoryBudget(
                targetRamMb = safeFallback,
                availableMb = 0L,
                totalMb = 0L,
                lowMemory = false,
            )
        }

        val availMb = (info.availMem / (1024L * 1024L)).coerceAtLeast(0L)
        val totalMb = (info.totalMem / (1024L * 1024L)).coerceAtLeast(0L)
        val clampedReq = requestedRamMb.coerceIn(256, 1536)
        val budget = when {
            info.lowMemory || availMb < 900L -> 512
            availMb < 1600L -> 768
            availMb < 2600L -> 1024
            else -> clampedReq
        }.coerceAtMost(clampedReq.coerceAtLeast(512))

        return HostMemoryBudget(
            targetRamMb = budget,
            availableMb = availMb,
            totalMb = totalMb,
            lowMemory = info.lowMemory,
        )
    }

    companion object {
        /**
         * Calculates guest framebuffer resolution matching the host aspect ratio,
         * aligned to multiples of 8 for VirtIO-GPU scanout compatibility.
         */
        fun buildLaunchConfig(
            system: VmSystem,
            profile: DeviceProfile,
            quality: QualityPreset,
            refreshRate: RefreshRateOption,
            hostWidthPx: Int,
            hostHeightPx: Int,
            showFpsOverlay: Boolean,
            activePackageName: String?,
        ): GamingLaunchConfig {
            val safeHostW = hostWidthPx.coerceAtLeast(360)
            val safeHostH = hostHeightPx.coerceAtLeast(640)
            val isPortrait = safeHostH >= safeHostW
            val shortSide = quality.heightPx
            val aspect = if (isPortrait) {
                safeHostH.toFloat() / safeHostW.toFloat()
            } else {
                safeHostW.toFloat() / safeHostH.toFloat()
            }
            val longSideRaw = (shortSide * aspect).roundToInt()
            val longSideAligned = ((longSideRaw + 7) / 8) * 8
            val shortSideAligned = ((shortSide + 7) / 8) * 8

            val guestW = if (isPortrait) shortSideAligned else longSideAligned
            val guestH = if (isPortrait) longSideAligned else shortSideAligned
            val dpi = when (quality) {
                QualityPreset.P360 -> 160
                QualityPreset.P540 -> 240
                QualityPreset.P720 -> 320
            }

            return GamingLaunchConfig(
                system = system,
                profile = profile,
                quality = quality,
                refreshRate = refreshRate,
                guestWidth = guestW,
                guestHeight = guestH,
                densityDpi = dpi,
                ramMb = 1024,
                gpuEnabled = true,
                guestNavBarOff = true,
                showFpsOverlay = showFpsOverlay,
                activePackageName = activePackageName,
            )
        }
    }
}
