package com.haseeb.emulator.model

enum class QualityPreset(val heightPx: Int, val label: String) {
    P360(360, "360p"),
    P540(540, "540p"),
    P720(720, "720p"),
}

enum class RefreshRateOption(val hz: Int) {
    HZ_30(30),
    HZ_45(45),
    HZ_60(60),
    HZ_90(90),
    HZ_120(120),
}

enum class AppLanguage(val code: String, val displayName: String) {
    ENGLISH("en", "English"),
    HINDI("hi", "हिन्दी (Hindi)"),
}

enum class AppThemeMode(val label: String) {
    DARK_GLASS("Dark Glass"),
    AMOLED_OBSIDIAN("AMOLED Obsidian"),
}

data class DeviceProfile(
    val id: String,
    val displayName: String,
    val model: String,
    val brand: String,
    val manufacturer: String,
    val device: String,
    val name: String,
    val marketname: String,
    val fingerprint: String,
) {
    companion object {
        val ALL: List<DeviceProfile> = listOf(
            DeviceProfile(
                id = "galaxy_s25_ultra",
                displayName = "Galaxy S25 Ultra",
                model = "SM-S938B",
                brand = "samsung",
                manufacturer = "samsung",
                device = "pa3q",
                name = "pa3qxxx",
                marketname = "Galaxy S25 Ultra",
                fingerprint = "samsung/pa3qxxx/pa3q:10/QP1A.190711.020/S938BXXU1:user/release-keys",
            ),
            DeviceProfile(
                id = "redmagic_10_pro",
                displayName = "RedMagic 10 Pro",
                model = "NX789J",
                brand = "nubia",
                manufacturer = "nubia",
                device = "NX789J",
                name = "NX789J",
                marketname = "REDMAGIC 10 Pro",
                fingerprint = "nubia/NX789J/NX789J:10/QKQ1.200816.002/10.0.1:user/release-keys",
            ),
            DeviceProfile(
                id = "rog_phone_9",
                displayName = "ROG Phone 9",
                model = "ASUS_AI2501",
                brand = "asus",
                manufacturer = "asus",
                device = "ASUS_AI2501",
                name = "WW_AI2501",
                marketname = "ROG Phone 9",
                fingerprint = "asus/WW_AI2501/ASUS_AI2501:10/QKQ1.200830.002/35.0810:user/release-keys",
            ),
            DeviceProfile(
                id = "iqoo_13",
                displayName = "iQOO 13",
                model = "V2408A",
                brand = "vivo",
                manufacturer = "vivo",
                device = "PD2408",
                name = "PD2408",
                marketname = "iQOO 13",
                fingerprint = "vivo/PD2408/PD2408:10/QP1A.190711.020/compiler:user/release-keys",
            ),
            DeviceProfile(
                id = "oneplus_13",
                displayName = "OnePlus 13",
                model = "PJZ110",
                brand = "OnePlus",
                manufacturer = "OnePlus",
                device = "OP5D0DL1",
                name = "PJZ110",
                marketname = "OnePlus 13",
                fingerprint = "OnePlus/PJZ110/OP5D0DL1:10/QKQ1.190711.002/241031:user/release-keys",
            ),
            DeviceProfile(
                id = "poco_f7_pro",
                displayName = "Poco F7 Pro",
                model = "24117RK2CG",
                brand = "POCO",
                manufacturer = "Xiaomi",
                device = "zorn",
                name = "zorn_global",
                marketname = "POCO F7 Pro",
                fingerprint = "POCO/zorn_global/zorn:10/QKQ1.190825.002/V12.0.4:user/release-keys",
            ),
            DeviceProfile(
                id = "xiaomi_15",
                displayName = "Xiaomi 15",
                model = "24129PN74G",
                brand = "Xiaomi",
                manufacturer = "Xiaomi",
                device = "dada",
                name = "dada_global",
                marketname = "Xiaomi 15",
                fingerprint = "Xiaomi/dada_global/dada:10/QKQ1.190825.002/V12.0.5:user/release-keys",
            ),
        )
    }
}

data class GameProfile(
    val packageName: String,
    val appLabel: String,
    val deviceProfileId: String,
    val quality: QualityPreset,
    val refreshRate: RefreshRateOption,
    val showFpsOverlay: Boolean,
)

data class GamingLaunchConfig(
    val system: VmSystem,
    val profile: DeviceProfile,
    val quality: QualityPreset,
    val refreshRate: RefreshRateOption,
    val guestWidth: Int,
    val guestHeight: Int,
    val densityDpi: Int,
    val ramMb: Int = 1024,
    val gpuEnabled: Boolean = true,
    val guestNavBarOff: Boolean = true,
    val showFpsOverlay: Boolean = true,
    val activePackageName: String? = null,
)

data class VmSystem(
    val id: String,
    val name: String,
    val androidVersion: String,
    val apiLevel: Int,
    val arch: String,
    val hasMagisk: Boolean,
    val sha256Verified: Boolean,
    val romMarker: String,
    val systemImagePath: String,
    val bootImagePath: String,
    val systemSha256: String,
    val bootSha256: String,
    val sizeBytes: Long,
    val lastBootEpochMs: Long?,
    val installedAtEpochMs: Long,
) {
    val rootDirectory: String
        get() = java.io.File(systemImagePath).parent ?: ""
}

sealed interface RomInstallStage {
    data object Idle : RomInstallStage
    data class Downloading(
        val progressPercent: Int,
        val downloadedLabel: String,
    ) : RomInstallStage
    data object VerifyingSha256 : RomInstallStage
    data object Extracting : RomInstallStage
    data object Importing : RomInstallStage
    data object BuildingEngineRom : RomInstallStage
    data class Completed(val systemName: String) : RomInstallStage
    data class Failed(val reason: String) : RomInstallStage
}

data class AppSettingsState(
    val language: AppLanguage = AppLanguage.ENGLISH,
    val themeMode: AppThemeMode = AppThemeMode.DARK_GLASS,
    val defaultDeviceProfileId: String = DeviceProfile.ALL.first().id,
    val defaultQuality: QualityPreset = QualityPreset.P720,
    val defaultRefreshRate: RefreshRateOption = RefreshRateOption.HZ_60,
    val defaultRamMb: Int = 1024,
    val magiskPromptEnabled: Boolean = true,
    val fpsOverlayDefault: Boolean = true,
    val githubRepoSlug: String = HomeUiState.DEFAULT_GITHUB_REPO,
    val romReleaseTag: String = HomeUiState.DEFAULT_ROM_TAG,
    val updateCheckStatus: String? = null,
    val isCheckingUpdates: Boolean = false,
)

data class PhoneTelemetryState(
    val running: Boolean = false,
    val model: String = "SM-S938B",
    val marketname: String = "Galaxy S25 Ultra",
    val glRenderer: String = "Haseeb SoftGLES 3.0 CPU (ARM64 No-EGL)",
    val guestFps: Float = 0f,
    val drawCalls: Long = 0L,
    val triangles: Long = 0L,
    val framesSwapped: Long = 0L,
    val magiskDetected: Boolean = false,
    val magiskVersion: String = "27.0",
    val suGrants: Int = 0,
    val lastSuCaller: String = "",
    val batteryPct: Int = 88,
    val charging: Boolean = false,
    val batteryTempC: Float = 34.2f,
    val socTempC: Float = 36.2f,
    val accelX: Float = 0f,
    val accelY: Float = 0f,
    val accelZ: Float = 9.81f,
    val gyroX: Float = 0f,
    val gyroY: Float = 0f,
    val gyroZ: Float = 0f,
    val magX: Float = 22.4f,
    val magY: Float = -14.8f,
    val magZ: Float = 41.2f,
    val lightLux: Float = 350f,
    val proximityCm: Float = 5f,
    val pressureHpa: Float = 1013.25f,
    val cameraFrames: Long = 0L,
    val audioPlayFrames: Long = 0L,
    val netTxPackets: Long = 0L,
    val netRxPackets: Long = 0L,
    val dnsQueries: Long = 0L,
    val sharedStorageRoot: String = "",
    val activeBinary: String = "idle",
    val bootStage: String = "IDLE",
    val effectiveRamMb: Int = 0,
    val instructionsExecuted: Long = 0L,
    val lastTrap: String = "",
    val exitCode: Int = 0,
    val activeTasks: Int = 0,
    val frameworkServices: List<String> = emptyList(),
)

enum class VmSessionViewMode {
    DISPLAY,
    SPLIT,
    CONSOLE,
}

data class HomeUiState(
    val systems: List<VmSystem> = emptyList(),
    val showFirstLaunchOffer: Boolean = true,
    val installStage: RomInstallStage = RomInstallStage.Idle,
    val gamingDialogSystem: VmSystem? = null,
    val activeLaunchConfig: GamingLaunchConfig? = null,
    val gameProfiles: List<GameProfile> = emptyList(),
    val settings: AppSettingsState = AppSettingsState(),
    val qemuLogTail: String = "",
    val guestLogTail: String = "",
    val vmErrorMessage: String? = null,
    val selectedDeviceProfileId: String = DeviceProfile.ALL.first().id,
    val isVmRunning: Boolean = false,
    val vmSessionVisible: Boolean = false,
    val sessionViewMode: VmSessionViewMode = VmSessionViewMode.SPLIT,
    val vmExitCode: Int = 0,
    val isBooting: Boolean = false,
    val bootStage: String = "IDLE",
    val bootStageDetail: String = "",
    val tunedRamMb: Int = 0,
    val hostAvailableRamMb: Long = 0L,
    val hostTotalRamMb: Long = 0L,
    val bootElapsedSec: Int = 0,
    val bootTraceTail: String = "",
    val lastTrapSummary: String = "",
    val activeSystem: VmSystem? = null,
    val showTelemetrySheet: Boolean = false,
    val telemetry: PhoneTelemetryState = PhoneTelemetryState(),
    val bootPatchTargetSystemId: String? = null,
    val bootPatchBanner: String? = null,
) {
    companion object {
        const val DEFAULT_GITHUB_REPO = "haseeb-gaming/haseeb-gaming-android"
        const val DEFAULT_ROM_TAG = "rom-a10-v1"
        const val EXPECTED_ROM_MARKER = "haseeb-gaming-a10-v1"
    }
}
