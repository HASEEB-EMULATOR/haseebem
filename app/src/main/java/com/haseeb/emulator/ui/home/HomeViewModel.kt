package com.haseeb.emulator.ui.home

import android.app.Application
import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioTrack
import android.net.Uri
import android.view.Surface
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.haseeb.emulator.Engine
import com.haseeb.emulator.data.EmulatorRepository
import com.haseeb.emulator.data.RomRepository
import com.haseeb.emulator.model.DeviceProfile
import com.haseeb.emulator.model.HomeUiState
import com.haseeb.emulator.model.PhoneTelemetryState
import com.haseeb.emulator.model.RomInstallStage
import com.haseeb.emulator.model.VmSessionViewMode
import com.haseeb.emulator.model.VmSystem
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.util.concurrent.Executors

class HomeViewModel(application: Application) : AndroidViewModel(application) {
    private val appContext = application.applicationContext
    private val repository = RomRepository(appContext)
    private val emulatorRepository = EmulatorRepository(appContext)

    private val _uiState = MutableStateFlow(HomeUiState())
    val uiState: StateFlow<HomeUiState> = _uiState.asStateFlow()

    private var audioJob: Job? = null
    private var telemetryJob: Job? = null
    private var bootProgressJob: Job? = null
    private val surfaceInputDispatcher = Executors.newSingleThreadExecutor().asCoroutineDispatcher()
    @Volatile
    private var isBootInProgress: Boolean = false

    init {
        viewModelScope.launch {
            refreshSystems()
            val profiles = emulatorRepository.loadGameProfiles()
            _uiState.update { it.copy(gameProfiles = profiles) }
        }
        viewModelScope.launch {
            combine(
                repository.firstLaunchOfferDismissed,
                repository.githubRepoSlug,
                repository.romReleaseTag,
                emulatorRepository.settingsFlow,
            ) { dismissed, repo, tag, settings ->
                Pair(Triple(dismissed, repo, tag), settings)
            }.collect { (romPrefs, settings) ->
                val (dismissed, repo, tag) = romPrefs
                _uiState.update { state ->
                    state.copy(
                        showFirstLaunchOffer = !dismissed && state.systems.isEmpty(),
                        selectedDeviceProfileId = settings.defaultDeviceProfileId,
                        settings = settings.copy(
                            githubRepoSlug = repo,
                            romReleaseTag = tag,
                        ),
                    )
                }
            }
        }
    }

    override fun onCleared() {
        super.onCleared()
        bootProgressJob?.cancel()
        bootProgressJob = null
        stopAudioAndTelemetryLoops()
        surfaceInputDispatcher.close()
    }

    fun refreshSystems() {
        viewModelScope.launch {
            val loaded = repository.loadInstalledSystems()
            _uiState.update { state ->
                state.copy(
                    systems = loaded,
                    showFirstLaunchOffer = state.showFirstLaunchOffer && loaded.isEmpty(),
                )
            }
        }
    }

    fun dismissFirstLaunchOffer() {
        _uiState.update { it.copy(showFirstLaunchOffer = false) }
        viewModelScope.launch {
            repository.setFirstLaunchOfferDismissed(true)
        }
    }

    fun installBundledGamingRom() {
        val st = _uiState.value.installStage
        if (st is RomInstallStage.Downloading ||
            st is RomInstallStage.VerifyingSha256 ||
            st is RomInstallStage.Extracting ||
            st is RomInstallStage.BuildingEngineRom
        ) {
            return
        }

        viewModelScope.launch {
            val result = repository.downloadVerifyAndImportBundledRom { stage ->
                _uiState.update { it.copy(installStage = stage) }
            }
            result.fold(
                onSuccess = { vm ->
                    val updatedSystems = repository.loadInstalledSystems()
                    _uiState.update {
                        it.copy(
                            systems = updatedSystems,
                            showFirstLaunchOffer = false,
                            installStage = RomInstallStage.Completed(vm.name),
                        )
                    }
                },
                onFailure = { error ->
                    _uiState.update {
                        it.copy(
                            installStage = RomInstallStage.Failed(
                                error.message ?: "Unknown network or checksum failure",
                            ),
                        )
                    }
                },
            )
        }
    }

    fun importFirmwareFromUri(uri: Uri) {
        viewModelScope.launch {
            val result = repository.importFirmwareUri(uri) { stage ->
                _uiState.update { it.copy(installStage = stage) }
            }
            result.fold(
                onSuccess = { vm ->
                    val updatedSystems = repository.loadInstalledSystems()
                    _uiState.update {
                        it.copy(
                            systems = updatedSystems,
                            showFirstLaunchOffer = false,
                            installStage = RomInstallStage.Completed(vm.name),
                        )
                    }
                },
                onFailure = { error ->
                    _uiState.update {
                        it.copy(
                            installStage = RomInstallStage.Failed(
                                error.message ?: "Invalid firmware archive",
                            ),
                        )
                    }
                },
            )
        }
    }

    fun buildEngineMagiskRom() {
        val st = _uiState.value.installStage
        if (st is RomInstallStage.Downloading ||
            st is RomInstallStage.VerifyingSha256 ||
            st is RomInstallStage.Extracting ||
            st is RomInstallStage.Importing ||
            st is RomInstallStage.BuildingEngineRom
        ) {
            return
        }

        viewModelScope.launch {
            val result = repository.buildAndRegisterEngineMagiskRom { stage ->
                _uiState.update { it.copy(installStage = stage) }
            }
            result.fold(
                onSuccess = { vm ->
                    val updatedSystems = repository.loadInstalledSystems()
                    _uiState.update {
                        it.copy(
                            systems = updatedSystems,
                            showFirstLaunchOffer = false,
                            installStage = RomInstallStage.Completed(vm.name),
                            bootPatchBanner = "Engine-matched Android 11 + Magisk v27 ready to launch",
                            vmErrorMessage = null,
                        )
                    }
                },
                onFailure = { error ->
                    _uiState.update {
                        it.copy(
                            installStage = RomInstallStage.Failed(
                                error.message ?: "Engine ROM generation failed",
                            ),
                        )
                    }
                },
            )
        }
    }

    fun setSessionViewMode(mode: VmSessionViewMode) {
        _uiState.update { it.copy(sessionViewMode = mode) }
    }

    fun closeVmSession() {
        stopAudioAndTelemetryLoops()
        viewModelScope.launch(Dispatchers.IO) {
            if (Engine.nativeLibraryLoaded && Engine.isRunning()) {
                Engine.stop()
            }
            withContext(Dispatchers.Main) {
                _uiState.update {
                    it.copy(
                        vmSessionVisible = false,
                        isVmRunning = false,
                        isBooting = false,
                        activeSystem = null,
                        vmErrorMessage = null,
                        bootStage = "IDLE",
                        bootStageDetail = "",
                        lastTrapSummary = "",
                        vmExitCode = 0,
                    )
                }
            }
        }
    }

    fun clearInstallStatus() {
        _uiState.update { it.copy(installStage = RomInstallStage.Idle) }
    }

    fun clearBootPatchBanner() {
        _uiState.update { it.copy(bootPatchBanner = null) }
    }

    fun clearVmError() {
        _uiState.update { it.copy(vmErrorMessage = null) }
    }

    fun inspectSystem(system: VmSystem?) {
        _uiState.update { it.copy(gamingDialogSystem = system) }
    }

    fun selectDeviceProfile(profileId: String) {
        val profile = DeviceProfile.ALL.firstOrNull { it.id == profileId } ?: return
        _uiState.update { it.copy(selectedDeviceProfileId = profile.id) }
        viewModelScope.launch {
            val s = _uiState.value.settings
            emulatorRepository.updateDefaultGamingPreset(
                profileId = profile.id,
                quality = s.defaultQuality,
                refreshRate = s.defaultRefreshRate,
            )
            if (Engine.nativeLibraryLoaded) {
                withContext(Dispatchers.IO) {
                    Engine.configureDeviceProfile(
                        model = profile.model,
                        brand = profile.brand,
                        manufacturer = profile.manufacturer,
                        device = profile.device,
                        name = profile.name,
                        marketname = profile.marketname,
                        fingerprint = profile.fingerprint,
                        magiskPromptEnabled = s.magiskPromptEnabled,
                    )
                }
                refreshTelemetryOnce()
            }
        }
    }

    fun attachSurfaceAsync(surface: Surface?) {
        if (!Engine.nativeLibraryLoaded) return
        viewModelScope.launch(surfaceInputDispatcher) {
            Engine.attachSurface(surface)
        }
    }

    fun sendTouchAsync(action: Int, x: Int, y: Int, pointerId: Int) {
        if (!Engine.nativeLibraryLoaded) return
        viewModelScope.launch(surfaceInputDispatcher) {
            Engine.sendTouch(action, x, y, pointerId)
        }
    }

    fun bootSystem(system: VmSystem) {
        if (!Engine.nativeLibraryLoaded) {
            _uiState.update {
                it.copy(vmErrorMessage = Engine.nativeLoadError ?: "Native VM library not loaded")
            }
            return
        }
        if (isBootInProgress) return
        isBootInProgress = true

        viewModelScope.launch {
            val bootStartedMs = System.currentTimeMillis()
            try {
                val profile = DeviceProfile.ALL.firstOrNull {
                    it.id == _uiState.value.selectedDeviceProfileId
                } ?: DeviceProfile.ALL.first()
                val settings = _uiState.value.settings
                val budget = emulatorRepository.computeAutoTunedRamBudget(settings.defaultRamMb)

                _uiState.update {
                    it.copy(
                        isBooting = true,
                        vmSessionVisible = true,
                        activeSystem = system,
                        sessionViewMode = VmSessionViewMode.SPLIT,
                        vmExitCode = 0,
                        bootStage = "HOST_RAM_TUNED",
                        bootStageDetail = if (budget.totalMb > 0L) {
                            "Auto-tuned ${budget.targetRamMb} MiB (${budget.availableMb} MiB host free / ${budget.totalMb} MiB total)"
                        } else {
                            "Auto-tuned ${budget.targetRamMb} MiB guest RAM"
                        },
                        tunedRamMb = budget.targetRamMb,
                        hostAvailableRamMb = budget.availableMb,
                        hostTotalRamMb = budget.totalMb,
                        bootElapsedSec = 0,
                        bootTraceTail = "",
                        guestLogTail = "",
                        lastTrapSummary = "",
                        vmErrorMessage = null,
                    )
                }

                bootProgressJob?.cancel()
                bootProgressJob = viewModelScope.launch(Dispatchers.IO) {
                    while (isActive) {
                        val rawStatus = runCatching { Engine.getBootStatus() }.getOrDefault("")
                        val parsed = runCatching { JSONObject(rawStatus) }.getOrNull()
                        val traceTail = runCatching { Engine.readBootTrace(4096) }.getOrDefault("")
                        val elapsedSec = ((System.currentTimeMillis() - bootStartedMs) / 1000L).toInt()
                        if (parsed != null) {
                            val stage = parsed.optString("stage", "").ifBlank { _uiState.value.bootStage }
                            val detail = parsed.optString("detail", "")
                            val effRam = parsed.optInt("effectiveRamMb", 0)
                            val trap = parsed.optString("lastTrap", "")
                            _uiState.update { state ->
                                state.copy(
                                    bootStage = stage,
                                    bootStageDetail = detail.ifBlank { state.bootStageDetail },
                                    tunedRamMb = if (effRam > 0) effRam else state.tunedRamMb,
                                    bootElapsedSec = elapsedSec,
                                    bootTraceTail = traceTail.ifBlank { state.bootTraceTail },
                                    lastTrapSummary = trap.ifBlank { state.lastTrapSummary },
                                )
                            }
                        } else {
                            _uiState.update { state ->
                                state.copy(
                                    bootElapsedSec = elapsedSec,
                                    bootTraceTail = traceTail.ifBlank { state.bootTraceTail },
                                )
                            }
                        }
                        delay(250L)
                    }
                }

                val errMsg = withContext(Dispatchers.IO) {
                    if (Engine.isRunning()) {
                        Engine.stop()
                    }
                    val rootDir = system.rootDirectory.ifBlank {
                        File(appContext.filesDir, "systems/${system.id}").absolutePath
                    }
                    val rcPath = Engine.setPath(rootDir)
                    if (rcPath != 0) return@withContext "setPath failed ($rcPath)"
                    Engine.setNativeLibDir(appContext.applicationInfo.nativeLibraryDir)
                    Engine.configureDeviceProfile(
                        model = profile.model,
                        brand = profile.brand,
                        manufacturer = profile.manufacturer,
                        device = profile.device,
                        name = profile.name,
                        marketname = profile.marketname,
                        fingerprint = profile.fingerprint,
                        magiskPromptEnabled = settings.magiskPromptEnabled,
                    )
                    if (system.bootImagePath.isNotBlank()) {
                        val rcBoot = Engine.loadBootImage(system.bootImagePath)
                        if (rcBoot != 0) {
                            return@withContext formatNativeError("loadBootImage failed ($rcBoot)")
                        }
                    }
                    if (system.systemImagePath.isNotBlank()) {
                        val rcSys = Engine.loadSystemImage(system.systemImagePath)
                        if (rcSys != 0) {
                            return@withContext formatNativeError("loadSystemImage failed ($rcSys)")
                        }
                    }
                    val rcStart = Engine.start(
                        api = system.apiLevel,
                        width = 720,
                        height = 1280,
                        dpi = 320,
                        ramMb = budget.targetRamMb,
                    )
                    if (rcStart != 0) {
                        return@withContext formatNativeError("VM start failed ($rcStart)")
                    }
                    null
                }

                bootProgressJob?.cancel()
                bootProgressJob = null

                val (effRam, statusObj, traceTail, logTail) = withContext(Dispatchers.IO) {
                    val ram = runCatching { Engine.getEffectiveRamMb() }.getOrDefault(0)
                    val statusJson = runCatching { JSONObject(Engine.getBootStatus()) }.getOrNull()
                    val trace = runCatching { Engine.readBootTrace(6144) }.getOrDefault("")
                    val logs = runCatching { Engine.readLog(8192) }.getOrDefault("")
                    Quad(ram, statusJson, trace, logs)
                }

                val statusStage = statusObj?.optString("stage").orEmpty()
                val statusTrap = statusObj?.optString("lastTrap").orEmpty()
                val statusExit = statusObj?.optInt("exitCode", 0) ?: 0
                val statusInsns = statusObj?.optLong("instructionsExecuted", 0L) ?: 0L
                val stillRunning = statusObj?.optBoolean("running", true) ?: true

                if (errMsg != null || !stillRunning || statusStage == "TRAPPED" || statusTrap.isNotBlank()) {
                    val failureMessage = errMsg
                        ?: statusTrap.ifBlank {
                            "Guest halted early ($statusStage, exit=$statusExit, insns=$statusInsns)"
                        }
                    _uiState.update {
                        it.copy(
                            isBooting = false,
                            isVmRunning = false,
                            vmSessionVisible = true,
                            activeSystem = system,
                            sessionViewMode = VmSessionViewMode.CONSOLE,
                            vmExitCode = if (errMsg != null && statusExit == 0) -1 else statusExit,
                            vmErrorMessage = failureMessage,
                            bootStage = statusStage.ifBlank { "BOOT_FAILED" },
                            bootStageDetail = statusObj?.optString("detail").orEmpty().ifBlank { failureMessage },
                            tunedRamMb = if (effRam > 0) effRam else budget.targetRamMb,
                            lastTrapSummary = statusTrap,
                            bootTraceTail = traceTail,
                            guestLogTail = logTail,
                        )
                    }
                    return@launch
                }

                emulatorRepository.markLastBoot(system)
                val refreshed = repository.loadInstalledSystems()
                _uiState.update {
                    it.copy(
                        systems = refreshed,
                        isBooting = false,
                        isVmRunning = true,
                        vmSessionVisible = true,
                        activeSystem = system,
                        vmErrorMessage = null,
                        vmExitCode = 0,
                        tunedRamMb = if (effRam > 0) effRam else budget.targetRamMb,
                        bootStage = statusStage.ifBlank { "RUNNING" },
                        bootStageDetail = statusObj?.optString("detail").orEmpty().ifBlank { "Guest VM active" },
                        lastTrapSummary = statusTrap,
                        bootTraceTail = traceTail,
                        guestLogTail = logTail,
                    )
                }
                startAudioAndTelemetryLoops()
            } finally {
                bootProgressJob?.cancel()
                bootProgressJob = null
                isBootInProgress = false
                _uiState.update { if (it.isBooting) it.copy(isBooting = false) else it }
            }
        }
    }

    fun stopVm() {
        stopAudioAndTelemetryLoops()
        viewModelScope.launch(Dispatchers.IO) {
            if (Engine.nativeLibraryLoaded && Engine.isRunning()) {
                Engine.stop()
            }
            val logs = if (Engine.nativeLibraryLoaded) Engine.readLog(8192) else ""
            val trace = if (Engine.nativeLibraryLoaded) Engine.readBootTrace(6144) else ""
            val statusJson = if (Engine.nativeLibraryLoaded) {
                runCatching { JSONObject(Engine.getBootStatus()) }.getOrNull()
            } else {
                null
            }
            val exitCode = statusJson?.optInt("exitCode", 0) ?: 0
            withContext(Dispatchers.Main) {
                _uiState.update {
                    it.copy(
                        isVmRunning = false,
                        isBooting = false,
                        vmSessionVisible = true,
                        bootStage = statusJson?.optString("stage").orEmpty().ifBlank { "HALTED" },
                        vmExitCode = exitCode,
                        guestLogTail = logs.ifBlank { it.guestLogTail },
                        bootTraceTail = trace.ifBlank { it.bootTraceTail },
                    )
                }
            }
            refreshTelemetryOnce()
        }
    }

    fun prepareBootPatchForSystem(system: VmSystem) {
        _uiState.update { it.copy(bootPatchTargetSystemId = system.id) }
    }

    fun patchSystemBootDirectly(system: VmSystem) {
        if (!Engine.nativeLibraryLoaded) {
            _uiState.update { it.copy(vmErrorMessage = Engine.nativeLoadError ?: "Native VM library not loaded") }
            return
        }
        if (system.bootImagePath.isBlank()) {
            _uiState.update { it.copy(vmErrorMessage = "No boot.img attached to ${system.name}; pick a stock boot.img first.") }
            return
        }
        viewModelScope.launch {
            val resultText = withContext(Dispatchers.IO) {
                val input = File(system.bootImagePath)
                val out = File(system.rootDirectory, "boot_magisk_v27.img")
                val jsonStr = Engine.patchBootImage(input.absolutePath, out.absolutePath)
                val json = runCatching { JSONObject(jsonStr) }.getOrNull()
                if (json != null && json.optBoolean("ok", false)) {
                    out.copyTo(input, overwrite = true)
                    out.delete()
                    repository.updateVmBootImage(system, input, hasMagisk = true)
                    json.optString("summary", "Magisk v27.0 patched & verified")
                } else {
                    val err = json?.optString("error").orEmpty().ifBlank { "Patcher returned error" }
                    "ERROR:$err"
                }
            }
            if (resultText.startsWith("ERROR:")) {
                _uiState.update { it.copy(vmErrorMessage = resultText.removePrefix("ERROR:")) }
            } else {
                val updated = repository.loadInstalledSystems()
                _uiState.update {
                    it.copy(
                        systems = updated,
                        bootPatchBanner = resultText,
                        vmErrorMessage = null,
                    )
                }
                refreshTelemetryOnce()
            }
        }
    }

    fun patchBootImageFromUri(uri: Uri) {
        val targetId = _uiState.value.bootPatchTargetSystemId
        val targetSystem = _uiState.value.systems.firstOrNull { it.id == targetId }
            ?: _uiState.value.systems.firstOrNull()
        if (!Engine.nativeLibraryLoaded) {
            _uiState.update { it.copy(vmErrorMessage = Engine.nativeLoadError ?: "Native VM library not loaded") }
            return
        }
        if (targetSystem == null) {
            _uiState.update { it.copy(vmErrorMessage = "Install or import a VM system first before patching boot.img") }
            return
        }

        viewModelScope.launch {
            val resultText = withContext(Dispatchers.IO) {
                val dir = File(targetSystem.rootDirectory).apply { mkdirs() }
                val rawIn = File(dir, "stock_boot_input.img")
                val patchedOut = File(dir, "boot.img")
                val copied = appContext.contentResolver.openInputStream(uri)?.use { input ->
                    FileOutputStream(rawIn).use { output -> input.copyTo(output) }
                    true
                } ?: false
                if (!copied) return@withContext "ERROR:Unable to read selected boot.img"

                val jsonStr = Engine.patchBootImage(rawIn.absolutePath, patchedOut.absolutePath)
                rawIn.delete()
                val json = runCatching { JSONObject(jsonStr) }.getOrNull()
                if (json != null && json.optBoolean("ok", false)) {
                    repository.updateVmBootImage(targetSystem, patchedOut, hasMagisk = true)
                    json.optString("summary", "Magisk v27.0 patched & verified")
                } else {
                    val err = json?.optString("error").orEmpty().ifBlank { "Magisk patch failed" }
                    "ERROR:$err"
                }
            }
            if (resultText.startsWith("ERROR:")) {
                _uiState.update {
                    it.copy(
                        bootPatchTargetSystemId = null,
                        vmErrorMessage = resultText.removePrefix("ERROR:"),
                    )
                }
            } else {
                val updated = repository.loadInstalledSystems()
                _uiState.update {
                    it.copy(
                        systems = updated,
                        bootPatchTargetSystemId = null,
                        bootPatchBanner = resultText,
                        vmErrorMessage = null,
                    )
                }
                refreshTelemetryOnce()
            }
        }
    }

    fun openTelemetrySheet() {
        _uiState.update { it.copy(showTelemetrySheet = true) }
        viewModelScope.launch {
            refreshTelemetryOnce()
        }
        startTelemetryPolling()
    }

    fun closeTelemetrySheet() {
        _uiState.update { it.copy(showTelemetrySheet = false) }
        if (!_uiState.value.isVmRunning) {
            telemetryJob?.cancel()
            telemetryJob = null
        }
    }

    fun tiltSensor(x: Float, y: Float, z: Float, active: Boolean) {
        if (!Engine.nativeLibraryLoaded) return
        viewModelScope.launch(Dispatchers.IO) {
            Engine.setSensorOverride(1 /* Accelerometer */, x, y, z, active)
            refreshTelemetryOnce()
        }
    }

    private fun startAudioAndTelemetryLoops() {
        stopAudioAndTelemetryLoops()

        audioJob = viewModelScope.launch(Dispatchers.IO) {
            val sampleRate = 48000
            val minBuf = AudioTrack.getMinBufferSize(
                sampleRate,
                AudioFormat.CHANNEL_OUT_STEREO,
                AudioFormat.ENCODING_PCM_16BIT,
            ).coerceAtLeast(4096)
            val track = runCatching {
                AudioTrack.Builder()
                    .setAudioAttributes(
                        AudioAttributes.Builder()
                            .setUsage(AudioAttributes.USAGE_GAME)
                            .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                            .build(),
                    )
                    .setAudioFormat(
                        AudioFormat.Builder()
                            .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                            .setSampleRate(sampleRate)
                            .setChannelMask(AudioFormat.CHANNEL_OUT_STEREO)
                            .build(),
                    )
                    .setTransferMode(AudioTrack.MODE_STREAM)
                    .setBufferSizeInBytes(minBuf)
                    .build()
            }.getOrNull()

            track?.play()
            val pcmBuf = ShortArray(2048)
            try {
                while (isActive && Engine.nativeLibraryLoaded && Engine.isRunning()) {
                    val count = Engine.drainAudioPcm(pcmBuf, pcmBuf.size)
                    if (count > 0 && track != null) {
                        track.write(pcmBuf, 0, count)
                    } else {
                        delay(10L)
                    }
                }
            } finally {
                runCatching {
                    track?.stop()
                    track?.release()
                }
            }
        }

        startTelemetryPolling()
    }

    private fun startTelemetryPolling() {
        telemetryJob?.cancel()
        telemetryJob = viewModelScope.launch {
            while (isActive && (_uiState.value.isVmRunning || _uiState.value.showTelemetrySheet)) {
                refreshTelemetryOnce()
                if (_uiState.value.isVmRunning && Engine.nativeLibraryLoaded && !Engine.isRunning()) {
                    val (trace, logs, statusJson) = withContext(Dispatchers.IO) {
                        val tr = runCatching { Engine.readBootTrace(6144) }.getOrDefault("")
                        val lg = runCatching { Engine.readLog(8192) }.getOrDefault("")
                        val st = runCatching { JSONObject(Engine.getBootStatus()) }.getOrNull()
                        Triple(tr, lg, st)
                    }
                    val trap = statusJson?.optString("lastTrap").orEmpty()
                        .ifBlank { _uiState.value.telemetry.lastTrap }
                    val stage = statusJson?.optString("stage").orEmpty()
                        .ifBlank { _uiState.value.telemetry.bootStage }
                    val exitCode = statusJson?.optInt("exitCode", _uiState.value.telemetry.exitCode)
                        ?: _uiState.value.telemetry.exitCode
                    val insns = statusJson?.optLong("instructionsExecuted", _uiState.value.telemetry.instructionsExecuted)
                        ?: _uiState.value.telemetry.instructionsExecuted
                    val earlyFault = stage == "TRAPPED" || trap.isNotBlank() || exitCode != 0 || insns < 500L
                    _uiState.update { state ->
                        state.copy(
                            isVmRunning = false,
                            vmSessionVisible = true,
                            vmExitCode = exitCode,
                            bootStage = stage,
                            lastTrapSummary = trap,
                            guestLogTail = logs.ifBlank { state.guestLogTail },
                            bootTraceTail = trace.ifBlank { state.bootTraceTail },
                            sessionViewMode = if (earlyFault) VmSessionViewMode.CONSOLE else state.sessionViewMode,
                            vmErrorMessage = if (trap.isNotBlank()) {
                                "Guest halted ($stage): $trap"
                            } else if (exitCode != 0 || insns < 500L) {
                                "Guest execution halted (exit=$exitCode, insns=$insns)"
                            } else {
                                state.vmErrorMessage
                            },
                        )
                    }
                    audioJob?.cancel()
                }
                delay(400L)
            }
        }
    }

    private fun stopAudioAndTelemetryLoops() {
        audioJob?.cancel()
        audioJob = null
        telemetryJob?.cancel()
        telemetryJob = null
    }

    private suspend fun refreshTelemetryOnce() {
        if (!Engine.nativeLibraryLoaded) return
        val (telemetry, logs, trace) = withContext(Dispatchers.IO) {
            val jsonStr = Engine.getPhoneTelemetry()
            val parsed = parseTelemetryJson(jsonStr)
            val tail = Engine.readLog(4096)
            val bootTrace = Engine.readBootTrace(4096)
            Triple(parsed, tail, bootTrace)
        }
        _uiState.update { state ->
            state.copy(
                telemetry = telemetry,
                guestLogTail = logs,
                bootTraceTail = trace.ifBlank { state.bootTraceTail },
                lastTrapSummary = telemetry.lastTrap.ifBlank { state.lastTrapSummary },
                tunedRamMb = if (telemetry.effectiveRamMb > 0) telemetry.effectiveRamMb else state.tunedRamMb,
            )
        }
    }

    private fun formatNativeError(prefix: String): String {
        val log = runCatching { Engine.readLog(2048) }.getOrDefault("")
        val errLine = log.lineSequence()
            .lastOrNull { it.contains("[ERROR]") }
            ?.substringAfter("[ERROR] ")
            ?.trim()
        return if (!errLine.isNullOrBlank()) "$prefix: $errLine" else prefix
    }

    private fun parseTelemetryJson(raw: String): PhoneTelemetryState = runCatching {
        val o = JSONObject(raw)
        val accel = o.optJSONArray("accel")
        val gyro = o.optJSONArray("gyro")
        val mag = o.optJSONArray("mag")
        PhoneTelemetryState(
            running = o.optBoolean("running", false),
            model = o.optString("model", "SM-S938B"),
            marketname = o.optString("marketname", "Galaxy S25 Ultra"),
            glRenderer = o.optString("glRenderer", "Haseeb SoftGLES 3.0 CPU (ARM64 No-EGL)"),
            guestFps = o.optDouble("guestFps", 0.0).toFloat(),
            drawCalls = o.optLong("drawCalls", 0L),
            triangles = o.optLong("triangles", 0L),
            framesSwapped = o.optLong("framesSwapped", 0L),
            magiskDetected = o.optBoolean("magiskDetected", false),
            magiskVersion = o.optString("magiskVersion", "27.0"),
            suGrants = o.optInt("suGrants", 0),
            lastSuCaller = o.optString("lastSuCaller", ""),
            batteryPct = o.optInt("batteryPct", 88),
            charging = o.optBoolean("charging", false),
            batteryTempC = o.optDouble("batteryTempC", 34.2).toFloat(),
            socTempC = o.optDouble("socTempC", 36.2).toFloat(),
            accelX = (accel?.optDouble(0, 0.0) ?: 0.0).toFloat(),
            accelY = (accel?.optDouble(1, 0.0) ?: 0.0).toFloat(),
            accelZ = (accel?.optDouble(2, 9.81) ?: 9.81).toFloat(),
            gyroX = (gyro?.optDouble(0, 0.0) ?: 0.0).toFloat(),
            gyroY = (gyro?.optDouble(1, 0.0) ?: 0.0).toFloat(),
            gyroZ = (gyro?.optDouble(2, 0.0) ?: 0.0).toFloat(),
            magX = (mag?.optDouble(0, 22.4) ?: 22.4).toFloat(),
            magY = (mag?.optDouble(1, -14.8) ?: -14.8).toFloat(),
            magZ = (mag?.optDouble(2, 41.2) ?: 41.2).toFloat(),
            lightLux = o.optDouble("lightLux", 350.0).toFloat(),
            proximityCm = o.optDouble("proximityCm", 5.0).toFloat(),
            pressureHpa = o.optDouble("pressureHpa", 1013.25).toFloat(),
            cameraFrames = o.optLong("cameraFrames", 0L),
            audioPlayFrames = o.optLong("audioPlayFrames", 0L),
            netTxPackets = o.optLong("netTxPackets", 0L),
            netRxPackets = o.optLong("netRxPackets", 0L),
            dnsQueries = o.optLong("dnsQueries", 0L),
            sharedStorageRoot = o.optString("sharedStorageRoot", ""),
            activeBinary = o.optString("activeBinary", "idle"),
            bootStage = o.optString("bootStage", "IDLE"),
            effectiveRamMb = o.optInt("effectiveRamMb", 0),
            instructionsExecuted = o.optLong("instructionsExecuted", 0L),
            lastTrap = o.optString("lastTrap", ""),
            exitCode = o.optInt("exitCode", 0),
            activeTasks = o.optInt("activeTasks", 0),
            frameworkServices = buildList {
                val arr = o.optJSONArray("frameworkServices")
                if (arr != null) {
                    for (i in 0 until arr.length()) {
                        val s = arr.optString(i, "")
                        if (s.isNotBlank()) add(s)
                    }
                }
            },
        )
    }.getOrDefault(PhoneTelemetryState())

    private data class Quad<A, B, C, D>(
        val first: A,
        val second: B,
        val third: C,
        val fourth: D,
    )
}
