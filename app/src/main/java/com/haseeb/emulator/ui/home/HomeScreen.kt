package com.haseeb.emulator.ui.home

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.view.MotionEvent
import android.view.Surface
import android.view.SurfaceHolder
import android.view.SurfaceView
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.Build
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Download
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.PhoneAndroid
import androidx.compose.material.icons.rounded.PlayArrow
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Sensors
import androidx.compose.material.icons.rounded.SportsEsports
import androidx.compose.material.icons.rounded.Stop
import androidx.compose.material.icons.rounded.Terminal
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material.icons.rounded.Tv
import androidx.compose.material.icons.rounded.Verified
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.haseeb.emulator.R
import com.haseeb.emulator.data.RomRepository
import com.haseeb.emulator.model.DeviceProfile
import com.haseeb.emulator.model.PhoneTelemetryState
import com.haseeb.emulator.model.RomInstallStage
import com.haseeb.emulator.model.VmSessionViewMode
import com.haseeb.emulator.model.VmSystem
import com.haseeb.emulator.ui.components.GlassCard
import com.haseeb.emulator.ui.components.SectionHeader
import com.haseeb.emulator.ui.components.StatusPill
import com.haseeb.emulator.ui.components.TealGlowButton
import com.haseeb.emulator.ui.theme.AmberWarning
import com.haseeb.emulator.ui.theme.CyanHighlight
import com.haseeb.emulator.ui.theme.ErrorCoral
import com.haseeb.emulator.ui.theme.GlassBorderTeal
import com.haseeb.emulator.ui.theme.MagiskEmerald
import com.haseeb.emulator.ui.theme.ObsidianBg
import com.haseeb.emulator.ui.theme.ObsidianSurface
import com.haseeb.emulator.ui.theme.OnTealAccent
import com.haseeb.emulator.ui.theme.TealAccent
import com.haseeb.emulator.ui.theme.TealAccentBright
import com.haseeb.emulator.ui.theme.TextMuted
import com.haseeb.emulator.ui.theme.TextSecondary
import java.text.DateFormat
import java.util.Date

@Composable
fun HomeScreen(
    viewModel: HomeViewModel = viewModel(),
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()

    val firmwarePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri != null) {
            viewModel.importFirmwareFromUri(uri)
        }
    }

    val bootImagePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri != null) {
            viewModel.patchBootImageFromUri(uri)
        }
    }

    val isBusy = uiState.installStage is RomInstallStage.Downloading ||
        uiState.installStage is RomInstallStage.VerifyingSha256 ||
        uiState.installStage is RomInstallStage.Extracting ||
        uiState.installStage is RomInstallStage.Importing ||
        uiState.installStage is RomInstallStage.BuildingEngineRom

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.radialGradient(
                    colors = listOf(
                        TealAccent.copy(alpha = 0.14f),
                        Color(0xFF0A111D),
                        ObsidianBg,
                    ),
                    center = Offset(240f, 120f),
                    radius = 1200f,
                ),
            ),
    ) {
        Scaffold(
            containerColor = Color.Transparent,
            contentWindowInsets = WindowInsets.safeDrawing,
            floatingActionButton = {
                ExtendedFloatingActionButton(
                    onClick = {
                        firmwarePickerLauncher.launch(
                            arrayOf("application/zip", "application/octet-stream", "*/*"),
                        )
                    },
                    containerColor = TealAccent,
                    contentColor = OnTealAccent,
                    shape = RoundedCornerShape(18.dp),
                    modifier = Modifier.testTag("import_firmware_fab"),
                    icon = {
                        Icon(
                            imageVector = Icons.Rounded.Add,
                            contentDescription = stringResource(R.string.cd_import_firmware),
                        )
                    },
                    text = {
                        Text(
                            text = stringResource(R.string.fab_import_label),
                            style = MaterialTheme.typography.labelLarge,
                        )
                    },
                )
            },
        ) { innerPadding ->
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
                contentAlignment = Alignment.TopCenter,
            ) {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .widthIn(max = 720.dp),
                    contentPadding = PaddingValues(
                        start = 16.dp,
                        end = 16.dp,
                        top = 12.dp,
                        bottom = 120.dp,
                    ),
                    verticalArrangement = Arrangement.spacedBy(16.dp),
                ) {
                    item {
                        BrandHeader(
                            onTelemetryClick = viewModel::openTelemetrySheet,
                        )
                    }

                    if (uiState.vmErrorMessage != null) {
                        item {
                            DismissibleStatusCard(
                                title = uiState.vmErrorMessage ?: "",
                                tint = ErrorCoral,
                                isError = true,
                                actionLabel = stringResource(R.string.action_inspect_crash_trace),
                                onActionClick = viewModel::openTelemetrySheet,
                                onDismiss = viewModel::clearVmError,
                            )
                        }
                    }

                    if (uiState.bootPatchBanner != null) {
                        item {
                            DismissibleStatusCard(
                                title = "${stringResource(R.string.status_boot_patched)}: ${uiState.bootPatchBanner}",
                                tint = MagiskEmerald,
                                isError = false,
                                onDismiss = viewModel::clearBootPatchBanner,
                            )
                        }
                    }

                    item {
                        AnimatedVisibility(
                            visible = uiState.isBooting,
                            enter = fadeIn(),
                            exit = fadeOut(),
                        ) {
                            BootPipelineBanner(
                                bootStage = uiState.bootStage,
                                bootStageDetail = uiState.bootStageDetail,
                                tunedRamMb = uiState.tunedRamMb,
                                hostAvailableRamMb = uiState.hostAvailableRamMb,
                                bootElapsedSec = uiState.bootElapsedSec,
                                bootTraceTail = uiState.bootTraceTail,
                            )
                        }
                    }

                    if (uiState.vmSessionVisible) {
                        item {
                            ActiveVmSessionCard(
                                system = uiState.activeSystem,
                                isVmRunning = uiState.isVmRunning,
                                isBooting = uiState.isBooting,
                                bootStage = uiState.bootStage,
                                bootStageDetail = uiState.bootStageDetail,
                                vmExitCode = uiState.vmExitCode,
                                lastTrapSummary = uiState.lastTrapSummary,
                                guestLogTail = uiState.guestLogTail,
                                bootTraceTail = uiState.bootTraceTail,
                                sessionViewMode = uiState.sessionViewMode,
                                telemetry = uiState.telemetry,
                                tunedRamMb = uiState.tunedRamMb,
                                onSelectViewMode = viewModel::setSessionViewMode,
                                onAttachSurface = viewModel::attachSurfaceAsync,
                                onSendTouch = viewModel::sendTouchAsync,
                                onOpenTelemetry = viewModel::openTelemetrySheet,
                                onStopVm = viewModel::stopVm,
                                onCloseSession = viewModel::closeVmSession,
                            )
                        }
                    }

                    item {
                        AnimatedVisibility(
                            visible = uiState.installStage !is RomInstallStage.Idle,
                            enter = fadeIn(),
                            exit = fadeOut(),
                        ) {
                            InstallProgressBanner(
                                stage = uiState.installStage,
                                onDismiss = viewModel::clearInstallStatus,
                            )
                        }
                    }

                    if (uiState.showFirstLaunchOffer) {
                        item {
                            FirstLaunchRomOfferCard(
                                repoSlug = uiState.settings.githubRepoSlug,
                                releaseTag = uiState.settings.romReleaseTag,
                                isBusy = isBusy,
                                onDownload = viewModel::installBundledGamingRom,
                                onBuildEngineRom = viewModel::buildEngineMagiskRom,
                                onDismiss = viewModel::dismissFirstLaunchOffer,
                            )
                        }
                    }

                    item {
                        InstallGamingRomHeroCard(
                            isBusy = isBusy,
                            onInstallClick = viewModel::installBundledGamingRom,
                            onBuildEngineRomClick = viewModel::buildEngineMagiskRom,
                        )
                    }

                    item {
                        DeviceProfileStrip(
                            selectedProfileId = uiState.selectedDeviceProfileId,
                            onSelectProfile = viewModel::selectDeviceProfile,
                        )
                    }

                    item {
                        SectionHeader(
                            title = stringResource(R.string.section_installed_systems),
                            trailingBadge = stringResource(
                                R.string.section_installed_count,
                                uiState.systems.size,
                            ),
                        )
                    }

                    if (uiState.systems.isEmpty()) {
                        item {
                            EmptySystemsCard()
                        }
                    } else {
                        items(
                            items = uiState.systems,
                            key = { it.id },
                        ) { system ->
                            VmSystemCard(
                                system = system,
                                isBooting = uiState.isBooting,
                                onBootClick = { viewModel.bootSystem(system) },
                                onGamingModeClick = { viewModel.inspectSystem(system) },
                                onPatchBootClick = {
                                    viewModel.prepareBootPatchForSystem(system)
                                    bootImagePickerLauncher.launch(
                                        arrayOf("application/octet-stream", "*/*"),
                                    )
                                },
                            )
                        }
                    }
                }
            }
        }
    }

    uiState.gamingDialogSystem?.let { system ->
        SystemInspectDialog(
            system = system,
            isBooting = uiState.isBooting,
            selectedProfileId = uiState.selectedDeviceProfileId,
            onSelectProfile = viewModel::selectDeviceProfile,
            onPatchExistingBoot = {
                viewModel.patchSystemBootDirectly(system)
                viewModel.inspectSystem(null)
            },
            onLaunchVm = {
                viewModel.inspectSystem(null)
                viewModel.bootSystem(system)
            },
            onDismiss = { viewModel.inspectSystem(null) },
        )
    }

    if (uiState.showTelemetrySheet) {
        PhoneTelemetryDialog(
            telemetry = uiState.telemetry,
            logsTail = uiState.guestLogTail,
            bootStage = uiState.bootStage,
            bootStageDetail = uiState.bootStageDetail,
            tunedRamMb = uiState.tunedRamMb,
            lastTrapSummary = uiState.lastTrapSummary,
            bootTraceTail = uiState.bootTraceTail,
            onTiltLeft = { viewModel.tiltSensor(-4.8f, 0.2f, 8.5f, true) },
            onTiltRight = { viewModel.tiltSensor(4.8f, 0.2f, 8.5f, true) },
            onResetTilt = { viewModel.tiltSensor(0f, 0f, 9.81f, false) },
            onDismiss = viewModel::closeTelemetrySheet,
        )
    }
}

@Composable
private fun BrandHeader(
    onTelemetryClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            modifier = Modifier.weight(1f),
        ) {
            Box(
                modifier = Modifier
                    .size(46.dp)
                    .clip(RoundedCornerShape(14.dp))
                    .background(TealAccent.copy(alpha = 0.14f)),
                contentAlignment = Alignment.Center,
            ) {
                Image(
                    painter = painterResource(id = R.drawable.ic_launcher_art),
                    contentDescription = stringResource(R.string.cd_brand_logo),
                    contentScale = ContentScale.Crop,
                    modifier = Modifier.fillMaxSize(),
                )
            }
            Column {
                Text(
                    text = stringResource(R.string.app_name),
                    style = MaterialTheme.typography.headlineMedium,
                    color = MaterialTheme.colorScheme.onBackground,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = stringResource(R.string.brand_subtitle),
                    style = MaterialTheme.typography.labelSmall,
                    color = TealAccent,
                )
            }
        }

        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Surface(
                modifier = Modifier
                    .defaultMinSize(minHeight = 48.dp)
                    .clip(RoundedCornerShape(999.dp))
                    .clickable(onClick = onTelemetryClick)
                    .testTag("open_telemetry_button"),
                shape = RoundedCornerShape(999.dp),
                color = TealAccent.copy(alpha = 0.14f),
                border = BorderStroke(1.dp, TealAccent.copy(alpha = 0.35f)),
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Icon(
                        imageVector = Icons.Rounded.Sensors,
                        contentDescription = stringResource(R.string.cd_telemetry_nav),
                        tint = TealAccent,
                        modifier = Modifier.size(16.dp),
                    )
                    Text(
                        text = stringResource(R.string.action_phone_telemetry),
                        style = MaterialTheme.typography.labelSmall,
                        color = TealAccent,
                    )
                }
            }
            StatusPill(
                label = "ARM64",
                tint = CyanHighlight,
                icon = Icons.Rounded.Memory,
            )
        }
    }
}

@Composable
private fun DismissibleStatusCard(
    title: String,
    tint: Color,
    isError: Boolean,
    actionLabel: String? = null,
    onActionClick: (() -> Unit)? = null,
    onDismiss: () -> Unit,
) {
    GlassCard(
        elevated = true,
        accentBorder = !isError,
        modifier = Modifier
            .fillMaxWidth()
            .testTag(if (isError) "vm_error_banner" else "vm_status_banner"),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    modifier = Modifier.weight(1f),
                ) {
                    Icon(
                        imageVector = if (isError) Icons.Rounded.ErrorOutline else Icons.Rounded.Verified,
                        contentDescription = null,
                        tint = tint,
                    )
                    Text(
                        text = title,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onBackground,
                    )
                }
                IconButton(onClick = onDismiss, modifier = Modifier.size(48.dp)) {
                    Icon(
                        imageVector = Icons.Rounded.Close,
                        contentDescription = stringResource(R.string.action_skip_for_now),
                        tint = TextSecondary,
                    )
                }
            }
            if (isError && actionLabel != null && onActionClick != null) {
                OutlinedButton(
                    onClick = onActionClick,
                    modifier = Modifier
                        .fillMaxWidth()
                        .defaultMinSize(minHeight = 48.dp)
                        .testTag("inspect_crash_trace_button"),
                    shape = RoundedCornerShape(14.dp),
                    border = BorderStroke(1.dp, ErrorCoral.copy(alpha = 0.55f)),
                ) {
                    Icon(
                        imageVector = Icons.Rounded.Sensors,
                        contentDescription = null,
                        tint = ErrorCoral,
                        modifier = Modifier.size(18.dp),
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = actionLabel,
                        style = MaterialTheme.typography.labelLarge,
                        color = ErrorCoral,
                    )
                }
            }
        }
    }
}

@Composable
private fun BootPipelineBanner(
    bootStage: String,
    bootStageDetail: String,
    tunedRamMb: Int,
    hostAvailableRamMb: Long,
    bootElapsedSec: Int,
    bootTraceTail: String,
) {
    GlassCard(
        elevated = true,
        accentBorder = true,
        modifier = Modifier
            .fillMaxWidth()
            .testTag("boot_pipeline_banner"),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = stringResource(R.string.boot_pipeline_title),
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onBackground,
                )
                Text(
                    text = "${bootStage.ifBlank { "STAGING" }} · ${bootElapsedSec}s",
                    style = MaterialTheme.typography.labelSmall,
                    color = TealAccentBright,
                )
            }
            if (tunedRamMb > 0) {
                StatusPill(
                    label = if (hostAvailableRamMb > 0L) {
                        "$tunedRamMb MiB AUTO (${hostAvailableRamMb}M free)"
                    } else {
                        "$tunedRamMb MiB AUTO"
                    },
                    tint = CyanHighlight,
                    icon = Icons.Rounded.Memory,
                )
            }
        }
        Spacer(modifier = Modifier.height(10.dp))
        LinearProgressIndicator(
            modifier = Modifier
                .fillMaxWidth()
                .height(6.dp)
                .clip(CircleShape),
            color = TealAccent,
            trackColor = TealAccent.copy(alpha = 0.18f),
        )
        if (bootStageDetail.isNotBlank()) {
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = bootStageDetail,
                style = MaterialTheme.typography.bodyMedium,
                color = TextSecondary,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
        }
        val lastLine = bootTraceTail.lineSequence()
            .lastOrNull { it.isNotBlank() }
            .orEmpty()
        if (lastLine.isNotBlank()) {
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = lastLine,
                style = MaterialTheme.typography.labelSmall,
                color = TextMuted,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

@Composable
private fun ActiveVmSessionCard(
    system: VmSystem?,
    isVmRunning: Boolean,
    isBooting: Boolean,
    bootStage: String,
    bootStageDetail: String,
    vmExitCode: Int,
    lastTrapSummary: String,
    guestLogTail: String,
    bootTraceTail: String,
    sessionViewMode: VmSessionViewMode,
    telemetry: PhoneTelemetryState,
    tunedRamMb: Int,
    onSelectViewMode: (VmSessionViewMode) -> Unit,
    onAttachSurface: (Surface?) -> Unit,
    onSendTouch: (Int, Int, Int, Int) -> Unit,
    onOpenTelemetry: () -> Unit,
    onStopVm: () -> Unit,
    onCloseSession: () -> Unit,
) {
    val context = LocalContext.current
    val activeRamMb = if (telemetry.effectiveRamMb > 0) telemetry.effectiveRamMb else tunedRamMb
    val isTrapped = !isVmRunning && !isBooting && (
        bootStage == "TRAPPED" ||
            bootStage == "BOOT_FAILED" ||
            vmExitCode != 0 ||
            lastTrapSummary.isNotBlank()
        )
    val isFrameworkReady = telemetry.frameworkServices.contains("activity") ||
        telemetry.frameworkServices.contains("surfaceflinger")

    val statusLabel = when {
        isBooting -> bootStage.ifBlank { "BOOTING" }
        isTrapped -> "TRAPPED (exit=$vmExitCode)"
        !isVmRunning -> "HALTED (exit=$vmExitCode)"
        isFrameworkReady && telemetry.magiskDetected -> "FRAMEWORK · MAGISK"
        telemetry.magiskDetected -> "MAGISK ROOT"
        else -> "RUNNING"
    }
    val statusTint = when {
        isTrapped -> ErrorCoral
        !isVmRunning && !isBooting -> AmberWarning
        isFrameworkReady || telemetry.magiskDetected -> MagiskEmerald
        else -> TealAccent
    }

    val combinedConsoleText = remember(guestLogTail, bootTraceTail, lastTrapSummary, bootStageDetail) {
        buildString {
            if (guestLogTail.isNotBlank()) {
                append(guestLogTail.trimEnd())
            }
            if (bootTraceTail.isNotBlank()) {
                if (isNotEmpty()) append("\n--- boot_trace.log ---\n")
                append(bootTraceTail.trimEnd())
            }
            if (lastTrapSummary.isNotBlank() && !contains(lastTrapSummary)) {
                if (isNotEmpty()) append("\n")
                append("[TRAP] ").append(lastTrapSummary)
            } else if (isEmpty() && bootStageDetail.isNotBlank()) {
                append("[INFO] ").append(bootStageDetail)
            }
        }
    }

    GlassCard(
        elevated = true,
        accentBorder = !isTrapped,
        modifier = Modifier
            .fillMaxWidth()
            .testTag("active_vm_session_card"),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "${stringResource(R.string.vm_session_title)}: ${system?.name ?: telemetry.marketname}",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onBackground,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = buildString {
                        append(telemetry.activeBinary)
                        append(" · %.1f FPS".format(telemetry.guestFps))
                        if (activeRamMb > 0) {
                            append(" · %d MiB".format(activeRamMb))
                        }
                        append(" · %d insns".format(telemetry.instructionsExecuted))
                    },
                    style = MaterialTheme.typography.labelSmall,
                    color = if (isTrapped) ErrorCoral else TealAccentBright,
                )
            }
            Spacer(modifier = Modifier.width(8.dp))
            StatusPill(
                label = statusLabel,
                tint = statusTint,
                icon = if (isTrapped) Icons.Rounded.ErrorOutline else Icons.Rounded.Security,
            )
        }

        if (telemetry.frameworkServices.isNotEmpty()) {
            Spacer(modifier = Modifier.height(8.dp))
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                telemetry.frameworkServices.forEach { svc ->
                    StatusPill(
                        label = svc,
                        tint = if (svc == "magisk_su") MagiskEmerald else CyanHighlight,
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(10.dp))
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(12.dp))
                .background(ObsidianSurface)
                .border(1.dp, GlassBorderTeal.copy(alpha = 0.5f), RoundedCornerShape(12.dp))
                .padding(4.dp),
            horizontalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            val modes = listOf(
                Triple(VmSessionViewMode.DISPLAY, R.string.vm_view_display, "vm_mode_display"),
                Triple(VmSessionViewMode.SPLIT, R.string.vm_view_split, "vm_mode_split"),
                Triple(VmSessionViewMode.CONSOLE, R.string.vm_view_console, "vm_mode_console"),
            )
            modes.forEach { (mode, labelRes, tag) ->
                val selected = sessionViewMode == mode
                Surface(
                    modifier = Modifier
                        .weight(1f)
                        .defaultMinSize(minHeight = 48.dp)
                        .clip(RoundedCornerShape(9.dp))
                        .clickable { onSelectViewMode(mode) }
                        .testTag(tag),
                    color = if (selected) TealAccent.copy(alpha = 0.2f) else Color.Transparent,
                    border = if (selected) BorderStroke(1.dp, TealAccent.copy(alpha = 0.6f)) else null,
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Text(
                            text = stringResource(labelRes),
                            style = MaterialTheme.typography.labelLarge,
                            color = if (selected) TealAccentBright else TextSecondary,
                        )
                    }
                }
            }
        }

        if (sessionViewMode == VmSessionViewMode.DISPLAY || sessionViewMode == VmSessionViewMode.SPLIT) {
            Spacer(modifier = Modifier.height(12.dp))
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .then(
                        if (sessionViewMode == VmSessionViewMode.SPLIT) {
                            Modifier.height(260.dp)
                        } else {
                            Modifier.aspectRatio(9f / 16f)
                        },
                    )
                    .clip(RoundedCornerShape(16.dp))
                    .background(ObsidianSurface),
            ) {
                if (isVmRunning || isBooting) {
                    AndroidView(
                        modifier = Modifier.fillMaxSize(),
                        factory = { ctx ->
                            SurfaceView(ctx).apply {
                                holder.addCallback(object : SurfaceHolder.Callback {
                                    override fun surfaceCreated(holder: SurfaceHolder) {
                                        onAttachSurface(holder.surface)
                                    }

                                    override fun surfaceChanged(
                                        holder: SurfaceHolder,
                                        format: Int,
                                        width: Int,
                                        height: Int,
                                    ) {
                                        onAttachSurface(holder.surface)
                                    }

                                    override fun surfaceDestroyed(holder: SurfaceHolder) {
                                        onAttachSurface(null)
                                    }
                                })
                                setOnTouchListener { v, event ->
                                    val action = event.actionMasked
                                    val idx = event.actionIndex
                                    val ptrId = event.getPointerId(idx)
                                    val gx = ((event.getX(idx) / v.width.coerceAtLeast(1)) * 720f).toInt()
                                    val gy = ((event.getY(idx) / v.height.coerceAtLeast(1)) * 1280f).toInt()
                                    when (action) {
                                        MotionEvent.ACTION_DOWN,
                                        MotionEvent.ACTION_POINTER_DOWN,
                                        MotionEvent.ACTION_POINTER_UP,
                                        MotionEvent.ACTION_CANCEL -> {
                                            onSendTouch(action, gx, gy, ptrId)
                                        }
                                        MotionEvent.ACTION_UP -> {
                                            onSendTouch(action, gx, gy, ptrId)
                                            v.performClick()
                                        }
                                        MotionEvent.ACTION_MOVE -> {
                                            for (p in 0 until event.pointerCount) {
                                                val px = ((event.getX(p) / v.width.coerceAtLeast(1)) * 720f).toInt()
                                                val py = ((event.getY(p) / v.height.coerceAtLeast(1)) * 1280f).toInt()
                                                onSendTouch(MotionEvent.ACTION_MOVE, px, py, event.getPointerId(p))
                                            }
                                        }
                                    }
                                    true
                                }
                            }
                        },
                    )
                } else {
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(16.dp),
                        verticalArrangement = Arrangement.Center,
                        horizontalAlignment = Alignment.CenterHorizontally,
                    ) {
                        Icon(
                            imageVector = if (isTrapped) Icons.Rounded.ErrorOutline else Icons.Rounded.Tv,
                            contentDescription = null,
                            tint = if (isTrapped) ErrorCoral else AmberWarning,
                            modifier = Modifier.size(32.dp),
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = if (isTrapped) {
                                "Guest halted before scanout ($bootStage, exit=$vmExitCode)"
                            } else {
                                "Guest session halted cleanly (exit=$vmExitCode)"
                            },
                            style = MaterialTheme.typography.titleSmall,
                            color = MaterialTheme.colorScheme.onBackground,
                        )
                        if (lastTrapSummary.isNotBlank()) {
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(
                                text = lastTrapSummary,
                                style = MaterialTheme.typography.labelSmall,
                                color = ErrorCoral,
                                maxLines = 4,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }
                }
            }
        }

        if (sessionViewMode == VmSessionViewMode.CONSOLE || sessionViewMode == VmSessionViewMode.SPLIT) {
            Spacer(modifier = Modifier.height(12.dp))
            BootConsolePanel(
                consoleText = combinedConsoleText,
                trapSummary = lastTrapSummary,
                bootStage = bootStage,
                exitCode = vmExitCode,
                activeTasks = telemetry.activeTasks,
                expanded = sessionViewMode == VmSessionViewMode.CONSOLE,
                isTrapped = isTrapped,
                onCopyLog = {
                    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                    clipboard?.setPrimaryClip(
                        ClipData.newPlainText("Haseeb VM Console Log", combinedConsoleText),
                    )
                    Toast.makeText(
                        context,
                        context.getString(R.string.status_console_copied),
                        Toast.LENGTH_SHORT,
                    ).show()
                },
            )
        }

        Spacer(modifier = Modifier.height(12.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            OutlinedButton(
                onClick = onOpenTelemetry,
                modifier = Modifier
                    .weight(1f)
                    .defaultMinSize(minHeight = 48.dp)
                    .testTag("session_telemetry_button"),
                shape = RoundedCornerShape(14.dp),
                border = BorderStroke(1.dp, GlassBorderTeal),
            ) {
                Icon(Icons.Rounded.Sensors, contentDescription = null, tint = TealAccent)
                Spacer(modifier = Modifier.width(6.dp))
                Text(stringResource(R.string.action_phone_telemetry), color = TealAccent)
            }
            if (isVmRunning || isBooting) {
                OutlinedButton(
                    onClick = onStopVm,
                    modifier = Modifier
                        .weight(1f)
                        .defaultMinSize(minHeight = 48.dp)
                        .testTag("stop_vm_button"),
                    shape = RoundedCornerShape(14.dp),
                    border = BorderStroke(1.dp, ErrorCoral.copy(alpha = 0.6f)),
                ) {
                    Icon(Icons.Rounded.Stop, contentDescription = null, tint = ErrorCoral)
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(stringResource(R.string.action_stop_vm), color = ErrorCoral)
                }
            } else {
                OutlinedButton(
                    onClick = onCloseSession,
                    modifier = Modifier
                        .weight(1f)
                        .defaultMinSize(minHeight = 48.dp)
                        .testTag("close_vm_session_button"),
                    shape = RoundedCornerShape(14.dp),
                    border = BorderStroke(1.dp, TextSecondary.copy(alpha = 0.5f)),
                ) {
                    Icon(Icons.Rounded.Close, contentDescription = null, tint = TextSecondary)
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(stringResource(R.string.action_close_session), color = TextSecondary)
                }
            }
        }
    }
}

@Composable
private fun BootConsolePanel(
    consoleText: String,
    trapSummary: String,
    bootStage: String,
    exitCode: Int,
    activeTasks: Int,
    expanded: Boolean,
    isTrapped: Boolean,
    onCopyLog: () -> Unit,
) {
    val lines = remember(consoleText) {
        consoleText.lineSequence()
            .filter { it.isNotBlank() }
            .toList()
            .takeLast(140)
    }
    val scrollState = rememberScrollState()
    LaunchedEffect(lines.size) {
        if (scrollState.maxValue > 0) {
            scrollState.scrollTo(scrollState.maxValue)
        }
    }

    Surface(
        shape = RoundedCornerShape(14.dp),
        color = Color(0xFF05080E),
        border = BorderStroke(
            1.dp,
            if (isTrapped) ErrorCoral.copy(alpha = 0.55f) else GlassBorderTeal.copy(alpha = 0.45f),
        ),
        modifier = Modifier
            .fillMaxWidth()
            .testTag("boot_console_panel"),
    ) {
        Column(modifier = Modifier.padding(10.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    modifier = Modifier.weight(1f),
                ) {
                    Icon(
                        imageVector = Icons.Rounded.Terminal,
                        contentDescription = null,
                        tint = if (isTrapped) ErrorCoral else TealAccent,
                        modifier = Modifier.size(16.dp),
                    )
                    Text(
                        text = "Console · $bootStage · ${activeTasks}t · exit=$exitCode",
                        style = MaterialTheme.typography.labelMedium,
                        color = if (isTrapped) ErrorCoral else TealAccentBright,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                TextButton(
                    onClick = onCopyLog,
                    modifier = Modifier
                        .defaultMinSize(minHeight = 48.dp)
                        .testTag("copy_console_log_button"),
                ) {
                    Icon(
                        imageVector = Icons.Rounded.ContentCopy,
                        contentDescription = null,
                        tint = CyanHighlight,
                        modifier = Modifier.size(14.dp),
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    Text(
                        text = stringResource(R.string.action_copy_console),
                        style = MaterialTheme.typography.labelSmall,
                        color = CyanHighlight,
                    )
                }
            }

            if (trapSummary.isNotBlank()) {
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = ErrorCoral.copy(alpha = 0.14f),
                    border = BorderStroke(1.dp, ErrorCoral.copy(alpha = 0.45f)),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 8.dp),
                ) {
                    Text(
                        text = trapSummary,
                        style = MaterialTheme.typography.labelSmall,
                        color = ErrorCoral,
                        modifier = Modifier.padding(8.dp),
                    )
                }
            }

            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(
                        min = if (expanded) 220.dp else 130.dp,
                        max = if (expanded) 380.dp else 210.dp,
                    )
                    .verticalScroll(scrollState),
                verticalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                if (lines.isEmpty()) {
                    Text(
                        text = stringResource(R.string.vm_console_empty),
                        style = MaterialTheme.typography.labelSmall,
                        color = TextMuted,
                    )
                } else {
                    lines.forEach { line ->
                        val lineColor = when {
                            line.contains("[FAIL]") ||
                                line.contains("[SIGNAL]") ||
                                line.contains("[ERROR]") ||
                                line.contains("[TRAP]") ||
                                line.contains("TRAPPED") ||
                                line.contains("failed", ignoreCase = true) -> ErrorCoral
                            line.contains("[WARN]") ||
                                line.contains("[SYS-ENOSYS]") -> AmberWarning
                            line.contains("[SYS]") ||
                                line.contains("[TRACE]") -> CyanHighlight.copy(alpha = 0.85f)
                            line.contains("magisk", ignoreCase = true) ||
                                line.contains("servicemanager") ||
                                line.contains("system_server") ||
                                line.contains("surfaceflinger") ||
                                line.contains("zygote64") -> MagiskEmerald
                            line.contains("[UART]") -> TealAccentBright
                            else -> TextSecondary
                        }
                        Text(
                            text = line,
                            style = MaterialTheme.typography.labelSmall,
                            color = lineColor,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun DeviceProfileStrip(
    selectedProfileId: String,
    onSelectProfile: (String) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Icon(
                imageVector = Icons.Rounded.PhoneAndroid,
                contentDescription = null,
                tint = TealAccent,
                modifier = Modifier.size(18.dp),
            )
            Text(
                text = "Spoofed Real Device Profile",
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.onBackground,
            )
        }
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            DeviceProfile.ALL.forEach { profile ->
                val selected = profile.id == selectedProfileId
                FilterChip(
                    selected = selected,
                    onClick = { onSelectProfile(profile.id) },
                    label = {
                        Text(
                            text = "${profile.displayName} (${profile.model})",
                            style = MaterialTheme.typography.labelSmall,
                        )
                    },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = TealAccent.copy(alpha = 0.2f),
                        selectedLabelColor = TealAccentBright,
                        containerColor = ObsidianSurface,
                        labelColor = TextSecondary,
                    ),
                )
            }
        }
    }
}

@Composable
private fun FirstLaunchRomOfferCard(
    repoSlug: String,
    releaseTag: String,
    isBusy: Boolean,
    onDownload: () -> Unit,
    onBuildEngineRom: () -> Unit,
    onDismiss: () -> Unit,
) {
    GlassCard(
        elevated = true,
        accentBorder = true,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            StatusPill(
                label = stringResource(R.string.first_launch_badge),
                tint = TealAccent,
                icon = Icons.Rounded.Download,
            )
            IconButton(
                onClick = onDismiss,
                modifier = Modifier
                    .size(48.dp)
                    .testTag("dismiss_first_launch_button"),
            ) {
                Icon(
                    imageVector = Icons.Rounded.Close,
                    contentDescription = stringResource(R.string.action_skip_for_now),
                    tint = TextSecondary,
                )
            }
        }
        Spacer(modifier = Modifier.height(6.dp))
        Text(
            text = stringResource(R.string.first_launch_title),
            style = MaterialTheme.typography.titleLarge,
            color = MaterialTheme.colorScheme.onBackground,
        )
        Spacer(modifier = Modifier.height(6.dp))
        Text(
            text = stringResource(R.string.first_launch_body),
            style = MaterialTheme.typography.bodyMedium,
            color = TextSecondary,
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = "github.com/$repoSlug · $releaseTag",
            style = MaterialTheme.typography.labelSmall,
            color = TealAccentBright,
        )
        Spacer(modifier = Modifier.height(14.dp))
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            TealGlowButton(
                text = stringResource(R.string.action_build_engine_rom),
                icon = Icons.Rounded.Build,
                enabled = !isBusy,
                onClick = onBuildEngineRom,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("first_launch_build_engine_rom_button"),
            )
            OutlinedButton(
                onClick = onDownload,
                enabled = !isBusy,
                modifier = Modifier
                    .fillMaxWidth()
                    .defaultMinSize(minHeight = 48.dp)
                    .testTag("first_launch_download_button"),
                shape = RoundedCornerShape(14.dp),
                border = BorderStroke(1.dp, GlassBorderTeal),
            ) {
                Icon(
                    imageVector = Icons.Rounded.Download,
                    contentDescription = null,
                    tint = TealAccentBright,
                    modifier = Modifier.size(18.dp),
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = stringResource(R.string.action_download_verify),
                    style = MaterialTheme.typography.labelLarge,
                    color = TealAccentBright,
                )
            }
        }
    }
}

@Composable
private fun InstallGamingRomHeroCard(
    isBusy: Boolean,
    onInstallClick: () -> Unit,
    onBuildEngineRomClick: () -> Unit,
) {
    val cardShape = RoundedCornerShape(24.dp)
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(cardShape)
            .testTag("install_gaming_rom_card"),
    ) {
        Image(
            painter = painterResource(id = R.drawable.img_rom_hero_banner),
            contentDescription = stringResource(R.string.cd_hero_banner),
            contentScale = ContentScale.Crop,
            modifier = Modifier.matchParentSize(),
        )
        Box(
            modifier = Modifier
                .matchParentSize()
                .background(
                    Brush.verticalGradient(
                        colors = listOf(
                            Color(0x9906090F),
                            Color(0xE8080D16),
                            Color(0xF506090F),
                        ),
                    ),
                ),
        )
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
        ) {
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                StatusPill(
                    label = stringResource(R.string.hero_card_badge),
                    tint = TealAccent,
                    icon = Icons.Rounded.SportsEsports,
                )
                StatusPill(
                    label = "SHA-256",
                    tint = MagiskEmerald,
                    icon = Icons.Rounded.Verified,
                )
            }
            Spacer(modifier = Modifier.height(14.dp))
            Text(
                text = stringResource(R.string.hero_card_title),
                style = MaterialTheme.typography.displaySmall,
                color = MaterialTheme.colorScheme.onBackground,
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = stringResource(R.string.hero_card_subtitle),
                style = MaterialTheme.typography.bodyLarge,
                color = TextSecondary,
            )
            Spacer(modifier = Modifier.height(18.dp))
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                TealGlowButton(
                    text = stringResource(R.string.action_build_engine_rom),
                    icon = Icons.Rounded.Build,
                    enabled = !isBusy,
                    onClick = onBuildEngineRomClick,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("build_engine_rom_button"),
                )
                OutlinedButton(
                    onClick = onInstallClick,
                    enabled = !isBusy,
                    modifier = Modifier
                        .fillMaxWidth()
                        .defaultMinSize(minHeight = 48.dp)
                        .testTag("hero_install_rom_button"),
                    shape = RoundedCornerShape(14.dp),
                    border = BorderStroke(1.dp, GlassBorderTeal),
                ) {
                    Icon(
                        imageVector = Icons.Rounded.Download,
                        contentDescription = null,
                        tint = TealAccentBright,
                        modifier = Modifier.size(18.dp),
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = stringResource(R.string.hero_card_cta),
                        style = MaterialTheme.typography.labelLarge,
                        color = TealAccentBright,
                    )
                }
            }
        }
    }
}

@Composable
private fun InstallProgressBanner(
    stage: RomInstallStage,
    onDismiss: () -> Unit,
) {
    GlassCard(
        elevated = true,
        accentBorder = stage !is RomInstallStage.Failed,
        modifier = Modifier
            .fillMaxWidth()
            .testTag("rom_install_progress_banner"),
    ) {
        when (stage) {
            is RomInstallStage.Downloading -> {
                Text(
                    text = stringResource(
                        R.string.status_downloading,
                        stage.progressPercent,
                        stage.downloadedLabel,
                    ),
                    style = MaterialTheme.typography.titleMedium,
                    color = TealAccentBright,
                )
                Spacer(modifier = Modifier.height(10.dp))
                LinearProgressIndicator(
                    progress = { stage.progressPercent / 100f },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(6.dp)
                        .clip(CircleShape),
                    color = TealAccent,
                    trackColor = TealAccent.copy(alpha = 0.18f),
                )
            }
            RomInstallStage.VerifyingSha256 -> {
                IndeterminateStageRow(stringResource(R.string.status_verifying))
            }
            RomInstallStage.Extracting -> {
                IndeterminateStageRow(stringResource(R.string.status_extracting))
            }
            RomInstallStage.Importing -> {
                IndeterminateStageRow(stringResource(R.string.status_importing))
            }
            RomInstallStage.BuildingEngineRom -> {
                IndeterminateStageRow(stringResource(R.string.status_building_engine_rom))
            }
            is RomInstallStage.Completed -> {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                        modifier = Modifier.weight(1f),
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.CheckCircle,
                            contentDescription = null,
                            tint = MagiskEmerald,
                        )
                        Text(
                            text = "${stringResource(R.string.status_rom_ready)}: ${stage.systemName}",
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.onBackground,
                        )
                    }
                    IconButton(onClick = onDismiss, modifier = Modifier.size(48.dp)) {
                        Icon(
                            imageVector = Icons.Rounded.Close,
                            contentDescription = stringResource(R.string.action_skip_for_now),
                            tint = TextSecondary,
                        )
                    }
                }
            }
            is RomInstallStage.Failed -> {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                        modifier = Modifier.weight(1f),
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.ErrorOutline,
                            contentDescription = null,
                            tint = ErrorCoral,
                        )
                        Text(
                            text = stringResource(R.string.status_error_prefix, stage.reason),
                            style = MaterialTheme.typography.bodyMedium,
                            color = ErrorCoral,
                        )
                    }
                    IconButton(onClick = onDismiss, modifier = Modifier.size(48.dp)) {
                        Icon(
                            imageVector = Icons.Rounded.Close,
                            contentDescription = stringResource(R.string.action_skip_for_now),
                            tint = TextSecondary,
                        )
                    }
                }
            }
            RomInstallStage.Idle -> Unit
        }
    }
}

@Composable
private fun IndeterminateStageRow(label: String) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(
            text = label,
            style = MaterialTheme.typography.titleMedium,
            color = TealAccentBright,
        )
        Spacer(modifier = Modifier.height(10.dp))
        LinearProgressIndicator(
            modifier = Modifier
                .fillMaxWidth()
                .height(6.dp)
                .clip(CircleShape),
            color = TealAccent,
            trackColor = TealAccent.copy(alpha = 0.18f),
        )
    }
}

@Composable
private fun EmptySystemsCard() {
    GlassCard(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("empty_systems_card"),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(48.dp)
                    .clip(RoundedCornerShape(14.dp))
                    .background(TealAccent.copy(alpha = 0.12f)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = Icons.Rounded.SportsEsports,
                    contentDescription = null,
                    tint = TealAccent,
                )
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = stringResource(R.string.empty_systems_title),
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onBackground,
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = stringResource(R.string.empty_systems_body),
                    style = MaterialTheme.typography.bodyMedium,
                    color = TextSecondary,
                )
            }
        }
    }
}

@Composable
private fun VmSystemCard(
    system: VmSystem,
    isBooting: Boolean,
    onBootClick: () -> Unit,
    onGamingModeClick: () -> Unit,
    onPatchBootClick: () -> Unit,
) {
    val lastBootText = system.lastBootEpochMs?.let { epoch ->
        DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(epoch))
    } ?: stringResource(R.string.label_never_booted)

    GlassCard(
        elevated = true,
        modifier = Modifier
            .fillMaxWidth()
            .testTag("vm_system_card_${system.id}"),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.Top,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = system.name,
                    style = MaterialTheme.typography.titleLarge,
                    color = MaterialTheme.colorScheme.onBackground,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Android ${system.androidVersion} (API ${system.apiLevel}) · ${system.arch} · ${RomRepository.formatBytes(system.sizeBytes)}",
                    style = MaterialTheme.typography.labelMedium,
                    color = TextSecondary,
                )
            }
        }

        Spacer(modifier = Modifier.height(10.dp))
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (system.hasMagisk) {
                StatusPill(
                    label = stringResource(R.string.label_magisk_badge),
                    tint = MagiskEmerald,
                    icon = Icons.Rounded.Security,
                )
            }
            if (system.sha256Verified) {
                StatusPill(
                    label = stringResource(R.string.label_verified_badge),
                    tint = TealAccent,
                    icon = Icons.Rounded.Verified,
                )
            }
        }

        Spacer(modifier = Modifier.height(10.dp))
        Text(
            text = "${stringResource(R.string.label_last_boot)}: $lastBootText",
            style = MaterialTheme.typography.labelSmall,
            color = TextMuted,
        )

        Spacer(modifier = Modifier.height(14.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            TealGlowButton(
                text = if (isBooting) {
                    stringResource(R.string.action_booting_vm)
                } else {
                    stringResource(R.string.action_boot_vm)
                },
                icon = Icons.Rounded.PlayArrow,
                enabled = !isBooting,
                onClick = onBootClick,
                modifier = Modifier
                    .weight(1f)
                    .testTag("boot_vm_button_${system.id}"),
            )
            OutlinedButton(
                onClick = onGamingModeClick,
                modifier = Modifier
                    .defaultMinSize(minHeight = 48.dp)
                    .testTag("gaming_mode_button_${system.id}"),
                shape = RoundedCornerShape(14.dp),
                border = BorderStroke(1.dp, GlassBorderTeal),
            ) {
                Icon(
                    imageVector = Icons.Rounded.Tune,
                    contentDescription = null,
                    tint = TealAccentBright,
                    modifier = Modifier.size(18.dp),
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = stringResource(R.string.action_gaming_mode),
                    style = MaterialTheme.typography.labelLarge,
                    color = TealAccentBright,
                )
            }
        }

        Spacer(modifier = Modifier.height(8.dp))
        OutlinedButton(
            onClick = onPatchBootClick,
            modifier = Modifier
                .fillMaxWidth()
                .defaultMinSize(minHeight = 48.dp)
                .testTag("patch_boot_button_${system.id}"),
            shape = RoundedCornerShape(14.dp),
            border = BorderStroke(1.dp, MagiskEmerald.copy(alpha = 0.45f)),
        ) {
            Icon(
                imageVector = Icons.Rounded.Security,
                contentDescription = null,
                tint = MagiskEmerald,
                modifier = Modifier.size(18.dp),
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = stringResource(R.string.action_patch_boot),
                style = MaterialTheme.typography.labelLarge,
                color = MagiskEmerald,
            )
        }
    }
}

@Composable
private fun SystemInspectDialog(
    system: VmSystem,
    isBooting: Boolean,
    selectedProfileId: String,
    onSelectProfile: (String) -> Unit,
    onPatchExistingBoot: () -> Unit,
    onLaunchVm: () -> Unit,
    onDismiss: () -> Unit,
) {
    val activeProfile = DeviceProfile.ALL.firstOrNull { it.id == selectedProfileId }
        ?: DeviceProfile.ALL.first()
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = Color(0xFF0E1624),
        titleContentColor = MaterialTheme.colorScheme.onBackground,
        textContentColor = TextSecondary,
        title = {
            Text(
                text = system.name,
                style = MaterialTheme.typography.titleLarge,
            )
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    text = "Spoofed Identity: ${activeProfile.marketname} (${activeProfile.model})",
                    style = MaterialTheme.typography.titleSmall,
                    color = TealAccent,
                )
                Text(
                    text = activeProfile.fingerprint,
                    style = MaterialTheme.typography.labelSmall,
                    color = TextSecondary,
                )
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    DeviceProfile.ALL.take(4).forEach { profile ->
                        FilterChip(
                            selected = profile.id == selectedProfileId,
                            onClick = { onSelectProfile(profile.id) },
                            label = { Text(profile.displayName) },
                        )
                    }
                }
                Text(
                    text = "Marker: ${system.romMarker.ifEmpty { "custom" }}\nMagisk Root: ${if (system.hasMagisk) "Patched" else "Stock"}\nsystem.img SHA-256: ${system.systemSha256.take(16)}…",
                    style = MaterialTheme.typography.labelSmall,
                    color = TealAccentBright,
                )
                if (system.bootImagePath.isNotBlank()) {
                    OutlinedButton(
                        onClick = onPatchExistingBoot,
                        modifier = Modifier
                            .fillMaxWidth()
                            .defaultMinSize(minHeight = 48.dp)
                            .testTag("patch_existing_boot_button"),
                        border = BorderStroke(1.dp, MagiskEmerald.copy(alpha = 0.55f)),
                    ) {
                        Text(
                            text = "Patch Installed boot.img with Magisk v27.0",
                            color = MagiskEmerald,
                        )
                    }
                }
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Close", color = TextSecondary)
            }
        },
        confirmButton = {
            TextButton(
                onClick = onLaunchVm,
                enabled = !isBooting,
            ) {
                Text(
                    text = if (isBooting) {
                        stringResource(R.string.action_booting_vm)
                    } else {
                        stringResource(R.string.action_boot_vm)
                    },
                    color = TealAccent,
                )
            }
        },
    )
}

@Composable
private fun PhoneTelemetryDialog(
    telemetry: PhoneTelemetryState,
    logsTail: String,
    bootStage: String,
    bootStageDetail: String,
    tunedRamMb: Int,
    lastTrapSummary: String,
    bootTraceTail: String,
    onTiltLeft: () -> Unit,
    onTiltRight: () -> Unit,
    onResetTilt: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = Color(0xFF0E1624),
        titleContentColor = MaterialTheme.colorScheme.onBackground,
        textContentColor = TextSecondary,
        title = {
            Text(
                text = stringResource(R.string.telemetry_sheet_title),
                style = MaterialTheme.typography.titleLarge,
            )
        },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                TelemetryBlock(
                    title = stringResource(R.string.telemetry_section_renderer),
                    tint = CyanHighlight,
                    lines = listOf(
                        "GL_RENDERER: ${telemetry.glRenderer}",
                        "State: ${if (telemetry.running) "Running (${telemetry.activeBinary})" else "Standby"} · %.1f FPS".format(telemetry.guestFps),
                        "Draws: ${telemetry.drawCalls} · Triangles: ${telemetry.triangles} · Swaps: ${telemetry.framesSwapped}",
                    ),
                )
                TelemetryBlock(
                    title = stringResource(R.string.telemetry_section_magisk),
                    tint = MagiskEmerald,
                    lines = listOf(
                        "Magisk v${telemetry.magiskVersion}: ${if (telemetry.magiskDetected) "VERIFIED" else "Not Patched"}",
                        "Root su grants: ${telemetry.suGrants} ${if (telemetry.lastSuCaller.isNotBlank()) "(${telemetry.lastSuCaller})" else ""}",
                        "Identity: ${telemetry.marketname} (${telemetry.model})",
                    ),
                )
                TelemetryBlock(
                    title = stringResource(R.string.telemetry_section_sensors),
                    tint = TealAccent,
                    lines = listOf(
                        "Accel: %.2f, %.2f, %.2f m/s²".format(telemetry.accelX, telemetry.accelY, telemetry.accelZ),
                        "Gyro: %.3f, %.3f, %.3f rad/s".format(telemetry.gyroX, telemetry.gyroY, telemetry.gyroZ),
                        "Mag: %.1f, %.1f, %.1f µT".format(telemetry.magX, telemetry.magY, telemetry.magZ),
                        "Light: %.0f lux · Prox: %.1f cm · Baro: %.1f hPa".format(
                            telemetry.lightLux,
                            telemetry.proximityCm,
                            telemetry.pressureHpa,
                        ),
                        "Battery: ${telemetry.batteryPct}%% (%.1f°C) · SoC: %.1f°C · Cam frames: ${telemetry.cameraFrames}".format(
                            telemetry.batteryTempC,
                            telemetry.socTempC,
                        ),
                    ),
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    OutlinedButton(
                        onClick = onTiltLeft,
                        modifier = Modifier
                            .weight(1f)
                            .defaultMinSize(minHeight = 48.dp)
                            .testTag("tilt_left_button"),
                    ) {
                        Text(stringResource(R.string.telemetry_tilt_left), style = MaterialTheme.typography.labelSmall)
                    }
                    OutlinedButton(
                        onClick = onResetTilt,
                        modifier = Modifier
                            .weight(1f)
                            .defaultMinSize(minHeight = 48.dp)
                            .testTag("tilt_reset_button"),
                    ) {
                        Text(stringResource(R.string.telemetry_tilt_reset), style = MaterialTheme.typography.labelSmall)
                    }
                    OutlinedButton(
                        onClick = onTiltRight,
                        modifier = Modifier
                            .weight(1f)
                            .defaultMinSize(minHeight = 48.dp)
                            .testTag("tilt_right_button"),
                    ) {
                        Text(stringResource(R.string.telemetry_tilt_right), style = MaterialTheme.typography.labelSmall)
                    }
                }
                TelemetryBlock(
                    title = stringResource(R.string.telemetry_section_storage_net),
                    tint = TealAccentBright,
                    lines = listOf(
                        "/storage/emulated/0 -> ${telemetry.sharedStorageRoot.ifBlank { "<per-VM private dir>" }}",
                        "Virtio-Snd frames: ${telemetry.audioPlayFrames} (48kHz stereo)",
                        "NAT TX/RX: ${telemetry.netTxPackets}/${telemetry.netRxPackets} pkts · DNS: ${telemetry.dnsQueries}",
                    ),
                )
                TelemetryBlock(
                    title = stringResource(R.string.telemetry_section_framework),
                    tint = if (telemetry.frameworkServices.isNotEmpty()) MagiskEmerald else CyanHighlight,
                    lines = listOf(
                        "Tasks: ${telemetry.activeTasks} · Active binary: ${telemetry.activeBinary} · exit=${telemetry.exitCode}",
                        "Binder services (${telemetry.frameworkServices.size}): " +
                            telemetry.frameworkServices.joinToString(", ").ifBlank { "waiting for servicemanager" },
                    ),
                )
                val effectiveStage = telemetry.bootStage.takeIf { it.isNotBlank() && it != "IDLE" } ?: bootStage
                val effectiveRam = if (telemetry.effectiveRamMb > 0) telemetry.effectiveRamMb else tunedRamMb
                val effectiveTrap = telemetry.lastTrap.ifBlank { lastTrapSummary }
                TelemetryBlock(
                    title = stringResource(R.string.telemetry_section_crash_trace),
                    tint = if (effectiveTrap.isNotBlank()) ErrorCoral else TealAccent,
                    lines = buildList {
                        add(
                            "Stage: ${effectiveStage.ifBlank { "IDLE" }}" +
                                if (bootStageDetail.isNotBlank()) " — $bootStageDetail" else "",
                        )
                        add(
                            "Guest RAM: ${if (effectiveRam > 0) "$effectiveRam MiB (auto-tuned)" else "Pending"} · Insns: ${telemetry.instructionsExecuted}",
                        )
                        if (effectiveTrap.isNotBlank()) {
                            add("Trap: $effectiveTrap")
                        } else {
                            add("Trap: none")
                        }
                    },
                )
                val traceToDisplay = bootTraceTail.ifBlank { logsTail }
                if (traceToDisplay.isNotBlank()) {
                    Text(
                        text = traceToDisplay.takeLast(1400),
                        style = MaterialTheme.typography.labelSmall,
                        color = TextMuted,
                        modifier = Modifier.testTag("telemetry_crash_trace_tail"),
                    )
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = onDismiss,
                modifier = Modifier.testTag("close_telemetry_button"),
            ) {
                Text("Close", color = TealAccent)
            }
        },
    )
}

@Composable
private fun TelemetryBlock(
    title: String,
    tint: Color,
    lines: List<String>,
) {
    Surface(
        shape = RoundedCornerShape(12.dp),
        color = ObsidianSurface,
        border = BorderStroke(1.dp, tint.copy(alpha = 0.35f)),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(10.dp),
            verticalArrangement = Arrangement.spacedBy(3.dp),
        ) {
            Text(text = title, style = MaterialTheme.typography.labelMedium, color = tint)
            lines.forEach { line ->
                Text(
                    text = line,
                    style = MaterialTheme.typography.labelSmall,
                    color = TextSecondary,
                )
            }
        }
    }
}
