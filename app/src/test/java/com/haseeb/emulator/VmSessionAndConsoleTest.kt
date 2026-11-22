package com.haseeb.emulator

import android.app.Application
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ApplicationProvider
import com.haseeb.emulator.model.HomeUiState
import com.haseeb.emulator.model.PhoneTelemetryState
import com.haseeb.emulator.model.RomInstallStage
import com.haseeb.emulator.model.VmSessionViewMode
import com.haseeb.emulator.model.VmSystem
import com.haseeb.emulator.ui.home.HomeScreen
import com.haseeb.emulator.ui.home.HomeViewModel
import com.haseeb.emulator.ui.theme.HaseebGamingTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class VmSessionAndConsoleTest {

    @get:Rule
    val composeRule = createComposeRule()

    @Test
    fun `home ui state defaults keep console mode and persistent session fields`() {
        val state = HomeUiState()
        assertFalse(state.vmSessionVisible)
        assertEquals(VmSessionViewMode.SPLIT, state.sessionViewMode)
        assertEquals(0, state.vmExitCode)

        val telemetry = PhoneTelemetryState(
            frameworkServices = listOf("activity", "window", "magisk_su"),
            activeTasks = 6,
            exitCode = 0,
        )
        assertEquals(3, telemetry.frameworkServices.size)
        assertEquals(6, telemetry.activeTasks)
        val building: RomInstallStage = RomInstallStage.BuildingEngineRom
        assertTrue(building is RomInstallStage.BuildingEngineRom)
    }

    @Test
    fun `viewmodel switches session view modes cleanly`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        Dispatchers.setMain(dispatcher)
        try {
            val app = ApplicationProvider.getApplicationContext<Application>()
            val vm = HomeViewModel(app)
            advanceUntilIdle()

            assertEquals(VmSessionViewMode.SPLIT, vm.uiState.value.sessionViewMode)
            vm.setSessionViewMode(VmSessionViewMode.CONSOLE)
            assertEquals(VmSessionViewMode.CONSOLE, vm.uiState.value.sessionViewMode)
            vm.setSessionViewMode(VmSessionViewMode.DISPLAY)
            assertEquals(VmSessionViewMode.DISPLAY, vm.uiState.value.sessionViewMode)

            val fakeSystem = VmSystem(
                id = "vm_test",
                name = "Test ROM",
                androidVersion = "11",
                apiLevel = 30,
                arch = "arm64-v8a",
                hasMagisk = true,
                sha256Verified = true,
                romMarker = "test",
                systemImagePath = "/tmp/nonexistent_system.img",
                bootImagePath = "/tmp/nonexistent_boot.img",
                systemSha256 = "abc",
                bootSha256 = "def",
                sizeBytes = 1024L,
                lastBootEpochMs = null,
                installedAtEpochMs = 1L,
            )
            // When native lib isn't loaded on host Robolectric JVM, bootSystem fails gracefully
            // without crashing and closeVmSession resets visibility cleanly.
            vm.bootSystem(fakeSystem)
            advanceUntilIdle()
            vm.closeVmSession()
            advanceUntilIdle()
            assertFalse(vm.uiState.value.vmSessionVisible)
        } finally {
            Dispatchers.resetMain()
        }
    }

    @Test
    fun `home screen renders build engine rom button cleanly`() {
        val app = ApplicationProvider.getApplicationContext<Application>()
        val vm = HomeViewModel(app)
        composeRule.setContent {
            HaseebGamingTheme {
                HomeScreen(viewModel = vm)
            }
        }
        composeRule.waitForIdle()
        composeRule.onNodeWithTag("first_launch_build_engine_rom_button").assertIsDisplayed()
        composeRule.onNodeWithTag("open_telemetry_button").performClick()
        composeRule.waitForIdle()
        composeRule.onNodeWithText("Android Framework Services & Tasks").assertExists()
        composeRule.onNodeWithTag("close_telemetry_button").assertIsDisplayed()
        composeRule.onNodeWithTag("close_telemetry_button").performClick()
        composeRule.waitForIdle()
        composeRule.onNodeWithText("HASEEB GAMING").assertIsDisplayed()
    }
}
