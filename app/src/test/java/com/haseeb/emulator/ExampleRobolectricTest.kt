package com.haseeb.emulator

import android.app.ActivityManager
import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.haseeb.emulator.data.EmulatorRepository
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class ExampleRobolectricTest {

  @Test
  fun `read string from context`() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val appName = context.getString(R.string.app_name)
    assertEquals("HASEEB GAMING", appName)
  }

  @Test
  fun `auto tuned ram budget adapts to host memory`() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
    val shadowAm = Shadows.shadowOf(am)
    val repo = EmulatorRepository(context)

    val lowInfo = ActivityManager.MemoryInfo().apply {
      availMem = 600L * 1024L * 1024L
      totalMem = 3072L * 1024L * 1024L
      lowMemory = true
    }
    shadowAm.setMemoryInfo(lowInfo)
    val lowBudget = repo.computeAutoTunedRamBudget(1536)
    assertEquals(512, lowBudget.targetRamMb)
    assertTrue(lowBudget.lowMemory)

    val highInfo = ActivityManager.MemoryInfo().apply {
      availMem = 4096L * 1024L * 1024L
      totalMem = 8192L * 1024L * 1024L
      lowMemory = false
    }
    shadowAm.setMemoryInfo(highInfo)
    val highBudget = repo.computeAutoTunedRamBudget(2048)
    assertEquals(1536, highBudget.targetRamMb)
  }
}
