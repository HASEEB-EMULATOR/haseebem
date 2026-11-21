package com.haseeb.emulator

import android.view.Surface

/**
 * Full-System VM JNI Bridge (libhaseeb_vm.so).
 *
 * Error Codes (0 = success, negative = failure):
 *   0   VM_OK
 *  -1   ERR_INVALID_ARGUMENT
 *  -2   ERR_PATH_NOT_SET
 *  -3   ERR_FILE_NOT_FOUND
 *  -4   ERR_IO_FAILURE
 *  -5   ERR_INVALID_BOOT_IMAGE
 *  -6   ERR_UNSUPPORTED_VERSION
 *  -7   ERR_INVALID_SYSTEM_IMAGE
 *  -8   ERR_OUT_OF_MEMORY
 *  -9   ERR_ALREADY_RUNNING
 * -10   ERR_NOT_RUNNING
 * -11   ERR_SURFACE_ATTACH_FAILED
 * -12   ERR_GUEST_KERNEL_INVALID
 * -13   ERR_FDT_BUILD_FAILED
 * -14   ERR_EXECUTION_TRAP
 */
object Engine {
    @Volatile
    var nativeLibraryLoaded: Boolean = false
        private set

    @Volatile
    var nativeLoadError: String? = null
        private set

    init {
        try {
            System.loadLibrary("haseeb_vm")
            nativeLibraryLoaded = true
        } catch (t: Throwable) {
            nativeLibraryLoaded = false
            nativeLoadError = t.message ?: "Failed to load libhaseeb_vm.so"
        }
    }

    external fun setPath(dir: String): Int

    external fun setNativeLibDir(dir: String): Int

    external fun loadBootImage(path: String): Int

    external fun loadSystemImage(path: String): Int

    external fun start(api: Int, width: Int, height: Int, dpi: Int, ramMb: Int): Int

    external fun attachSurface(surface: Surface?): Int

    external fun sendTouch(action: Int, x: Int, y: Int, id: Int): Int

    external fun sendKey(code: Int, down: Boolean): Int

    external fun sendText(text: String): Int

    external fun setTargetFps(fps: Int): Int

    external fun readLog(maxBytes: Int): String

    external fun getGuestFps(): Float

    external fun isRunning(): Boolean

    external fun stop(): Int

    external fun configureDeviceProfile(
        model: String,
        brand: String,
        manufacturer: String,
        device: String,
        name: String,
        marketname: String,
        fingerprint: String,
        magiskPromptEnabled: Boolean,
    ): Int

    external fun patchBootImage(inputPath: String, outputPath: String): String

    external fun getPhoneTelemetry(): String

    external fun setSensorOverride(
        sensorType: Int,
        x: Float,
        y: Float,
        z: Float,
        active: Boolean,
    ): Int

    external fun drainAudioPcm(buffer: ShortArray, maxSamples: Int): Int

    external fun getBootStatus(): String

    external fun readBootTrace(maxBytes: Int): String

    external fun getEffectiveRamMb(): Int

    external fun buildEngineMagiskRom(outputDir: String): String
}
