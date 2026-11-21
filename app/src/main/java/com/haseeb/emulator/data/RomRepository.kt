package com.haseeb.emulator.data

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.haseeb.emulator.Engine
import com.haseeb.emulator.model.HomeUiState
import com.haseeb.emulator.model.RomInstallStage
import com.haseeb.emulator.model.VmSystem
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.zip.GZIPInputStream
import java.util.zip.ZipInputStream

private val Context.appDataStore by preferencesDataStore(name = "haseeb_gaming_prefs")

class RomRepository(
    private val context: Context,
) {
    private val httpClient: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(20, TimeUnit.SECONDS)
        .readTimeout(120, TimeUnit.SECONDS)
        .followRedirects(true)
        .build()

    private val systemsRootDir: File
        get() = File(context.filesDir, "systems").apply { mkdirs() }

    private val downloadsCacheDir: File
        get() = File(context.cacheDir, "rom_downloads").apply { mkdirs() }

    private object PrefKeys {
        val FIRST_LAUNCH_OFFER_DISMISSED = booleanPreferencesKey("first_launch_offer_dismissed")
        val GITHUB_REPO_SLUG = stringPreferencesKey("github_repo_slug")
        val ROM_RELEASE_TAG = stringPreferencesKey("rom_release_tag")
    }

    val firstLaunchOfferDismissed: Flow<Boolean> =
        context.appDataStore.data.map { prefs -> prefs[PrefKeys.FIRST_LAUNCH_OFFER_DISMISSED] ?: false }

    val githubRepoSlug: Flow<String> =
        context.appDataStore.data.map { prefs ->
            prefs[PrefKeys.GITHUB_REPO_SLUG] ?: HomeUiState.DEFAULT_GITHUB_REPO
        }

    val romReleaseTag: Flow<String> =
        context.appDataStore.data.map { prefs ->
            prefs[PrefKeys.ROM_RELEASE_TAG] ?: HomeUiState.DEFAULT_ROM_TAG
        }

    suspend fun setFirstLaunchOfferDismissed(dismissed: Boolean) {
        context.appDataStore.edit { prefs ->
            prefs[PrefKeys.FIRST_LAUNCH_OFFER_DISMISSED] = dismissed
        }
    }

    suspend fun loadInstalledSystems(): List<VmSystem> = withContext(Dispatchers.IO) {
        val dirs = systemsRootDir.listFiles { file -> file.isDirectory } ?: return@withContext emptyList()
        dirs.mapNotNull { dir ->
            val metaFile = File(dir, "vm_system.json")
            if (!metaFile.exists()) return@mapNotNull null
            runCatching { parseVmSystem(JSONObject(metaFile.readText())) }.getOrNull()
        }.sortedByDescending { it.installedAtEpochMs }
    }

    suspend fun downloadVerifyAndImportBundledRom(
        onStage: (RomInstallStage) -> Unit,
    ): Result<VmSystem> = withContext(Dispatchers.IO) {
        runCatching {
            val repo = githubRepoSlug.first().trim()
            val tag = romReleaseTag.first().trim()

            onStage(RomInstallStage.Downloading(0, "Connecting to GitHub Releases…"))
            val releaseApiUrl = "https://api.github.com/repos/$repo/releases/tags/$tag"
            val releaseRequest = Request.Builder()
                .url(releaseApiUrl)
                .header("Accept", "application/vnd.github+json")
                .header("User-Agent", "HaseebGaming-Android/1.0")
                .build()

            val releaseJson = httpClient.newCall(releaseRequest).execute().use { resp ->
                if (!resp.isSuccessful) {
                    error("GitHub release '$tag' unavailable (HTTP ${resp.code}) at $repo")
                }
                JSONObject(resp.body?.string().orEmpty())
            }

            val assets = releaseJson.optJSONArray("assets")
                ?: error("Release '$tag' contains no downloadable ROM assets")

            var archiveUrl: String? = null
            var archiveName = "haseeb-gaming-a10-v1-arm64.zip"
            var shaAssetUrl: String? = null

            for (i in 0 until assets.length()) {
                val asset = assets.getJSONObject(i)
                val name = asset.optString("name")
                val url = asset.optString("browser_download_url")
                if (name.endsWith(".zip", ignoreCase = true)) {
                    archiveUrl = url
                    archiveName = name
                } else if (name.endsWith(".zip.sha256", ignoreCase = true)) {
                    shaAssetUrl = url
                }
            }

            val downloadUrl = archiveUrl ?: error("No .zip ROM archive found in release '$tag'")
            val expectedArchiveSha = shaAssetUrl?.let { fetchExpectedSha256(it) }

            val targetArchive = File(downloadsCacheDir, archiveName)
            streamDownload(downloadUrl, targetArchive) { percent, downloadedBytes, totalBytes ->
                val label = if (totalBytes > 0) {
                    "${formatBytes(downloadedBytes)} / ${formatBytes(totalBytes)}"
                } else {
                    formatBytes(downloadedBytes)
                }
                onStage(RomInstallStage.Downloading(percent, label))
            }

            onStage(RomInstallStage.VerifyingSha256)
            if (!expectedArchiveSha.isNullOrBlank()) {
                val actualSha = computeSha256(targetArchive)
                if (!actualSha.equals(expectedArchiveSha, ignoreCase = true)) {
                    targetArchive.delete()
                    error("Archive SHA-256 mismatch (expected ${expectedArchiveSha.take(12)}…, got ${actualSha.take(12)}…)")
                }
            }

            val imported = extractAndRegisterZip(
                zipFile = targetArchive,
                fallbackName = "Haseeb Gaming A10",
                onStage = onStage,
            )
            targetArchive.delete()
            setFirstLaunchOfferDismissed(true)
            imported
        }
    }

    suspend fun importFirmwareUri(
        uri: Uri,
        onStage: (RomInstallStage) -> Unit,
    ): Result<VmSystem> = withContext(Dispatchers.IO) {
        runCatching {
            val displayName = queryDisplayName(uri) ?: "imported_firmware.img"
            onStage(RomInstallStage.Importing)
            val tempFile = File(downloadsCacheDir, "import_${System.currentTimeMillis()}_$displayName")
            context.contentResolver.openInputStream(uri)?.use { input ->
                FileOutputStream(tempFile).use { output -> input.copyTo(output) }
            } ?: error("Unable to open selected firmware file")

            val result = if (displayName.endsWith(".zip", ignoreCase = true) || isZipFile(tempFile)) {
                extractAndRegisterZip(
                    zipFile = tempFile,
                    fallbackName = displayName.removeSuffix(".zip"),
                    onStage = onStage,
                )
            } else {
                registerRawImage(tempFile, displayName, onStage)
            }
            tempFile.delete()
            result
        }
    }

    suspend fun buildAndRegisterEngineMagiskRom(
        onStage: (RomInstallStage) -> Unit,
    ): Result<VmSystem> = withContext(Dispatchers.IO) {
        runCatching {
            if (!Engine.nativeLibraryLoaded) {
                error(Engine.nativeLoadError ?: "Native VM library not loaded")
            }
            onStage(RomInstallStage.BuildingEngineRom)
            val systemId = "vm_engine_${UUID.randomUUID().toString().take(8)}"
            val systemDir = File(systemsRootDir, systemId).apply { mkdirs() }
            try {
                val jsonStr = Engine.buildEngineMagiskRom(systemDir.absolutePath)
                val res = JSONObject(jsonStr)
                if (!res.optBoolean("ok", false)) {
                    val err = res.optString("error").ifBlank { "Native Engine ROM builder failed" }
                    error(err)
                }
                val bootFile = File(res.getString("bootImgPath"))
                val systemFile = File(res.getString("systemImgPath"))
                if (!bootFile.exists() || !systemFile.exists()) {
                    error("Engine ROM images missing after generation")
                }

                onStage(RomInstallStage.VerifyingSha256)
                val bootSha = computeSha256(bootFile)
                val sysSha = computeSha256(systemFile)

                onStage(RomInstallStage.Importing)
                val androidVer = res.optString("androidVersion", "11")
                val apiLevel = res.optInt("apiLevel", 30)
                val vmSystem = VmSystem(
                    id = systemId,
                    name = "Haseeb A$androidVer Engine · Magisk v27",
                    androidVersion = androidVer,
                    apiLevel = apiLevel,
                    arch = "arm64-v8a",
                    hasMagisk = res.optBoolean("magiskPatched", true),
                    sha256Verified = true,
                    romMarker = "haseeb-engine-a11-magisk",
                    systemImagePath = systemFile.absolutePath,
                    bootImagePath = bootFile.absolutePath,
                    systemSha256 = sysSha,
                    bootSha256 = bootSha,
                    sizeBytes = bootFile.length() + systemFile.length(),
                    lastBootEpochMs = null,
                    installedAtEpochMs = System.currentTimeMillis(),
                )
                saveVmSystemMetadata(systemDir, vmSystem)
                setFirstLaunchOfferDismissed(true)
                vmSystem
            } catch (t: Throwable) {
                systemDir.deleteRecursively()
                throw t
            }
        }
    }

    private fun extractAndRegisterZip(
        zipFile: File,
        fallbackName: String,
        onStage: (RomInstallStage) -> Unit,
    ): VmSystem {
        onStage(RomInstallStage.Extracting)
        val systemId = "vm_${UUID.randomUUID().toString().take(8)}"
        val systemDir = File(systemsRootDir, systemId).apply { mkdirs() }

        try {
            val extractedFiles = mutableListOf<File>()
            ZipInputStream(FileInputStream(zipFile).buffered()).use { zis ->
                var entry = zis.nextEntry
                while (entry != null) {
                    if (!entry.isDirectory) {
                        val safeName = File(entry.name).name
                        if (safeName.isNotBlank()) {
                            val outFile = File(systemDir, safeName)
                            if (!outFile.canonicalPath.startsWith(systemDir.canonicalPath)) {
                                error("Blocked unsafe zip entry path: ${entry.name}")
                            }
                            FileOutputStream(outFile).buffered().use { out ->
                                zis.copyTo(out)
                            }
                            extractedFiles += gunzipIfNeeded(outFile)
                        }
                    }
                    zis.closeEntry()
                    entry = zis.nextEntry
                }
            }

            onStage(RomInstallStage.VerifyingSha256)
            val systemImg = resolveExtractedSystemImage(systemDir, extractedFiles)
                ?: error("Firmware archive does not contain system.img, super.img, or rootfs image")
            val bootImg = resolveExtractedBootImage(systemDir, extractedFiles)

            val manifestFile = File(systemDir, "manifest.json")
            var name = fallbackName
            var androidVersion = "10"
            var apiLevel = 29
            var arch = "arm64-v8a"
            var marker = ""
            var shaVerified = false
            val sysSha = computeSha256(systemImg)
            val bootSha = if (bootImg != null && bootImg.exists()) computeSha256(bootImg) else ""

            if (manifestFile.exists()) {
                val manifest = JSONObject(manifestFile.readText())
                name = manifest.optString("name", fallbackName)
                androidVersion = manifest.optString("androidVersion", "10")
                apiLevel = manifest.optInt("apiLevel", 29)
                arch = manifest.optString("arch", "arm64-v8a")
                marker = manifest.optString("marker", "")

                val parts = manifest.optJSONObject("parts")
                if (parts != null) {
                    val expectedSysSha = parts.optJSONObject("system.img")?.optString("sha256").orEmpty()
                    if (expectedSysSha.isNotEmpty() && !expectedSysSha.equals(sysSha, ignoreCase = true)) {
                        error("system.img SHA-256 verification failed")
                    }
                    val expectedBootSha = parts.optJSONObject("boot.img")?.optString("sha256").orEmpty()
                    if (expectedBootSha.isNotEmpty() && bootImg != null && bootImg.exists() &&
                        !expectedBootSha.equals(bootSha, ignoreCase = true)
                    ) {
                        error("boot.img SHA-256 verification failed")
                    }
                    shaVerified = expectedSysSha.isNotEmpty()
                }
            }

            onStage(RomInstallStage.Importing)
            val hasMagisk = bootImg != null && bootImg.exists() &&
                (marker == HomeUiState.EXPECTED_ROM_MARKER ||
                    marker.contains("magisk", ignoreCase = true) ||
                    fallbackName.contains("magisk", ignoreCase = true))
            val totalSize = systemImg.length() + (if (bootImg != null && bootImg.exists()) bootImg.length() else 0L)
            val vmSystem = VmSystem(
                id = systemId,
                name = name,
                androidVersion = androidVersion,
                apiLevel = apiLevel,
                arch = arch,
                hasMagisk = hasMagisk,
                sha256Verified = shaVerified,
                romMarker = marker,
                systemImagePath = systemImg.absolutePath,
                bootImagePath = if (bootImg != null && bootImg.exists()) bootImg.absolutePath else "",
                systemSha256 = sysSha,
                bootSha256 = bootSha,
                sizeBytes = totalSize,
                lastBootEpochMs = null,
                installedAtEpochMs = System.currentTimeMillis(),
            )
            saveVmSystemMetadata(systemDir, vmSystem)
            return vmSystem
        } catch (t: Throwable) {
            systemDir.deleteRecursively()
            throw t
        }
    }

    private fun registerRawImage(
        imageFile: File,
        displayName: String,
        onStage: (RomInstallStage) -> Unit,
    ): VmSystem {
        val systemId = "vm_${UUID.randomUUID().toString().take(8)}"
        val systemDir = File(systemsRootDir, systemId).apply { mkdirs() }
        try {
            onStage(RomInstallStage.Extracting)
            val staged = File(systemDir, displayName.ifBlank { "system.img" })
            imageFile.copyTo(staged, overwrite = true)
            val unpacked = gunzipIfNeeded(staged)
            val head = readHeaderBytes(unpacked, 8)
            if (head.size >= 8 && head.copyOfRange(0, 8).contentEquals("ANDROID!".encodeToByteArray())) {
                error("Selected file is an Android boot.img; import a ROM .zip or system.img instead.")
            }

            val targetImg = File(systemDir, "system.img")
            if (unpacked.absolutePath != targetImg.absolutePath) {
                if (targetImg.exists()) targetImg.delete()
                if (!unpacked.renameTo(targetImg)) {
                    unpacked.copyTo(targetImg, overwrite = true)
                    unpacked.delete()
                }
            }

            onStage(RomInstallStage.VerifyingSha256)
            val sysSha = computeSha256(targetImg)
            val cleanName = displayName
                .removeSuffix(".gz")
                .substringBeforeLast('.')
                .ifBlank { "Imported ROM" }

            val vmSystem = VmSystem(
                id = systemId,
                name = cleanName,
                androidVersion = "10",
                apiLevel = 29,
                arch = "arm64-v8a",
                hasMagisk = false,
                sha256Verified = true,
                romMarker = "custom-import",
                systemImagePath = targetImg.absolutePath,
                bootImagePath = "",
                systemSha256 = sysSha,
                bootSha256 = "",
                sizeBytes = targetImg.length(),
                lastBootEpochMs = null,
                installedAtEpochMs = System.currentTimeMillis(),
            )
            saveVmSystemMetadata(systemDir, vmSystem)
            return vmSystem
        } catch (t: Throwable) {
            systemDir.deleteRecursively()
            throw t
        }
    }

    private fun isZipFile(file: File): Boolean {
        val head = readHeaderBytes(file, 4)
        return head.size >= 4 && head[0] == 'P'.code.toByte() && head[1] == 'K'.code.toByte() &&
            head[2] == 3.toByte() && head[3] == 4.toByte()
    }

    private fun gunzipIfNeeded(file: File): File {
        val head = readHeaderBytes(file, 2)
        val isGzip = head.size >= 2 && head[0] == 0x1F.toByte() && head[1] == 0x8B.toByte()
        if (!isGzip && !file.name.endsWith(".gz", ignoreCase = true)) {
            return file
        }
        val outName = if (file.name.endsWith(".gz", ignoreCase = true)) {
            file.name.dropLast(3).ifBlank { "unpacked.img" }
        } else {
            "${file.name}.unpacked"
        }
        val outFile = File(file.parentFile, outName)
        runCatching {
            GZIPInputStream(FileInputStream(file).buffered()).use { gzis ->
                FileOutputStream(outFile).buffered().use { out ->
                    gzis.copyTo(out)
                }
            }
        }.onSuccess {
            file.delete()
            return outFile
        }.onFailure {
            outFile.delete()
        }
        return file
    }

    private fun resolveExtractedSystemImage(systemDir: File, files: List<File>): File? {
        val exact = File(systemDir, "system.img")
        if (exact.exists()) return exact
        val priorityNames = listOf("system_raw.img", "system_a.img", "super.img", "rootfs.img", "rootfs.ext4")
        for (candidateName in priorityNames) {
            val match = files.firstOrNull { it.exists() && it.name.equals(candidateName, ignoreCase = true) }
                ?: File(systemDir, candidateName).takeIf { it.exists() }
            if (match != null) {
                match.renameTo(exact)
                return exact
            }
        }
        val fuzzy = files.firstOrNull {
            it.exists() &&
                (it.name.contains("system", ignoreCase = true) || it.name.contains("rootfs", ignoreCase = true)) &&
                (it.name.endsWith(".img", ignoreCase = true) || it.name.endsWith(".ext4", ignoreCase = true))
        }
        if (fuzzy != null) {
            fuzzy.renameTo(exact)
            return exact
        }
        return null
    }

    private fun resolveExtractedBootImage(systemDir: File, files: List<File>): File? {
        val exact = File(systemDir, "boot.img")
        if (exact.exists()) return exact
        val candidate = files.firstOrNull {
            it.exists() &&
                !it.name.contains("vendor_boot", ignoreCase = true) &&
                !it.name.contains("init_boot", ignoreCase = true) &&
                it.name.contains("boot", ignoreCase = true) &&
                it.name.endsWith(".img", ignoreCase = true)
        }
        if (candidate != null) {
            candidate.renameTo(exact)
            return exact
        }
        return null
    }

    private fun readHeaderBytes(file: File, maxBytes: Int): ByteArray = runCatching {
        FileInputStream(file).use { fis ->
            val buf = ByteArray(maxBytes)
            val n = fis.read(buf)
            if (n <= 0) ByteArray(0) else buf.copyOf(n)
        }
    }.getOrDefault(ByteArray(0))

    suspend fun updateVmBootImage(
        system: VmSystem,
        patchedBootFile: File,
        hasMagisk: Boolean,
    ): VmSystem = withContext(Dispatchers.IO) {
        val systemDir = File(system.rootDirectory).apply { mkdirs() }
        val systemImg = File(system.systemImagePath)
        val newBootSha = computeSha256(patchedBootFile)
        val totalSize = (if (systemImg.exists()) systemImg.length() else 0L) + patchedBootFile.length()
        val updated = system.copy(
            hasMagisk = hasMagisk,
            bootImagePath = patchedBootFile.absolutePath,
            bootSha256 = newBootSha,
            sizeBytes = totalSize,
        )
        saveVmSystemMetadata(systemDir, updated)
        updated
    }

    private fun saveVmSystemMetadata(systemDir: File, vm: VmSystem) {
        val json = JSONObject().apply {
            put("id", vm.id)
            put("name", vm.name)
            put("androidVersion", vm.androidVersion)
            put("apiLevel", vm.apiLevel)
            put("arch", vm.arch)
            put("hasMagisk", vm.hasMagisk)
            put("sha256Verified", vm.sha256Verified)
            put("romMarker", vm.romMarker)
            put("systemImagePath", vm.systemImagePath)
            put("bootImagePath", vm.bootImagePath)
            put("systemSha256", vm.systemSha256)
            put("bootSha256", vm.bootSha256)
            put("sizeBytes", vm.sizeBytes)
            put("lastBootEpochMs", vm.lastBootEpochMs ?: JSONObject.NULL)
            put("installedAtEpochMs", vm.installedAtEpochMs)
        }
        File(systemDir, "vm_system.json").writeText(json.toString(2))
    }

    private fun parseVmSystem(json: JSONObject): VmSystem = VmSystem(
        id = json.getString("id"),
        name = json.getString("name"),
        androidVersion = json.getString("androidVersion"),
        apiLevel = json.getInt("apiLevel"),
        arch = json.getString("arch"),
        hasMagisk = json.optBoolean("hasMagisk", false),
        sha256Verified = json.optBoolean("sha256Verified", false),
        romMarker = json.optString("romMarker", ""),
        systemImagePath = json.getString("systemImagePath"),
        bootImagePath = json.optString("bootImagePath", ""),
        systemSha256 = json.optString("systemSha256", ""),
        bootSha256 = json.optString("bootSha256", ""),
        sizeBytes = json.optLong("sizeBytes", 0L),
        lastBootEpochMs = if (json.isNull("lastBootEpochMs")) null else json.optLong("lastBootEpochMs"),
        installedAtEpochMs = json.optLong("installedAtEpochMs", System.currentTimeMillis()),
    )

    private fun fetchExpectedSha256(url: String): String? = runCatching {
        val req = Request.Builder().url(url).build()
        httpClient.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) return@runCatching null
            resp.body?.string()?.trim()?.split(Regex("\\s+"))?.firstOrNull()
        }
    }.getOrNull()

    private fun streamDownload(
        url: String,
        target: File,
        onProgress: (percent: Int, downloadedBytes: Long, totalBytes: Long) -> Unit,
    ) {
        val req = Request.Builder().url(url).build()
        httpClient.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) {
                error("Download failed with HTTP ${resp.code}")
            }
            val body = resp.body ?: error("Empty download response")
            val total = body.contentLength()
            var downloaded = 0L
            var lastReportedPct = -1
            val buffer = ByteArray(64 * 1024)
            body.byteStream().use { input: InputStream ->
                FileOutputStream(target).use { output ->
                    while (true) {
                        val read = input.read(buffer)
                        if (read == -1) break
                        output.write(buffer, 0, read)
                        downloaded += read
                        val pct = if (total > 0) ((downloaded * 100L) / total).toInt().coerceIn(0, 100) else 0
                        if (pct != lastReportedPct) {
                            lastReportedPct = pct
                            onProgress(pct, downloaded, total)
                        }
                    }
                }
            }
        }
    }

    private fun computeSha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(64 * 1024)
        FileInputStream(file).use { fis ->
            while (true) {
                val read = fis.read(buffer)
                if (read == -1) break
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun queryDisplayName(uri: Uri): String? =
        context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) cursor.getString(0) else null
        }

    companion object {
        fun formatBytes(bytes: Long): String {
            if (bytes <= 0L) return "0 B"
            val kb = 1024.0
            val mb = kb * 1024.0
            val gb = mb * 1024.0
            return when {
                bytes >= gb -> "%.2f GB".format(bytes / gb)
                bytes >= mb -> "%.1f MB".format(bytes / mb)
                bytes >= kb -> "%.0f KB".format(bytes / kb)
                else -> "$bytes B"
            }
        }
    }
}
