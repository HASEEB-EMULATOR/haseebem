#include "haseeb/engine_runtime.hpp"

#include <android/native_window_jni.h>
#include <jni.h>
#include <string>

namespace {

std::string JStringToStd(JNIEnv* env, jstring s) {
    if (!s) return "";
    const char* p = env->GetStringUTFChars(s, nullptr);
    std::string out(p ? p : "");
    if (p) env->ReleaseStringUTFChars(s, p);
    return out;
}

jint AsJint(haseeb::vm::VmError err) {
    return static_cast<jint>(err);
}

} // namespace

extern "C" {

JNIEXPORT jint JNICALL
Java_com_haseeb_emulator_Engine_setPath(JNIEnv* env, jobject /* thiz */, jstring dir) {
    return AsJint(haseeb::engine::EngineRuntime::Instance().SetPath(JStringToStd(env, dir)));
}

JNIEXPORT jint JNICALL
Java_com_haseeb_emulator_Engine_setNativeLibDir(JNIEnv* env, jobject /* thiz */, jstring dir) {
    return AsJint(haseeb::engine::EngineRuntime::Instance().SetNativeLibDir(JStringToStd(env, dir)));
}

JNIEXPORT jint JNICALL
Java_com_haseeb_emulator_Engine_loadBootImage(JNIEnv* env, jobject /* thiz */, jstring path) {
    return AsJint(haseeb::engine::EngineRuntime::Instance().LoadBootImage(JStringToStd(env, path)));
}

JNIEXPORT jint JNICALL
Java_com_haseeb_emulator_Engine_loadSystemImage(JNIEnv* env, jobject /* thiz */, jstring path) {
    return AsJint(haseeb::engine::EngineRuntime::Instance().LoadSystemImage(JStringToStd(env, path)));
}

JNIEXPORT jint JNICALL
Java_com_haseeb_emulator_Engine_start(
    JNIEnv* /* env */,
    jobject /* thiz */,
    jint api,
    jint width,
    jint height,
    jint dpi,
    jint ram_mb
) {
    return AsJint(haseeb::engine::EngineRuntime::Instance().Start(api, width, height, dpi, ram_mb));
}

JNIEXPORT jint JNICALL
Java_com_haseeb_emulator_Engine_attachSurface(JNIEnv* env, jobject /* thiz */, jobject surface) {
    ANativeWindow* window = surface ? ANativeWindow_fromSurface(env, surface) : nullptr;
    return AsJint(haseeb::engine::EngineRuntime::Instance().AttachSurface(window));
}

JNIEXPORT jint JNICALL
Java_com_haseeb_emulator_Engine_sendTouch(
    JNIEnv* /* env */,
    jobject /* thiz */,
    jint action,
    jint x,
    jint y,
    jint id
) {
    return AsJint(haseeb::engine::EngineRuntime::Instance().SendTouch(action, x, y, id));
}

JNIEXPORT jint JNICALL
Java_com_haseeb_emulator_Engine_sendKey(
    JNIEnv* /* env */,
    jobject /* thiz */,
    jint code,
    jboolean down
) {
    return AsJint(haseeb::engine::EngineRuntime::Instance().SendKey(code, down == JNI_TRUE));
}

JNIEXPORT jint JNICALL
Java_com_haseeb_emulator_Engine_sendText(JNIEnv* env, jobject /* thiz */, jstring text) {
    return AsJint(haseeb::engine::EngineRuntime::Instance().SendText(JStringToStd(env, text)));
}

JNIEXPORT jint JNICALL
Java_com_haseeb_emulator_Engine_setTargetFps(JNIEnv* /* env */, jobject /* thiz */, jint fps) {
    return AsJint(haseeb::engine::EngineRuntime::Instance().SetTargetFps(fps));
}

JNIEXPORT jstring JNICALL
Java_com_haseeb_emulator_Engine_readLog(JNIEnv* env, jobject /* thiz */, jint max_bytes) {
    std::string log = haseeb::engine::EngineRuntime::Instance().ReadLog(max_bytes);
    return env->NewStringUTF(log.c_str());
}

JNIEXPORT jfloat JNICALL
Java_com_haseeb_emulator_Engine_getGuestFps(JNIEnv* /* env */, jobject /* thiz */) {
    return haseeb::engine::EngineRuntime::Instance().GetGuestFps();
}

JNIEXPORT jboolean JNICALL
Java_com_haseeb_emulator_Engine_isRunning(JNIEnv* /* env */, jobject /* thiz */) {
    return haseeb::engine::EngineRuntime::Instance().IsRunning() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL
Java_com_haseeb_emulator_Engine_stop(JNIEnv* /* env */, jobject /* thiz */) {
    return AsJint(haseeb::engine::EngineRuntime::Instance().Stop());
}

JNIEXPORT jint JNICALL
Java_com_haseeb_emulator_Engine_configureDeviceProfile(
    JNIEnv* env,
    jobject /* thiz */,
    jstring model,
    jstring brand,
    jstring manufacturer,
    jstring device,
    jstring name,
    jstring marketname,
    jstring fingerprint,
    jboolean magisk_prompt_enabled
) {
    haseeb::engine::GuestConfig cfg;
    cfg.model = JStringToStd(env, model);
    cfg.brand = JStringToStd(env, brand);
    cfg.manufacturer = JStringToStd(env, manufacturer);
    cfg.device = JStringToStd(env, device);
    cfg.name = JStringToStd(env, name);
    cfg.marketname = JStringToStd(env, marketname);
    cfg.fingerprint = JStringToStd(env, fingerprint);
    cfg.magisk_prompt_enabled = (magisk_prompt_enabled == JNI_TRUE);
    haseeb::engine::EngineRuntime::Instance().ConfigureGuestProps(cfg);
    return 0;
}

JNIEXPORT jstring JNICALL
Java_com_haseeb_emulator_Engine_patchBootImage(
    JNIEnv* env,
    jobject /* thiz */,
    jstring input_path,
    jstring output_path
) {
    const auto res = haseeb::engine::EngineRuntime::Instance().PatchBootImage(
        JStringToStd(env, input_path), JStringToStd(env, output_path));
    auto esc = [](const std::string& s) {
        std::string out;
        for (char c : s) {
            if (c == '\"') out += "\\\"";
            else if (c == '\\') out += "\\\\";
            else if (c == '\n') out += "\\n";
            else if (static_cast<unsigned char>(c) >= 0x20u) out.push_back(c);
        }
        return out;
    };
    const std::string json =
        std::string("{\"ok\":") + (res.ok ? "true" : "false") +
        ",\"verified\":" + (res.verified ? "true" : "false") +
        ",\"headerVersion\":" + std::to_string(res.patched_header_version) +
        ",\"ramdiskEntries\":" + std::to_string(res.patched_ramdisk_entries) +
        ",\"summary\":\"" + esc(res.verification_summary) + "\"" +
        ",\"error\":\"" + esc(res.error) + "\"}";
    return env->NewStringUTF(json.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_haseeb_emulator_Engine_getPhoneTelemetry(JNIEnv* env, jobject /* thiz */) {
    const std::string json = haseeb::engine::EngineRuntime::Instance().GetPhoneTelemetryJson();
    return env->NewStringUTF(json.c_str());
}

JNIEXPORT jint JNICALL
Java_com_haseeb_emulator_Engine_setSensorOverride(
    JNIEnv* /* env */,
    jobject /* thiz */,
    jint sensor_type,
    jfloat x,
    jfloat y,
    jfloat z,
    jboolean active
) {
    return AsJint(haseeb::engine::EngineRuntime::Instance().SetSensorOverride(
        static_cast<uint32_t>(sensor_type), x, y, z, active == JNI_TRUE));
}

JNIEXPORT jint JNICALL
Java_com_haseeb_emulator_Engine_drainAudioPcm(
    JNIEnv* env,
    jobject /* thiz */,
    jshortArray buffer,
    jint max_samples
) {
    if (!buffer || max_samples <= 0) return 0;
    const jsize arr_len = env->GetArrayLength(buffer);
    const size_t cap = static_cast<size_t>(arr_len < max_samples ? arr_len : max_samples);
    jshort* elems = env->GetShortArrayElements(buffer, nullptr);
    if (!elems) return 0;
    const size_t got = haseeb::engine::EngineRuntime::Instance().DrainAudioPcm(
        reinterpret_cast<int16_t*>(elems), cap);
    env->ReleaseShortArrayElements(buffer, elems, 0);
    return static_cast<jint>(got);
}

JNIEXPORT jstring JNICALL
Java_com_haseeb_emulator_Engine_getBootStatus(JNIEnv* env, jobject /* thiz */) {
    const std::string json = haseeb::engine::EngineRuntime::Instance().GetBootStatusJson();
    return env->NewStringUTF(json.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_haseeb_emulator_Engine_readBootTrace(JNIEnv* env, jobject /* thiz */, jint max_bytes) {
    const std::string trace = haseeb::engine::EngineRuntime::Instance().ReadBootTrace(max_bytes);
    return env->NewStringUTF(trace.c_str());
}

JNIEXPORT jint JNICALL
Java_com_haseeb_emulator_Engine_getEffectiveRamMb(JNIEnv* /* env */, jobject /* thiz */) {
    return static_cast<jint>(haseeb::engine::EngineRuntime::Instance().GetEffectiveRamMb());
}

JNIEXPORT jstring JNICALL
Java_com_haseeb_emulator_Engine_buildEngineMagiskRom(
    JNIEnv* env,
    jobject /* thiz */,
    jstring output_dir
) {
    const auto res = haseeb::engine::EngineRuntime::Instance().BuildEngineMagiskRom(
        JStringToStd(env, output_dir));
    auto esc = [](const std::string& s) {
        std::string out;
        for (char c : s) {
            if (c == '\"') out += "\\\"";
            else if (c == '\\') out += "\\\\";
            else if (c == '\n') out += "\\n";
            else if (static_cast<unsigned char>(c) >= 0x20u) out.push_back(c);
        }
        return out;
    };
    const std::string json =
        std::string("{\"ok\":") + (res.ok ? "true" : "false") +
        ",\"bootImgPath\":\"" + esc(res.boot_img_path) + "\"" +
        ",\"systemImgPath\":\"" + esc(res.system_img_path) + "\"" +
        ",\"bootSize\":" + std::to_string(res.boot_img_size) +
        ",\"systemSize\":" + std::to_string(res.system_img_size) +
        ",\"ramdiskEntries\":" + std::to_string(res.ramdisk_entries) +
        ",\"systemFiles\":" + std::to_string(res.system_files) +
        ",\"magiskPatched\":" + (res.magisk_patched ? "true" : "false") +
        ",\"magiskVersion\":\"" + esc(res.magisk_version) + "\"" +
        ",\"androidVersion\":\"" + esc(res.android_version) + "\"" +
        ",\"apiLevel\":" + std::to_string(res.api_level) +
        ",\"error\":\"" + esc(res.error) + "\"}";
    return env->NewStringUTF(json.c_str());
}

} // extern "C"
