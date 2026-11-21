#include "haseeb/soft_gles.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>

namespace haseeb::vm {

namespace {

uint32_t PackRgba(float r, float g, float b, float a) {
    const uint32_t cr = static_cast<uint32_t>(std::clamp(r, 0.0f, 1.0f) * 255.0f + 0.5f);
    const uint32_t cg = static_cast<uint32_t>(std::clamp(g, 0.0f, 1.0f) * 255.0f + 0.5f);
    const uint32_t cb = static_cast<uint32_t>(std::clamp(b, 0.0f, 1.0f) * 255.0f + 0.5f);
    const uint32_t ca = static_cast<uint32_t>(std::clamp(a, 0.0f, 1.0f) * 255.0f + 0.5f);
    return cr | (cg << 8) | (cb << 16) | (ca << 24);
}

void UnpackRgba(uint32_t px, float& r, float& g, float& b, float& a) {
    r = static_cast<float>(px & 0xFFu) / 255.0f;
    g = static_cast<float>((px >> 8) & 0xFFu) / 255.0f;
    b = static_cast<float>((px >> 16) & 0xFFu) / 255.0f;
    a = static_cast<float>((px >> 24) & 0xFFu) / 255.0f;
}

float EdgeFn(float ax, float ay, float bx, float by, float cx, float cy) {
    return (cx - ax) * (by - ay) - (cy - ay) * (bx - ax);
}

uint32_t ReadU32Le(const uint8_t* p) {
    uint32_t v = 0u;
    std::memcpy(&v, p, 4u);
    return v;
}

} // namespace

SoftGlesContext::SoftGlesContext() {
    Reset(320u, 240u);
}

void SoftGlesContext::Reset(uint32_t width, uint32_t height) {
    std::lock_guard<std::mutex> lock(mutex_);
    width_ = std::clamp(width, 8u, 1920u);
    height_ = std::clamp(height, 8u, 2400u);
    vp_x_ = 0;
    vp_y_ = 0;
    vp_w_ = width_;
    vp_h_ = height_;
    color_.assign(static_cast<size_t>(width_) * height_, 0xFF000000u);
    depth_.assign(static_cast<size_t>(width_) * height_, 1.0f);
    clear_r_ = 0.0f;
    clear_g_ = 0.0f;
    clear_b_ = 0.0f;
    clear_a_ = 1.0f;
    depth_test_ = true;
    blend_enabled_ = false;
    cull_face_ = false;
    depth_func_ = kDepthLess;
    mvp_ = {
        1, 0, 0, 0,
        0, 1, 0, 0,
        0, 0, 1, 0,
        0, 0, 0, 1,
    };
    textures_.clear();
    bound_tex_id_ = 0u;
    next_tex_id_ = 1u;
    draw_calls_ = 0;
    triangles_rasterized_ = 0;
    frames_swapped_ = 0;
}

void SoftGlesContext::Resize(uint32_t width, uint32_t height) {
    std::lock_guard<std::mutex> lock(mutex_);
    width_ = std::clamp(width, 8u, 1920u);
    height_ = std::clamp(height, 8u, 2400u);
    vp_x_ = 0;
    vp_y_ = 0;
    vp_w_ = width_;
    vp_h_ = height_;
    color_.assign(static_cast<size_t>(width_) * height_, PackRgba(clear_r_, clear_g_, clear_b_, clear_a_));
    depth_.assign(static_cast<size_t>(width_) * height_, 1.0f);
}

void SoftGlesContext::Viewport(int32_t x, int32_t y, uint32_t width, uint32_t height) {
    std::lock_guard<std::mutex> lock(mutex_);
    vp_x_ = x;
    vp_y_ = y;
    vp_w_ = std::max(1u, width);
    vp_h_ = std::max(1u, height);
}

const char* SoftGlesContext::GlGetString(uint32_t name) const {
    switch (name) {
        case kGlVendor:             return "Haseeb Gaming Engine";
        case kGlRenderer:           return "Haseeb SoftGLES 3.0 CPU (ARM64 No-EGL)";
        case kGlVersion:            return "OpenGL ES 3.0 Haseeb-SoftRaster 1.0";
        case kGlShadingLanguageVer: return "OpenGL ES GLSL ES 3.00";
        default:                    return "";
    }
}

void SoftGlesContext::ClearColor(float r, float g, float b, float a) {
    std::lock_guard<std::mutex> lock(mutex_);
    clear_r_ = r;
    clear_g_ = g;
    clear_b_ = b;
    clear_a_ = a;
}

void SoftGlesContext::Clear(uint32_t mask) {
    std::lock_guard<std::mutex> lock(mutex_);
    if ((mask & kClearColorBit) != 0u) {
        const uint32_t cc = PackRgba(clear_r_, clear_g_, clear_b_, clear_a_);
        std::fill(color_.begin(), color_.end(), cc);
    }
    if ((mask & kClearDepthBit) != 0u) {
        std::fill(depth_.begin(), depth_.end(), 1.0f);
    }
}

void SoftGlesContext::SetCapability(uint32_t cap, bool enabled) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (cap == kCapDepthTest) depth_test_ = enabled;
    else if (cap == kCapBlend) blend_enabled_ = enabled;
    else if (cap == kCapCullFace) cull_face_ = enabled;
}

void SoftGlesContext::SetDepthFunc(uint32_t func) {
    std::lock_guard<std::mutex> lock(mutex_);
    depth_func_ = func;
}

void SoftGlesContext::SetMvpMatrix(const std::array<float, 16>& col_major_mvp) {
    std::lock_guard<std::mutex> lock(mutex_);
    mvp_ = col_major_mvp;
}

void SoftGlesContext::SetLightDirection(float lx, float ly, float lz) {
    std::lock_guard<std::mutex> lock(mutex_);
    const float len = std::sqrt(lx * lx + ly * ly + lz * lz);
    if (len > 1e-6f) {
        light_dir_[0] = lx / len;
        light_dir_[1] = ly / len;
        light_dir_[2] = lz / len;
    }
}

uint32_t SoftGlesContext::UploadTextureRgba(uint32_t tex_id,
                                            uint32_t width,
                                            uint32_t height,
                                            const uint32_t* rgba_pixels,
                                            bool bilinear) {
    if (width == 0u || height == 0u || !rgba_pixels) return 0u;
    std::lock_guard<std::mutex> lock(mutex_);
    uint32_t id = tex_id;
    if (id == 0u) id = next_tex_id_++;
    else if (id >= next_tex_id_) next_tex_id_ = id + 1u;

    Texture2D tex;
    tex.width = width;
    tex.height = height;
    tex.bilinear = bilinear;
    tex.pixels.assign(rgba_pixels, rgba_pixels + static_cast<size_t>(width) * height);
    textures_[id] = std::move(tex);
    return id;
}

void SoftGlesContext::BindTexture(uint32_t tex_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    bound_tex_id_ = tex_id;
}

SoftGlesContext::ClipVertex SoftGlesContext::TransformVertex(const Vertex& in) const {
    ClipVertex out{};
    out.x = mvp_[0] * in.x + mvp_[4] * in.y + mvp_[8] * in.z + mvp_[12] * in.w;
    out.y = mvp_[1] * in.x + mvp_[5] * in.y + mvp_[9] * in.z + mvp_[13] * in.w;
    out.z = mvp_[2] * in.x + mvp_[6] * in.y + mvp_[10] * in.z + mvp_[14] * in.w;
    out.w = mvp_[3] * in.x + mvp_[7] * in.y + mvp_[11] * in.z + mvp_[15] * in.w;
    out.r = in.r;
    out.g = in.g;
    out.b = in.b;
    out.a = in.a;
    out.u = in.u;
    out.v = in.v;
    const float nlen = std::sqrt(in.nx * in.nx + in.ny * in.ny + in.nz * in.nz);
    if (nlen > 1e-5f) {
        const float dot = (in.nx * light_dir_[0] + in.ny * light_dir_[1] + in.nz * light_dir_[2]) / nlen;
        out.light = std::clamp(0.30f + 0.70f * std::max(0.0f, dot), 0.30f, 1.0f);
    } else {
        out.light = 1.0f;
    }
    return out;
}

void SoftGlesContext::SampleTexture(float u,
                                    float v,
                                    float& out_r,
                                    float& out_g,
                                    float& out_b,
                                    float& out_a) const {
    auto it = textures_.find(bound_tex_id_);
    if (it == textures_.end() || it->second.pixels.empty()) {
        out_r = out_g = out_b = out_a = 1.0f;
        return;
    }
    const Texture2D& tex = it->second;
    const float wu = u - std::floor(u);
    const float wv = v - std::floor(v);
    const float fx = wu * static_cast<float>(tex.width - 1u);
    const float fy = wv * static_cast<float>(tex.height - 1u);

    if (!tex.bilinear || tex.width == 1u || tex.height == 1u) {
        const uint32_t ix = static_cast<uint32_t>(std::lround(fx)) % tex.width;
        const uint32_t iy = static_cast<uint32_t>(std::lround(fy)) % tex.height;
        UnpackRgba(tex.pixels[static_cast<size_t>(iy) * tex.width + ix], out_r, out_g, out_b, out_a);
        return;
    }

    const uint32_t x0 = static_cast<uint32_t>(fx);
    const uint32_t y0 = static_cast<uint32_t>(fy);
    const uint32_t x1 = std::min(x0 + 1u, tex.width - 1u);
    const uint32_t y1 = std::min(y0 + 1u, tex.height - 1u);
    const float tx = fx - static_cast<float>(x0);
    const float ty = fy - static_cast<float>(y0);

    float r00, g00, b00, a00, r10, g10, b10, a10;
    float r01, g01, b01, a01, r11, g11, b11, a11;
    UnpackRgba(tex.pixels[static_cast<size_t>(y0) * tex.width + x0], r00, g00, b00, a00);
    UnpackRgba(tex.pixels[static_cast<size_t>(y0) * tex.width + x1], r10, g10, b10, a10);
    UnpackRgba(tex.pixels[static_cast<size_t>(y1) * tex.width + x0], r01, g01, b01, a01);
    UnpackRgba(tex.pixels[static_cast<size_t>(y1) * tex.width + x1], r11, g11, b11, a11);

    auto bilerp = [&](float c00, float c10, float c01, float c11) {
        const float top = c00 + (c10 - c00) * tx;
        const float bot = c01 + (c11 - c01) * tx;
        return top + (bot - top) * ty;
    };
    out_r = bilerp(r00, r10, r01, r11);
    out_g = bilerp(g00, g10, g01, g11);
    out_b = bilerp(b00, b10, b01, b11);
    out_a = bilerp(a00, a10, a01, a11);
}

void SoftGlesContext::RasterizeTriangle(const ClipVertex& v0,
                                        const ClipVertex& v1,
                                        const ClipVertex& v2) {
    if (v0.w <= 1e-4f || v1.w <= 1e-4f || v2.w <= 1e-4f) return;

    const float inv_w0 = 1.0f / v0.w;
    const float inv_w1 = 1.0f / v1.w;
    const float inv_w2 = 1.0f / v2.w;

    auto to_screen = [&](const ClipVertex& cv, float inv_w, float& sx, float& sy, float& sz) {
        const float ndc_x = cv.x * inv_w;
        const float ndc_y = cv.y * inv_w;
        const float ndc_z = cv.z * inv_w;
        sx = static_cast<float>(vp_x_) + (ndc_x * 0.5f + 0.5f) * static_cast<float>(vp_w_);
        sy = static_cast<float>(vp_y_) + (0.5f - ndc_y * 0.5f) * static_cast<float>(vp_h_);
        sz = ndc_z * 0.5f + 0.5f;
    };

    float x0, y0, z0, x1, y1, z1, x2, y2, z2;
    to_screen(v0, inv_w0, x0, y0, z0);
    to_screen(v1, inv_w1, x1, y1, z1);
    to_screen(v2, inv_w2, x2, y2, z2);

    const float area = EdgeFn(x0, y0, x1, y1, x2, y2);
    if (std::fabs(area) < 1e-5f) return;
    if (cull_face_ && area > 0.0f) return; // Screen Y-down flips sign for CCW backfaces

    const int32_t min_x = std::max<int32_t>(0, static_cast<int32_t>(std::floor(std::min({x0, x1, x2}))));
    const int32_t max_x = std::min<int32_t>(static_cast<int32_t>(width_) - 1,
                                            static_cast<int32_t>(std::ceil(std::max({x0, x1, x2}))));
    const int32_t min_y = std::max<int32_t>(0, static_cast<int32_t>(std::floor(std::min({y0, y1, y2}))));
    const int32_t max_y = std::min<int32_t>(static_cast<int32_t>(height_) - 1,
                                            static_cast<int32_t>(std::ceil(std::max({y0, y1, y2}))));
    if (min_x > max_x || min_y > max_y) return;

    const float inv_area = 1.0f / area;
    const bool has_tex = (bound_tex_id_ != 0u && textures_.count(bound_tex_id_) > 0u);
    bool drew_any = false;

    for (int32_t py = min_y; py <= max_y; ++py) {
        const float fy = static_cast<float>(py) + 0.5f;
        for (int32_t px = min_x; px <= max_x; ++px) {
            const float fx = static_cast<float>(px) + 0.5f;
            float w0 = EdgeFn(x1, y1, x2, y2, fx, fy) * inv_area;
            float w1 = EdgeFn(x2, y2, x0, y0, fx, fy) * inv_area;
            float w2 = EdgeFn(x0, y0, x1, y1, fx, fy) * inv_area;
            if (w0 < -1e-4f || w1 < -1e-4f || w2 < -1e-4f) continue;

            const float z = w0 * z0 + w1 * z1 + w2 * z2;
            if (z < 0.0f || z > 1.0f) continue;

            const size_t idx = static_cast<size_t>(py) * width_ + static_cast<size_t>(px);
            if (depth_test_) {
                bool pass = false;
                if (depth_func_ == kDepthLess) pass = (z < depth_[idx]);
                else if (depth_func_ == kDepthLequal) pass = (z <= depth_[idx]);
                else pass = true;
                if (!pass) continue;
                depth_[idx] = z;
            }

            // Perspective-correct interpolation
            const float pw0 = w0 * inv_w0;
            const float pw1 = w1 * inv_w1;
            const float pw2 = w2 * inv_w2;
            const float denom = pw0 + pw1 + pw2;
            if (denom <= 1e-7f) continue;
            const float inv_d = 1.0f / denom;

            const float light = (pw0 * v0.light + pw1 * v1.light + pw2 * v2.light) * inv_d;
            float cr = (pw0 * v0.r + pw1 * v1.r + pw2 * v2.r) * inv_d * light;
            float cg = (pw0 * v0.g + pw1 * v1.g + pw2 * v2.g) * inv_d * light;
            float cb = (pw0 * v0.b + pw1 * v1.b + pw2 * v2.b) * inv_d * light;
            float ca = (pw0 * v0.a + pw1 * v1.a + pw2 * v2.a) * inv_d;

            if (has_tex) {
                const float u = (pw0 * v0.u + pw1 * v1.u + pw2 * v2.u) * inv_d;
                const float v = (pw0 * v0.v + pw1 * v1.v + pw2 * v2.v) * inv_d;
                float tr, tg, tb, ta;
                SampleTexture(u, v, tr, tg, tb, ta);
                cr *= tr;
                cg *= tg;
                cb *= tb;
                ca *= ta;
            }

            if (blend_enabled_ && ca < 0.999f) {
                float dr, dg, db, da;
                UnpackRgba(color_[idx], dr, dg, db, da);
                const float inv_a = 1.0f - ca;
                cr = cr * ca + dr * inv_a;
                cg = cg * ca + dg * inv_a;
                cb = cb * ca + db * inv_a;
                ca = std::min(1.0f, ca + da * inv_a);
            }

            color_[idx] = PackRgba(cr, cg, cb, ca);
            drew_any = true;
        }
    }
    if (drew_any) {
        ++triangles_rasterized_;
    }
}

void SoftGlesContext::DrawTriangles(const std::vector<Vertex>& vertices,
                                    const std::vector<uint32_t>& indices) {
    std::lock_guard<std::mutex> lock(mutex_);
    ++draw_calls_;
    if (indices.empty()) {
        for (size_t i = 0; i + 2u < vertices.size(); i += 3u) {
            RasterizeTriangle(TransformVertex(vertices[i]),
                              TransformVertex(vertices[i + 1u]),
                              TransformVertex(vertices[i + 2u]));
        }
    } else {
        for (size_t i = 0; i + 2u < indices.size(); i += 3u) {
            if (indices[i] >= vertices.size() ||
                indices[i + 1u] >= vertices.size() ||
                indices[i + 2u] >= vertices.size()) {
                continue;
            }
            RasterizeTriangle(TransformVertex(vertices[indices[i]]),
                              TransformVertex(vertices[indices[i + 1u]]),
                              TransformVertex(vertices[indices[i + 2u]]));
        }
    }
}

bool SoftGlesContext::SwapBuffers(VirtioGpuDevice* gpu) {
    std::vector<uint32_t> snapshot;
    uint32_t w = 0, h = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ++frames_swapped_;
        snapshot = color_;
        w = width_;
        h = height_;
    }
    if (!gpu) return true;
    return gpu->SubmitRawRgbaFrame(reinterpret_cast<const uint8_t*>(snapshot.data()), w, h, w * 4u);
}

bool SoftGlesContext::ExecuteCommandStream(const uint8_t* data, size_t size, VirtioGpuDevice* gpu) {
    if (!data || size < 8u) return false;
    size_t off = 0u;
    while (off + 8u <= size) {
        const uint32_t op = ReadU32Le(data + off);
        const uint32_t payload_bytes = ReadU32Le(data + off + 4u);
        off += 8u;
        if (payload_bytes > size - off) return false;
        const uint8_t* p = data + off;
        off += payload_bytes;

        switch (op) {
            case kCmdResize: {
                if (payload_bytes < 8u) return false;
                Resize(ReadU32Le(p), ReadU32Le(p + 4u));
                break;
            }
            case kCmdClearColor: {
                if (payload_bytes < 16u) return false;
                float rgba[4]{};
                std::memcpy(rgba, p, 16u);
                ClearColor(rgba[0], rgba[1], rgba[2], rgba[3]);
                break;
            }
            case kCmdClear: {
                if (payload_bytes < 4u) return false;
                Clear(ReadU32Le(p));
                break;
            }
            case kCmdEnable:
            case kCmdDisable: {
                if (payload_bytes < 4u) return false;
                SetCapability(ReadU32Le(p), op == kCmdEnable);
                break;
            }
            case kCmdSetMvp: {
                if (payload_bytes < 64u) return false;
                std::array<float, 16> m{};
                std::memcpy(m.data(), p, 64u);
                SetMvpMatrix(m);
                break;
            }
            case kCmdUploadTexRgba: {
                if (payload_bytes < 12u) return false;
                const uint32_t tid = ReadU32Le(p);
                const uint32_t tw = ReadU32Le(p + 4u);
                const uint32_t th = ReadU32Le(p + 8u);
                const size_t need = static_cast<size_t>(tw) * th * 4u;
                if (tw == 0u || th == 0u || payload_bytes < 12u + need) return false;
                std::vector<uint32_t> px(static_cast<size_t>(tw) * th);
                std::memcpy(px.data(), p + 12u, need);
                UploadTextureRgba(tid, tw, th, px.data(), true);
                break;
            }
            case kCmdBindTex: {
                if (payload_bytes < 4u) return false;
                BindTexture(ReadU32Le(p));
                break;
            }
            case kCmdDrawTriangles: {
                const size_t count = payload_bytes / sizeof(Vertex);
                if (count == 0u) break;
                std::vector<Vertex> verts(count);
                std::memcpy(verts.data(), p, count * sizeof(Vertex));
                DrawTriangles(verts);
                break;
            }
            case kCmdSwapBuffers: {
                SwapBuffers(gpu);
                break;
            }
            default:
                return false;
        }
    }
    return true;
}

uint32_t SoftGlesContext::Width() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return width_;
}

uint32_t SoftGlesContext::Height() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return height_;
}

uint64_t SoftGlesContext::DrawCalls() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return draw_calls_;
}

uint64_t SoftGlesContext::TrianglesRasterized() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return triangles_rasterized_;
}

uint64_t SoftGlesContext::FramesSwapped() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return frames_swapped_;
}

std::vector<uint32_t> SoftGlesContext::CopyColorBuffer() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return color_;
}

} // namespace haseeb::vm
