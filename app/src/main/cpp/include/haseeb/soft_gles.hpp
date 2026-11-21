#pragma once

#include "haseeb/virtio_gpu.hpp"

#include <array>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace haseeb::vm {

// Pure CPU Software GLES 3.x Rasterizer (ZERO host EGL / host GPU dependency).
// Renders triangles, vertex/fragment shading, Z-buffering, alpha blending,
// and RGBA8888 textures directly into guest-visible RGBA8888 buffers and
// scans out through VirtioGpuDevice -> ANativeWindow.
class SoftGlesContext {
public:
    static constexpr uint32_t kGlVendor                = 0x1F00u;
    static constexpr uint32_t kGlRenderer              = 0x1F01u;
    static constexpr uint32_t kGlVersion               = 0x1F02u;
    static constexpr uint32_t kGlShadingLanguageVer    = 0x8B8Cu;

    static constexpr uint32_t kClearColorBit           = 0x00004000u;
    static constexpr uint32_t kClearDepthBit           = 0x00000100u;

    static constexpr uint32_t kCapDepthTest            = 0x0B71u;
    static constexpr uint32_t kCapBlend                = 0x0BE2u;
    static constexpr uint32_t kCapCullFace             = 0x0B44u;

    static constexpr uint32_t kDepthLess               = 0x0201u;
    static constexpr uint32_t kDepthLequal             = 0x0203u;
    static constexpr uint32_t kDepthAlways             = 0x0207u;

    // Serialized EL0 /dev/haseeb_gles command stream opcodes
    enum CmdOp : uint32_t {
        kCmdResize        = 1u,
        kCmdClearColor    = 2u,
        kCmdClear         = 3u,
        kCmdEnable        = 4u,
        kCmdDisable       = 5u,
        kCmdSetMvp        = 6u,
        kCmdUploadTexRgba = 7u,
        kCmdBindTex       = 8u,
        kCmdDrawTriangles = 9u,
        kCmdSwapBuffers   = 10u,
    };

    struct Vertex {
        float x = 0.0f, y = 0.0f, z = 0.0f, w = 1.0f;
        float r = 1.0f, g = 1.0f, b = 1.0f, a = 1.0f;
        float u = 0.0f, v = 0.0f;
        float nx = 0.0f, ny = 0.0f, nz = 1.0f;
    };

    SoftGlesContext();

    void Reset(uint32_t width = 720u, uint32_t height = 1560u);
    void Resize(uint32_t width, uint32_t height);
    void Viewport(int32_t x, int32_t y, uint32_t width, uint32_t height);

    const char* GlGetString(uint32_t name) const;

    void ClearColor(float r, float g, float b, float a);
    void Clear(uint32_t mask);
    void SetCapability(uint32_t cap, bool enabled);
    void SetDepthFunc(uint32_t func);

    // Column-major or row-major? Uses standard OpenGL column-major 4x4 matrix
    void SetMvpMatrix(const std::array<float, 16>& col_major_mvp);
    void SetLightDirection(float lx, float ly, float lz);

    uint32_t UploadTextureRgba(uint32_t tex_id,
                               uint32_t width,
                               uint32_t height,
                               const uint32_t* rgba_pixels,
                               bool bilinear = true);
    void BindTexture(uint32_t tex_id);

    void DrawTriangles(const std::vector<Vertex>& vertices,
                       const std::vector<uint32_t>& indices = {});

    bool SwapBuffers(VirtioGpuDevice* gpu = nullptr);

    // Executes serialized binary packet stream submitted by guest EL0 /dev/haseeb_gles
    bool ExecuteCommandStream(const uint8_t* data, size_t size, VirtioGpuDevice* gpu);

    uint32_t Width() const;
    uint32_t Height() const;
    uint64_t DrawCalls() const;
    uint64_t TrianglesRasterized() const;
    uint64_t FramesSwapped() const;
    std::vector<uint32_t> CopyColorBuffer() const;

private:
    struct Texture2D {
        uint32_t width = 0;
        uint32_t height = 0;
        bool bilinear = true;
        std::vector<uint32_t> pixels;
    };

    struct ClipVertex {
        float x, y, z, w;
        float r, g, b, a;
        float u, v;
        float light;
    };

    ClipVertex TransformVertex(const Vertex& in) const;
    void RasterizeTriangle(const ClipVertex& v0, const ClipVertex& v1, const ClipVertex& v2);
    void SampleTexture(float u, float v, float& out_r, float& out_g, float& out_b, float& out_a) const;

    mutable std::mutex mutex_;
    uint32_t width_ = 720u;
    uint32_t height_ = 1560u;
    int32_t vp_x_ = 0;
    int32_t vp_y_ = 0;
    uint32_t vp_w_ = 720u;
    uint32_t vp_h_ = 1560u;

    std::vector<uint32_t> color_;
    std::vector<float> depth_;

    float clear_r_ = 0.0f, clear_g_ = 0.0f, clear_b_ = 0.0f, clear_a_ = 1.0f;
    bool depth_test_ = true;
    bool blend_enabled_ = false;
    bool cull_face_ = false;
    uint32_t depth_func_ = kDepthLess;

    std::array<float, 16> mvp_{
        1, 0, 0, 0,
        0, 1, 0, 0,
        0, 0, 1, 0,
        0, 0, 0, 1,
    };
    float light_dir_[3]{0.35f, 0.55f, 0.75f};

    uint32_t next_tex_id_ = 1u;
    uint32_t bound_tex_id_ = 0u;
    std::unordered_map<uint32_t, Texture2D> textures_;

    uint64_t draw_calls_ = 0;
    uint64_t triangles_rasterized_ = 0;
    uint64_t frames_swapped_ = 0;
};

} // namespace haseeb::vm
