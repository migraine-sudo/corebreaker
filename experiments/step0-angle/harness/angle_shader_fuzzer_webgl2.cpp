// ANGLE shader translator fuzzer — WebGL 2.0 attack surface
// Targets: ES 3.0 (WebGL2) + MSL/WGSL backends (OSS-Fuzz blind spot)
// Only vertex + fragment shaders (WebGL has no compute/geometry)

#include "GLSLANG/ShaderLang.h"

#include <cstdint>
#include <cstring>
#include "glsl_generator.h"

extern "C" size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);

namespace {

// Weight MSL and WGSL heavily — they are the primary targets
// 0-2: MSL, 3-5: WGSL, 6: SPIRV, 7: HLSL
constexpr ShShaderOutput kOutputs[] = {
    SH_MSL_METAL_OUTPUT,     // 0
    SH_MSL_METAL_OUTPUT,     // 1
    SH_MSL_METAL_OUTPUT,     // 2
    SH_WGSL_OUTPUT,          // 3
    SH_WGSL_OUTPUT,          // 4
    SH_WGSL_OUTPUT,          // 5
    SH_SPIRV_VULKAN_OUTPUT,  // 6
    SH_HLSL_4_1_OUTPUT,      // 7
};
constexpr size_t kNumOutputs = sizeof(kOutputs) / sizeof(kOutputs[0]);

ShBuiltInResources sResources;

void TryCompile(ShShaderOutput output, sh::GLenum shaderType,
                ShShaderSpec spec, const char *source) {
    ShCompileOptions options = {};
    options.objectCode = true;
    options.limitExpressionComplexity = true;
    options.limitCallStackDepth = true;
    options.initGLPosition = true;
    options.initSharedVariables = true;

    ShHandle compiler = sh::ConstructCompiler(shaderType, spec, output, &sResources);
    if (!compiler)
        return;

    const char *sources[] = {source};
    sh::Compile(compiler, sources, 1, options);
    sh::Destruct(compiler);
}

}  // namespace

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    sh::Initialize();
    sh::InitBuiltInResources(&sResources);
    sResources.MaxVertexAttribs             = 16;
    sResources.MaxVertexUniformVectors      = 256;
    sResources.MaxVaryingVectors            = 32;
    sResources.MaxVertexTextureImageUnits   = 16;
    sResources.MaxCombinedTextureImageUnits = 80;
    sResources.MaxTextureImageUnits         = 16;
    sResources.MaxFragmentUniformVectors    = 256;
    sResources.MaxDrawBuffers               = 8;
    sResources.MaxDualSourceDrawBuffers     = 1;
    sResources.OES_standard_derivatives     = 1;
    sResources.EXT_shader_texture_lod       = 1;
    sResources.EXT_shader_framebuffer_fetch = 1;
    sResources.OES_EGL_image_external       = 1;
    sResources.OES_EGL_image_external_essl3 = 1;
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2 || size > 4096)
        return 0;

    uint8_t ctrl = data[0];
    const char *shader_data = reinterpret_cast<const char *>(data + 1);
    size_t shader_len = size - 1;

    // WebGL only has vertex and fragment shaders
    sh::GLenum shaderType;
    if (ctrl & 0x01) {
        shaderType = 0x8B30;  // GL_FRAGMENT_SHADER
    } else {
        shaderType = 0x8B31;  // GL_VERTEX_SHADER
    }

    // WebGL 2.0 = ES 3.0, also test ES 2.0 (WebGL 1.0)
    ShShaderSpec spec;
    if (ctrl & 0x02) {
        spec = SH_WEBGL2_SPEC;  // ES 3.0 / #version 300 es
    } else {
        spec = SH_WEBGL_SPEC;   // ES 2.0 / #version 100
    }

    // Output backend: bits 2-4 (8 slots, weighted toward MSL/WGSL)
    size_t outputIdx = ((ctrl >> 2) & 0x07) % kNumOutputs;

    char *source = new char[shader_len + 1];
    memcpy(source, shader_data, shader_len);
    source[shader_len] = '\0';

    TryCompile(kOutputs[outputIdx], shaderType, spec, source);

    delete[] source;
    return 0;
}

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size,
                                           size_t max_size, unsigned int seed) {
    if (seed % 3 == 0 && max_size > 16) {
        bool is_vertex = !(data[0] & 0x01);
        std::string shader = glslgen::GenerateShader(data, size, is_vertex);
        size_t total = 1 + shader.size();
        if (total <= max_size) {
            memcpy(data + 1, shader.data(), shader.size());
            return total;
        }
    }
    return LLVMFuzzerMutate(data, size, max_size);
}
