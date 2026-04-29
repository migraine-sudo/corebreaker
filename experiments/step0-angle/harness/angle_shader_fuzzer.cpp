// ANGLE shader translator fuzzer
// Targets all 6 output backends including MSL and WGSL (not covered by OSS-Fuzz)

#include "GLSLANG/ShaderLang.h"

#include <cstdint>
#include <cstring>

namespace {

constexpr ShShaderOutput kOutputs[] = {
    SH_ESSL_OUTPUT,
    SH_GLSL_450_CORE_OUTPUT,
    SH_HLSL_4_1_OUTPUT,
    SH_SPIRV_VULKAN_OUTPUT,
    SH_MSL_METAL_OUTPUT,
    SH_WGSL_OUTPUT,
};
constexpr size_t kNumOutputs = sizeof(kOutputs) / sizeof(kOutputs[0]);

ShBuiltInResources sResources;

void TryCompile(ShShaderOutput output, sh::GLenum shaderType,
                ShShaderSpec spec, const char *source) {
    ShCompileOptions options = {};
    options.objectCode = true;
    options.limitExpressionComplexity = true;
    options.limitCallStackDepth = true;

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
    sResources.MaxComputeWorkGroupCount[0]  = 65535;
    sResources.MaxComputeWorkGroupCount[1]  = 65535;
    sResources.MaxComputeWorkGroupCount[2]  = 65535;
    sResources.MaxComputeWorkGroupSize[0]   = 1024;
    sResources.MaxComputeWorkGroupSize[1]   = 1024;
    sResources.MaxComputeWorkGroupSize[2]   = 64;
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2 || size > 4096)
        return 0;

    uint8_t ctrl = data[0];
    const char *shader_data = reinterpret_cast<const char *>(data + 1);
    size_t shader_len = size - 1;

    sh::GLenum shaderType;
    switch (ctrl & 0x03) {
        case 0: shaderType = 0x8B31; break;  // GL_VERTEX_SHADER
        case 1: shaderType = 0x8B30; break;  // GL_FRAGMENT_SHADER
        case 2: shaderType = 0x91B9; break;  // GL_COMPUTE_SHADER
        default: shaderType = 0x8DD9; break; // GL_GEOMETRY_SHADER
    }

    ShShaderSpec spec;
    switch ((ctrl >> 2) & 0x03) {
        case 0: spec = SH_GLES3_1_SPEC; break;
        case 1: spec = SH_GLES3_SPEC; break;
        case 2: spec = SH_GLES3_2_SPEC; break;
        default: spec = SH_GLES2_SPEC; break;
    }

    // Select output backend: use bits 4-6 to pick one
    size_t outputIdx = ((ctrl >> 4) & 0x07) % kNumOutputs;

    // Null-terminate the shader source
    char *source = new char[shader_len + 1];
    memcpy(source, shader_data, shader_len);
    source[shader_len] = '\0';

    TryCompile(kOutputs[outputIdx], shaderType, spec, source);

    delete[] source;
    return 0;
}
