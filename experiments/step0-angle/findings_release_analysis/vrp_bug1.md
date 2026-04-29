# VRP Report — Bug 1: TSymbolTable::setGlInArraySize null pointer dereference

## The problem

A null pointer dereference exists in ANGLE's shader translator at `src/compiler/translator/SymbolTable.cpp:192`, in the function `TSymbolTable::setGlInArraySize()`.

When compiling a geometry shader (`GL_GEOMETRY_SHADER_EXT`) with `SH_GLES3_1_SPEC`, the function `setGlInArraySize()` calls `find(ImmutableString("gl_in"), shaderVersion)` to locate the `gl_in` built-in variable. If the geometry shader extension (`EXT_geometry_shader` / `OES_geometry_shader`) was not enabled in `ShBuiltInResources`, `gl_in` is never registered in the symbol table, and `find()` returns `nullptr`.

An `ASSERT(glPerVertexVar)` exists at line 190, but in release builds (`-DNDEBUG`), ANGLE's `ASSERT` macro expands to a no-op (see `src/common/log_utils.h:265`). The null pointer is then dereferenced at line 192:

```cpp
// SymbolTable.cpp:189-192
const TSymbol *glPerVertexVar = find(ImmutableString("gl_in"), shaderVersion);
ASSERT(glPerVertexVar);  // no-op in release builds

TType *glInType = new TType(static_cast<const TVariable *>(glPerVertexVar)->getType());
//                          nullptr dereference → SEGV at address 0x18
```

The call chain is:
1. `yyparse()` → parses `in vec4 v_position[3];` as geometry shader input with explicit array size
2. `TParseContext::parseSingleArrayDeclaration()` (`ParseContext.cpp:4924`)
3. `TParseContext::checkGeometryShaderInputAndSetArraySize()` (`ParseContext.cpp:4646`)
4. `TSymbolTable::setGlInArraySize()` (`SymbolTable.cpp:189-192`) → **SEGV**

Tested on ANGLE commit `bb9e1870521d` (2026-04-24).

**Suggested fix**: Replace `ASSERT(glPerVertexVar)` with a null check that returns `false`. The caller `setGeometryShaderInputArraySize()` (`ParseContext.cpp:5328`) already handles the `false` return by emitting a compile error.

```cpp
if (!glPerVertexVar)
{
    return false;
}
```

## Impact analysis

This bug can be triggered by any application that uses ANGLE as its OpenGL ES implementation and compiles geometry shaders via `sh::Compile()`. The most relevant real-world scenario is **Android devices using ANGLE as the system GLES driver** (e.g., Google Pixel), where native apps using GLES 3.1+ with `GL_EXT_geometry_shader` could be crashed by a malicious shader.

This is **not reachable from Chrome WebGL** because WebGL 2.0 is limited to ES 3.0 (`SH_WEBGL2_SPEC`), and geometry shaders require ES 3.1. It is also not reachable from WebGPU (which uses the WGSL backend, not the GLSL parser).

The impact is denial of service (process crash via SEGV). This is not exploitable for code execution as the dereference is at a fixed offset from null (address 0x18).

## What version of Chrome have you found the security issue in?

The bug is in the ANGLE shader translator library, which is a component of Chrome. Tested against ANGLE HEAD commit `bb9e1870521db37d5030103d74a9d3c9163ef7cc` (2026-04-24). The bug exists in all Chrome versions shipping this ANGLE revision.

## PoC

Attached: `poc_bug1_symboltable.cpp`

**To reproduce with ANGLE's GN build system:**

```bash
git clone https://chromium.googlesource.com/angle/angle
cd angle
git checkout bb9e1870521d
python3 scripts/bootstrap.py && gclient sync

gn gen out/Asan --args='is_debug=false is_asan=true'
autoninja -C out/Asan translator

clang++ -fsanitize=address -DNDEBUG -O2 -g -std=c++20 \
  -I include -I src -I out/gen/angle \
  -DANGLE_ENABLE_ESSL -DANGLE_ENABLE_GLSL -DANGLE_ENABLE_HLSL \
  -DANGLE_ENABLE_VULKAN -DANGLE_ENABLE_METAL -DANGLE_ENABLE_WGPU \
  poc_bug1_symboltable.cpp \
  out/Asan/obj/libtranslator.a out/Asan/obj/libangle_common.a \
  -lc++ -o poc_bug1

./poc_bug1
```

**Expected output:**
```
ERROR: AddressSanitizer: SEGV on unknown address 0x000000000018
The signal is caused by a READ memory access.
    #0 sh::TSymbolTable::setGlInArraySize(unsigned int, int) SymbolTable.cpp:192
    #1 sh::TParseContext::checkGeometryShaderInputAndSetArraySize(...) ParseContext.cpp:4646
    #2 sh::TParseContext::parseSingleArrayDeclaration(...) ParseContext.cpp:4924
    #3 yyparse(sh::TParseContext*, void*) glslang_tab_autogen.cpp:3226
```

## Is the security issue related to a crash?

Yes, it is related to a crash.

## Vulnerability type

Heap/stack buffer overflow or underflow (CWE-476: NULL Pointer Dereference)
