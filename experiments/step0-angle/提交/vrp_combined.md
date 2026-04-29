

https://issues.chromium.org/issues/506603606

# The problem

Two null pointer dereference vulnerabilities exist in the ANGLE shader translator (commit `bb9e1870521d`, 2026-04-24). Both are caused by `ASSERT()` checks that become no-ops in release builds (`-DNDEBUG`), allowing null pointers to be dereferenced.

Found via libFuzzer + AddressSanitizer on the release build of the ANGLE translator library.

---

### Bug 1: `TSymbolTable::setGlInArraySize` — SymbolTable.cpp:192

When compiling a geometry shader (`GL_GEOMETRY_SHADER_EXT`, `SH_GLES3_1_SPEC`), the function `setGlInArraySize()` calls `find(ImmutableString("gl_in"), shaderVersion)` to locate the `gl_in` built-in. If the geometry shader extension is not enabled in `ShBuiltInResources`, `gl_in` is never registered, and `find()` returns `nullptr`. The `ASSERT` at line 190 is a no-op in release builds, and line 192 dereferences the null pointer:

```cpp
// SymbolTable.cpp:189-192
const TSymbol *glPerVertexVar = find(ImmutableString("gl_in"), shaderVersion);
ASSERT(glPerVertexVar);  // no-op in release

TType *glInType = new TType(static_cast<const TVariable *>(glPerVertexVar)->getType());
//                          nullptr → SEGV at 0x18
```

**Call chain**: `yyparse()` → `parseSingleArrayDeclaration()` (ParseContext.cpp:4924) → `checkGeometryShaderInputAndSetArraySize()` (ParseContext.cpp:4646) → `setGlInArraySize()` (SymbolTable.cpp:192) → **SEGV**

**Fix**: Replace `ASSERT(glPerVertexVar)` with `if (!glPerVertexVar) return false;`. The caller already handles the `false` return by emitting a compile error.

---

### Bug 2: `OutputHLSL::visitAggregate` — OutputHLSL.cpp:2322

When translating a shader containing `memoryBarrier()` to HLSL output (`SH_HLSL_4_1_OUTPUT`), the `switch` in `visitAggregate()` does not handle `EOpMemoryBarrier`. It falls to the `default` case, which assumes all unhandled ops are texture functions with ≥1 argument:

```cpp
// OutputHLSL.cpp:2278-2322
case EOpCallFunctionInAST:
case EOpCallInternalRawFunction:
default:
{
    ...
    else {
        TBasicType samplerType = (*arguments)[0]->getAsTyped()->getType().getBasicType();
        //                       ^^^^^^^^^^^^^^^ empty sequence → null deref at 0x0
    }
}
```

`memoryBarrier()` has zero arguments, so `(*arguments)[0]` is out-of-bounds, resulting in SEGV. The same bug affects `memoryBarrierAtomicCounter()`, `memoryBarrierBuffer()`, `memoryBarrierShared()`.

**Fix**: Add explicit `case` labels for barrier ops (e.g., `case EOpMemoryBarrier: out << "AllMemoryBarrier()"; return false;`), or guard: `if (arguments->empty()) { UNREACHABLE(); return false; }`.

---

# Impact analysis

**Bug 1** can be triggered by any application using ANGLE as its GLES implementation that compiles geometry shaders. The most relevant scenario is **Android devices using ANGLE as the system GLES driver** (e.g., Google Pixel with Vulkan backend), where native GLES 3.1+ apps could be crashed by a malicious shader. It is **not reachable from Chrome WebGL** (WebGL 2.0 is capped at ES 3.0; geometry shaders require ES 3.1) or WebGPU.

**Bug 2** is currently **not reachable** through any normal API path: the HLSL backend is only used by D3D9/D3D11 (Windows), which caps at ES 3.0, while `memoryBarrier()` requires ES 3.1. However, this is a latent vulnerability — ANGLE's D3D11 code has comments indicating ES 3.1 support is a future possibility.

Both bugs result in denial of service (SEGV crash). Not exploitable for code execution.

# What version of Chrome have you found the security issue in?

The bugs are in the ANGLE shader translator library, a component of Chrome. Tested against ANGLE HEAD `bb9e1870521db37d5030103d74a9d3c9163ef7cc` (2026-04-24).

# Reproduction

Two self-contained PoC files are attached: `poc_bug1_symboltable.cpp` and `poc_bug2_hlsl.cpp`.

**Build and run:**

```bash
git clone https://chromium.googlesource.com/angle/angle
cd angle
git checkout bb9e1870521d
python3 scripts/bootstrap.py && gclient sync

# Build ANGLE translator with ASan, release mode (ASSERT disabled)
gn gen out/Asan --args='is_debug=false is_asan=true'
autoninja -C out/Asan translator

# Bug 1
clang++ -fsanitize=address -DNDEBUG -O2 -g -std=c++20 \
  -I include -I src -I out/gen/angle \
  -DANGLE_ENABLE_ESSL -DANGLE_ENABLE_GLSL -DANGLE_ENABLE_HLSL \
  -DANGLE_ENABLE_VULKAN -DANGLE_ENABLE_METAL -DANGLE_ENABLE_WGPU \
  poc_bug1_symboltable.cpp \
  out/Asan/obj/libtranslator.a out/Asan/obj/libangle_common.a \
  -lc++ -o poc_bug1
./poc_bug1
# → SEGV at SymbolTable.cpp:192

# Bug 2
clang++ -fsanitize=address -DNDEBUG -O2 -g -std=c++20 \
  -I include -I src -I out/gen/angle \
  -DANGLE_ENABLE_ESSL -DANGLE_ENABLE_GLSL -DANGLE_ENABLE_HLSL \
  -DANGLE_ENABLE_VULKAN -DANGLE_ENABLE_METAL -DANGLE_ENABLE_WGPU \
  poc_bug2_hlsl.cpp \
  out/Asan/obj/libtranslator.a out/Asan/obj/libangle_common.a \
  -lc++ -o poc_bug2
./poc_bug2
# → SEGV at OutputHLSL.cpp:2322
```

**Key**: Must compile with `-DNDEBUG`. In debug mode, `ASSERT()` fires as `__builtin_trap()` (SIGILL) before the null dereference, masking the real bug.

# Is the security issue related to a crash?

Yes, it is related to a crash.

# Vulnerability type

NULL Pointer Dereference (CWE-476)
