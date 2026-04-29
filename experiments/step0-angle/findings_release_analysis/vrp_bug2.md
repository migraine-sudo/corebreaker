# VRP Report — Bug 2: OutputHLSL::visitAggregate null pointer dereference

## The problem

A null pointer dereference exists in ANGLE's HLSL output backend at `src/compiler/translator/hlsl/OutputHLSL.cpp:2322`, in the function `OutputHLSL::visitAggregate()`.

When translating an ES 3.1 shader containing `memoryBarrier()` to HLSL output (`SH_HLSL_4_1_OUTPUT`), the `switch` statement in `visitAggregate()` does not handle `EOpMemoryBarrier`. It falls through to the `default` case, which shares its handler with `EOpCallFunctionInAST` and `EOpCallInternalRawFunction`:

```cpp
// OutputHLSL.cpp:2278-2322
case EOpCallFunctionInAST:
case EOpCallInternalRawFunction:
default:
{
    ...
    if (node->getOp() == EOpCallFunctionInAST) { ... }
    else if (node->getFunction()->isImageFunction()) { ... }
    else {
        // line 2322: assumes this is a texture function with ≥1 argument
        TBasicType samplerType = (*arguments)[0]->getAsTyped()->getType().getBasicType();
        //                       ^^^^^^^^^^^^^^^ OOB on empty sequence → null deref
    }
}
```

`memoryBarrier()` takes zero arguments, so `(*arguments)[0]` is an out-of-bounds access on an empty `TIntermSequence`, resulting in a null pointer dereference (SEGV at address 0x0).

The same bug affects other zero-argument built-in functions whose op codes are not handled in the switch: `memoryBarrierAtomicCounter()`, `memoryBarrierBuffer()`, `memoryBarrierShared()`, and potentially `barrier()`.

Tested on ANGLE commit `bb9e1870521d` (2026-04-24).

**Suggested fix**: Add explicit `case` labels for the barrier ops:

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
```

Or at minimum, guard the default block against empty arguments:

```cpp
if (arguments->empty()) {
    UNREACHABLE();
    return false;
}
```

## Impact analysis

This bug is currently **not reachable through any normal Chrome API path**:

- The HLSL output backend is only used by the D3D9/D3D11 renderers (Windows).
- ANGLE's D3D11 renderer caps at ES 3.0 (`renderer11_utils.cpp:1239`), and `memoryBarrier()` requires ES 3.1.
- Chrome WebGL 2.0 uses `SH_WEBGL2_SPEC` (ES 3.0 max).
- Chrome WebGPU uses the WGSL backend, not HLSL.

However, this is a **latent vulnerability**: the D3D11 code contains comments indicating ES 3.1 support is a future possibility. If ANGLE ever enables ES 3.1 on D3D11, this bug would become directly reachable from WebGL on Windows, allowing any website to crash the Chrome renderer process.

The impact is denial of service (process crash via SEGV). Not exploitable for code execution.

## What version of Chrome have you found the security issue in?

The bug is in the ANGLE shader translator library, which is a component of Chrome. Tested against ANGLE HEAD commit `bb9e1870521db37d5030103d74a9d3c9163ef7cc` (2026-04-24). The bug exists in all Chrome versions shipping this ANGLE revision.

## PoC

Attached: `poc_bug2_hlsl.cpp`

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
  poc_bug2_hlsl.cpp \
  out/Asan/obj/libtranslator.a out/Asan/obj/libangle_common.a \
  -lc++ -o poc_bug2

./poc_bug2
```

**Expected output:**
```
ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
The signal is caused by a READ memory access.
    #0 sh::OutputHLSL::visitAggregate(sh::Visit, sh::TIntermAggregate*) OutputHLSL.cpp:2322
    #1 void sh::TIntermTraverser::traverse<sh::TIntermAggregate>(...) IntermTraverse.cpp:33
    #2 sh::OutputHLSL::visitBlock(sh::Visit, sh::TIntermBlock*) OutputHLSL.cpp:2045
    ...
    #9 sh::TranslatorHLSL::translate(...) TranslatorHLSL.cpp:202
    #10 sh::TCompiler::compile(...) Compiler.cpp:1303
```

## Is the security issue related to a crash?

Yes, it is related to a crash.

## Vulnerability type

Heap/stack buffer overflow or underflow (CWE-476: NULL Pointer Dereference)
