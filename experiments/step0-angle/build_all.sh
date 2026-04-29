#!/bin/bash
set -e

cd /Users/migriane/Downloads/fuzzmind/corebreaker/experiments/step0-angle/angle

BUILD_DIR="/Users/migriane/Downloads/fuzzmind/corebreaker/experiments/step0-angle/build"
OBJ_DIR="$BUILD_DIR/obj"
mkdir -p "$OBJ_DIR"

CXX="/usr/local/opt/llvm/bin/clang++"
CC="/usr/local/opt/llvm/bin/clang"

UBSAN_IGNORELIST="$PWD/tools/ubsan/ignorelist.txt"
RELEASE_MODE="${RELEASE_MODE:-0}"
if [ "$RELEASE_MODE" = "1" ]; then
    CFLAGS_BASE="-fsanitize=address,fuzzer-no-link -fno-omit-frame-pointer -fsanitize-ignorelist=$UBSAN_IGNORELIST -O2 -g -DNDEBUG"
else
    CFLAGS_BASE="-fsanitize=address,undefined,fuzzer-no-link -fno-sanitize-recover=all -fsanitize-ignorelist=$UBSAN_IGNORELIST -O1 -g -fno-omit-frame-pointer"
fi
INCLUDES="-I. -Isrc -Iinclude -Iout/gen/angle -Ithird_party/spirv-headers/src/include -Ithird_party/spirv-tools/src/include -Ithird_party/abseil-cpp -Isrc/common/base -Isrc/common/third_party/xxhash"
DEFINES="-DANGLE_ENABLE_ESSL -DANGLE_ENABLE_GLSL -DANGLE_ENABLE_HLSL -DANGLE_ENABLE_VULKAN -DANGLE_ENABLE_METAL -DANGLE_ENABLE_WGPU -DANGLE_ENABLE_NULL -DANGLE_IS_64_BIT_CPU"

OK=0
FAIL=0
SKIP=0

compile_one() {
    local src="$1"
    local obj="$OBJ_DIR/$(echo "$src" | tr '/' '_').o"

    if [ -f "$obj" ]; then
        SKIP=$((SKIP+1))
        return 0
    fi

    if [[ "$src" == *.c ]]; then
        $CC $CFLAGS_BASE -std=c11 $DEFINES $INCLUDES -c "$src" -o "$obj" 2>/dev/null
    else
        $CXX $CFLAGS_BASE -std=c++20 $DEFINES $INCLUDES -c "$src" -o "$obj" 2>/dev/null
    fi
    return $?
}

# Translator sources
for src in $(find src/compiler/translator -name '*.cpp' ! -path '*/test/*' ! -path '*/fuzz/*'); do
    if compile_one "$src"; then
        OK=$((OK+1))
    else
        FAIL=$((FAIL+1))
        echo "FAIL: $src"
    fi
done

# Preprocessor sources
for src in $(find src/compiler/preprocessor -name '*.cpp' ! -path '*/test/*'); do
    if compile_one "$src"; then
        OK=$((OK+1))
    else
        FAIL=$((FAIL+1))
        echo "FAIL: $src"
    fi
done

# Common sources (filter platform-specific)
for src in $(find src/common -name '*.cpp' -o -name '*.c' | grep -v test | grep -v '_win\.' | grep -v '_linux\.' | grep -v '_fuchsia' | grep -v '_ios\.' | grep -v 'vulkan/' | grep -v 'dma_buf' | grep -v '_winuwp' | grep -v 'fuchsia_egl'); do
    if compile_one "$src"; then
        OK=$((OK+1))
    else
        FAIL=$((FAIL+1))
        echo "FAIL: $src"
    fi
done

echo ""
echo "=== Build Summary ==="
echo "OK: $OK  Skipped: $SKIP  Failed: $FAIL"
echo "Total objects: $(ls $OBJ_DIR/*.o 2>/dev/null | wc -l)"

if [ $FAIL -eq 0 ] || [ $OK -gt 100 ]; then
    echo ""
    echo "=== Creating static library ==="
    ar rcs "$BUILD_DIR/libangle_translator.a" $OBJ_DIR/*.o
    echo "Library: $(ls -lh $BUILD_DIR/libangle_translator.a)"
fi
