#!/bin/bash
# Build ANGLE translator library with CMake, bypassing GN/Xcode requirement
# Uses Homebrew LLVM with ASan + fuzzer instrumentation

set -e

ANGLE_DIR="/Users/migriane/Downloads/fuzzmind/corebreaker/experiments/step0-angle/angle"
BUILD_DIR="/Users/migriane/Downloads/fuzzmind/corebreaker/experiments/step0-angle/build"
CC="/usr/local/opt/llvm/bin/clang"
CXX="/usr/local/opt/llvm/bin/clang++"

export https_proxy=http://127.0.0.1:7890
export http_proxy=http://127.0.0.1:7890

mkdir -p "$BUILD_DIR"

echo "=== Step 1: Generate stub headers ==="
# angle_commit.h
mkdir -p "$ANGLE_DIR/out/gen/angle"
cat > "$ANGLE_DIR/out/gen/angle/angle_commit.h" << 'HEADER'
#define ANGLE_COMMIT_HASH "unknown"
#define ANGLE_COMMIT_HASH_SIZE 7
#define ANGLE_COMMIT_DATE "unknown"
#define ANGLE_COMMIT_POSITION 0
HEADER

# ANGLEShaderProgramVersion.h
cat > "$ANGLE_DIR/out/gen/angle/ANGLEShaderProgramVersion.h" << 'HEADER'
#ifndef ANGLE_SHADER_PROGRAM_VERSION_H_
#define ANGLE_SHADER_PROGRAM_VERSION_H_
namespace angle {
inline const unsigned char *GetANGLEShaderProgramVersion() {
    static const unsigned char kVersion[] = {0};
    return kVersion;
}
constexpr size_t GetANGLEShaderProgramVersionHashSize() { return 1; }
}
#endif
HEADER

echo "=== Step 2: Build SPIRV-Tools ==="
SPIRV_TOOLS_DIR="$ANGLE_DIR/third_party/spirv-tools/src"
SPIRV_HEADERS_DIR="$ANGLE_DIR/third_party/spirv-headers/src"
SPIRV_BUILD_DIR="$BUILD_DIR/spirv-tools"

if [ ! -f "$SPIRV_BUILD_DIR/source/libSPIRV-Tools.a" ]; then
    mkdir -p "$SPIRV_BUILD_DIR"
    cd "$SPIRV_BUILD_DIR"
    cmake "$SPIRV_TOOLS_DIR" \
        -DCMAKE_C_COMPILER="$CC" \
        -DCMAKE_CXX_COMPILER="$CXX" \
        -DCMAKE_C_FLAGS="-fsanitize=address,undefined,fuzzer-no-link -fno-sanitize-recover=all -O1 -g" \
        -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined,fuzzer-no-link -fno-sanitize-recover=all -O1 -g -std=c++17" \
        -DSPIRV-Headers_SOURCE_DIR="$SPIRV_HEADERS_DIR" \
        -DSPIRV_SKIP_TESTS=ON \
        -DSPIRV_SKIP_EXECUTABLES=ON \
        -DBUILD_SHARED_LIBS=OFF \
        2>&1 | tail -5
    make -j8 SPIRV-Tools-opt SPIRV-Tools 2>&1 | tail -5
    echo "SPIRV-Tools built: $(ls -la source/libSPIRV-Tools*.a 2>/dev/null)"
else
    echo "SPIRV-Tools already built"
fi

echo "=== Step 3: Compile ANGLE translator ==="
cd "$ANGLE_DIR"

# Collect all .cpp source files from compiler.gni
# This is parsed from the GNI file
TRANSLATOR_SOURCES=$(python3 -c "
import re
with open('src/compiler.gni') as f:
    content = f.read()

# Extract all .cpp files from all source lists
files = re.findall(r'\"(src/compiler/[^\"]+\.cpp)\"', content)
# Also get .c files
files += re.findall(r'\"(src/compiler/[^\"]+\.c)\"', content)
for f in sorted(set(files)):
    print(f)
")

# angle_common sources
COMMON_SOURCES=$(python3 -c "
import re
with open('src/libGLESv2.gni') as f:
    content = f.read()
files = re.findall(r'\"(src/common/[^\"]+\.cpp)\"', content)
files += re.findall(r'\"(src/common/[^\"]+\.c)\"', content)
# Add macOS specific
files.append('src/common/system_utils_posix.cpp')
files.append('src/common/system_utils_apple.cpp')
files.append('src/common/system_utils_mac.cpp')
# Filter out non-existent and platform-specific ones we don't want
import os
for f in sorted(set(files)):
    if os.path.exists(f):
        # Skip android/win/linux specific
        if 'android' in f or '_win' in f or '_linux' in f or '_fuchsia' in f:
            continue
        print(f)
")

# SPIRV common utilities
SPIRV_COMMON_SOURCES="src/common/spirv/angle_spirv_utils.cpp src/common/spirv/spirv_instruction_builder_autogen.cpp src/common/spirv/spirv_instruction_parser_autogen.cpp"

# xxhash
XXHASH_SOURCES="src/common/third_party/xxhash/xxhash.c"

# Preprocessor sources
PREPROCESSOR_SOURCES=$(python3 -c "
import re
with open('src/compiler.gni') as f:
    content = f.read()
files = re.findall(r'\"(src/compiler/preprocessor/[^\"]+\.cpp)\"', content)
for f in sorted(set(files)):
    print(f)
")

ALL_SOURCES="$TRANSLATOR_SOURCES $COMMON_SOURCES $SPIRV_COMMON_SOURCES $XXHASH_SOURCES $PREPROCESSOR_SOURCES"

# Count sources
echo "Total source files: $(echo $ALL_SOURCES | wc -w)"

# Compile each source file to object
OBJECTS=""
for src in $ALL_SOURCES; do
    if [ ! -f "$src" ]; then
        echo "SKIP (not found): $src"
        continue
    fi
    obj="$BUILD_DIR/obj/$(echo $src | tr '/' '_').o"
    mkdir -p "$(dirname $obj)"

    LANG_FLAG="-std=c++17"
    SANITIZE="-fsanitize=address,undefined,fuzzer-no-link"
    if [[ "$src" == *.c ]]; then
        LANG_FLAG="-std=c11"
        COMPILER="$CC"
    else
        COMPILER="$CXX"
    fi

    # Check for .mm (Objective-C++)
    if [[ "$src" == *.mm ]]; then
        LANG_FLAG="-std=c++17 -ObjC++"
        COMPILER="$CXX"
    fi

    $COMPILER \
        $SANITIZE \
        -fno-sanitize-recover=all \
        -O1 -g -fno-omit-frame-pointer \
        $LANG_FLAG \
        -DANGLE_ENABLE_ESSL \
        -DANGLE_ENABLE_GLSL \
        -DANGLE_ENABLE_HLSL \
        -DANGLE_ENABLE_VULKAN \
        -DANGLE_ENABLE_METAL \
        -DANGLE_ENABLE_WGPU \
        -DANGLE_ENABLE_NULL \
        -DANGLE_IS_64_BIT_CPU \
        -I. \
        -Isrc \
        -Iinclude \
        -Iout/gen/angle \
        -Ithird_party/spirv-headers/src/include \
        -Ithird_party/spirv-tools/src/include \
        -Ithird_party/abseil-cpp \
        -Isrc/common/base \
        -Isrc/common/third_party/xxhash \
        -c "$src" -o "$obj" 2>&1 || { echo "FAILED: $src"; continue; }
    OBJECTS="$OBJECTS $obj"
done

echo "=== Step 4: Create static library ==="
ar rcs "$BUILD_DIR/libangle_translator.a" $OBJECTS
echo "Library: $(ls -la $BUILD_DIR/libangle_translator.a)"

echo "=== Step 5: Compile and link fuzzer ==="
$CXX \
    -fsanitize=fuzzer,address,undefined \
    -fno-sanitize-recover=all \
    -O1 -g -fno-omit-frame-pointer \
    -std=c++17 \
    -DANGLE_ENABLE_ESSL \
    -DANGLE_ENABLE_GLSL \
    -DANGLE_ENABLE_HLSL \
    -DANGLE_ENABLE_VULKAN \
    -DANGLE_ENABLE_METAL \
    -DANGLE_ENABLE_WGPU \
    -I. \
    -Isrc \
    -Iinclude \
    -Iout/gen/angle \
    -Ithird_party/spirv-headers/src/include \
    -Ithird_party/spirv-tools/src/include \
    /Users/migriane/Downloads/fuzzmind/corebreaker/experiments/step0-angle/harness/angle_shader_fuzzer.cpp \
    "$BUILD_DIR/libangle_translator.a" \
    "$SPIRV_BUILD_DIR/source/libSPIRV-Tools.a" \
    "$SPIRV_BUILD_DIR/source/opt/libSPIRV-Tools-opt.a" \
    -lc++ -lpthread \
    -framework CoreFoundation \
    -framework IOKit \
    -o "$BUILD_DIR/angle_shader_fuzzer"

echo "=== Done ==="
echo "Fuzzer binary: $BUILD_DIR/angle_shader_fuzzer"
nm "$BUILD_DIR/angle_shader_fuzzer" | grep __asan_init && echo "ASan OK"
