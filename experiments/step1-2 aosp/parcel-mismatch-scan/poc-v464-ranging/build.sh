#!/bin/bash
# Manual APK build for V-464 PoC
# No Gradle required — uses SDK tools directly

set -e

SDK="$HOME/Library/Android/sdk"
BUILD_TOOLS="$SDK/build-tools/35.0.1"
PLATFORM="$SDK/platforms/android-35/android.jar"
AAPT2="$BUILD_TOOLS/aapt2"
D8="$BUILD_TOOLS/d8"
ZIPALIGN="$BUILD_TOOLS/zipalign"
APKSIGNER="$BUILD_TOOLS/apksigner"

SRC_DIR="app/src/main"
OUT_DIR="build"
PACKAGE="com.poc.rangingleak"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/compiled" "$OUT_DIR/classes" "$OUT_DIR/dex"

echo "[1/6] Compiling resources..."
$AAPT2 compile --dir "$SRC_DIR/res" -o "$OUT_DIR/compiled/" 2>/dev/null || true

echo "[2/6] Linking APK..."
$AAPT2 link \
    --manifest "$SRC_DIR/AndroidManifest.xml" \
    -I "$PLATFORM" \
    -o "$OUT_DIR/poc-unsigned-noclasses.apk" \
    --java "$OUT_DIR/R" \
    --auto-add-overlay 2>/dev/null || \
$AAPT2 link \
    --manifest "$SRC_DIR/AndroidManifest.xml" \
    -I "$PLATFORM" \
    -o "$OUT_DIR/poc-unsigned-noclasses.apk" \
    --auto-add-overlay

echo "[3/6] Compiling Java..."
# Find all java files
find "$SRC_DIR/java" -name "*.java" > "$OUT_DIR/sources.txt"
# Also compile R.java if generated
find "$OUT_DIR/R" -name "*.java" >> "$OUT_DIR/sources.txt" 2>/dev/null || true

javac \
    -source 1.8 -target 1.8 \
    -classpath "$PLATFORM" \
    -d "$OUT_DIR/classes" \
    @"$OUT_DIR/sources.txt"

echo "[4/6] Dexing..."
find "$OUT_DIR/classes" -name "*.class" > "$OUT_DIR/classes.txt"
$D8 \
    --lib "$PLATFORM" \
    --output "$OUT_DIR/dex" \
    $(cat "$OUT_DIR/classes.txt")

echo "[5/6] Assembling APK..."
cp "$OUT_DIR/poc-unsigned-noclasses.apk" "$OUT_DIR/poc-unsigned.apk"
cd "$OUT_DIR"
# Add classes.dex to the APK
zip -j poc-unsigned.apk dex/classes.dex
cd ..

echo "[6/6] Signing APK..."
# Generate a debug keystore if needed
KEYSTORE="$OUT_DIR/debug.keystore"
if [ ! -f "$KEYSTORE" ]; then
    keytool -genkeypair -v \
        -keystore "$KEYSTORE" \
        -keyalg RSA -keysize 2048 \
        -validity 10000 \
        -alias debug \
        -storepass android \
        -keypass android \
        -dname "CN=PoC,O=Security Research"
fi

$ZIPALIGN -f 4 "$OUT_DIR/poc-unsigned.apk" "$OUT_DIR/poc-aligned.apk"
$APKSIGNER sign \
    --ks "$KEYSTORE" \
    --ks-pass pass:android \
    --key-pass pass:android \
    --ks-key-alias debug \
    --out "$OUT_DIR/poc-v464-ranging.apk" \
    "$OUT_DIR/poc-aligned.apk"

echo ""
echo "=== Build complete ==="
echo "APK: $OUT_DIR/poc-v464-ranging.apk"
echo ""
echo "Install: adb install $OUT_DIR/poc-v464-ranging.apk"
echo "Run:     adb shell am start -n com.poc.rangingleak/.MainActivity"
