#!/bin/bash
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

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/compiled" "$OUT_DIR/classes" "$OUT_DIR/dex"

echo "[1/5] Linking APK..."
$AAPT2 link \
    --manifest "$SRC_DIR/AndroidManifest.xml" \
    -I "$PLATFORM" \
    -o "$OUT_DIR/base.apk" \
    --auto-add-overlay

echo "[2/5] Compiling Java..."
find "$SRC_DIR/java" -name "*.java" > "$OUT_DIR/sources.txt"
javac \
    -source 1.8 -target 1.8 \
    -classpath "$PLATFORM" \
    -d "$OUT_DIR/classes" \
    @"$OUT_DIR/sources.txt"

echo "[3/5] Dexing..."
find "$OUT_DIR/classes" -name "*.class" > "$OUT_DIR/classes.txt"
$D8 --lib "$PLATFORM" --output "$OUT_DIR/dex" $(cat "$OUT_DIR/classes.txt")

echo "[4/5] Assembling..."
cp "$OUT_DIR/base.apk" "$OUT_DIR/unsigned.apk"
cd "$OUT_DIR"
zip -j unsigned.apk dex/classes.dex
cd ..

echo "[5/5] Signing..."
KEYSTORE="$OUT_DIR/debug.keystore"
if [ ! -f "$KEYSTORE" ]; then
    keytool -genkeypair -v \
        -keystore "$KEYSTORE" -keyalg RSA -keysize 2048 -validity 10000 \
        -alias debug -storepass android -keypass android \
        -dname "CN=PoC,O=Security Research" 2>/dev/null
fi

$ZIPALIGN -f 4 "$OUT_DIR/unsigned.apk" "$OUT_DIR/aligned.apk"
$APKSIGNER sign \
    --ks "$KEYSTORE" --ks-pass pass:android --key-pass pass:android \
    --ks-key-alias debug --out "$OUT_DIR/poc-crossuser.apk" \
    "$OUT_DIR/aligned.apk"

echo ""
echo "=== Done ==="
echo "APK: $OUT_DIR/poc-crossuser.apk"
echo "Install: adb install $OUT_DIR/poc-crossuser.apk"
echo "Run:     adb shell am start -n com.poc.crossuser/.MainActivity"
