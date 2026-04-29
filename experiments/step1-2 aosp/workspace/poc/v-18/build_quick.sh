#!/bin/bash
set -e

SDK="$HOME/Library/Android/sdk"
ANDROID_JAR="$SDK/platforms/android-35/android.jar"
D8="$SDK/build-tools/36.0.0/d8"
WORK_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$WORK_DIR/build"

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

echo "[1] Compiling QuickTest.java..."
javac -source 17 -target 17 \
    -classpath "$ANDROID_JAR" \
    -d "$BUILD_DIR" \
    "$WORK_DIR/QuickTest.java" \
    --add-exports java.base/sun.misc=ALL-UNNAMED 2>/dev/null || \
javac -classpath "$ANDROID_JAR" \
    -d "$BUILD_DIR" \
    "$WORK_DIR/QuickTest.java"

echo "[2] Converting to DEX..."
"$D8" --output "$BUILD_DIR" "$BUILD_DIR/QuickTest.class" --lib "$ANDROID_JAR"

echo "[3] Pushing to device..."
adb push "$BUILD_DIR/classes.dex" /data/local/tmp/QuickTest.dex

echo "[4] Running on device..."
adb shell "CLASSPATH=/data/local/tmp/QuickTest.dex app_process / QuickTest"

echo "[Done]"
