#!/bin/bash
# detect_v452.sh — Check if connected Android device is vulnerable to V-452
# (NfcService notifyHceDeactivated zero-permission payment DoS)
#
# Usage: ./detect_v452.sh
# Requires: adb connected to target device

set -e

echo "=== V-452 Vulnerability Fingerprint ==="
echo ""

if ! command -v adb &>/dev/null; then
    echo "[ERROR] adb not found in PATH"
    exit 1
fi

if ! adb get-state &>/dev/null; then
    echo "[ERROR] No device connected via adb"
    exit 1
fi

SDK=$(adb shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r')
BUILD=$(adb shell getprop ro.build.display.id 2>/dev/null | tr -d '\r')
DEVICE=$(adb shell getprop ro.product.model 2>/dev/null | tr -d '\r')
FINGERPRINT=$(adb shell getprop ro.build.fingerprint 2>/dev/null | tr -d '\r')
NFC_SVC=$(adb shell service check nfc 2>/dev/null | tr -d '\r')
NFC_MODULE=$(adb shell pm list packages --show-versioncode 2>/dev/null | grep nfcservices | tr -d '\r')

echo "Device:        $DEVICE"
echo "SDK Level:     $SDK"
echo "Build ID:      $BUILD"
echo "Fingerprint:   $FINGERPRINT"
echo "NFC Service:   $NFC_SVC"
echo "NFC Module:    $NFC_MODULE"
echo ""

if [ -z "$SDK" ]; then
    echo "[ERROR] Could not read SDK level"
    exit 1
fi

if echo "$NFC_SVC" | grep -q "not found"; then
    echo "[*] NFC service not available on this device"
    exit 0
fi

if [ "$SDK" -ge 35 ] 2>/dev/null; then
    echo "[!] SDK >= 35 (Android 15+) — POTENTIALLY VULNERABLE to V-452"
    echo "[!] notifyHceDeactivated() likely exposed without permission check"
    echo ""
    echo "[*] To confirm: install PoC APK and run V-452 test"
    echo "[*] Vulnerable if: no SecurityException in logcat"
    echo "[*] Monitor with: adb logcat -s NfcKillService NfcHijack"
elif [ "$SDK" -ge 34 ] 2>/dev/null; then
    echo "[?] SDK 34 (Android 14) — NEEDS VERIFICATION"
    echo "[?] notifyHceDeactivated may exist but needs confirmation"
else
    echo "[*] SDK < 34 — Likely NOT AFFECTED"
fi

echo ""
echo "=== End Fingerprint ==="
