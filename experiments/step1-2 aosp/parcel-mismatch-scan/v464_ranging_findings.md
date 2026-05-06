# V-464: IRangingAdapter — Permissionless Capability Enumeration + OOB Data Interception

**Date**: 2026-05-01
**Target**: Pixel 10, Android 16 (CP1A.260405.005, 2026-04-05 SPL)
**Service**: `ranging` (android.ranging.IRangingAdapter)
**Module**: com.android.uwb APEX (service-ranging.jar)
**Implementation**: `com.android.server.ranging.RangingServiceImpl`
**Severity**: MEDIUM-HIGH (bypass of runtime permission requirement)

---

## Summary

The new unified Ranging service (Android 16) has **7 of 13 methods without any permission check**, while the remaining 6 properly enforce `android.permission.RANGING` (a dangerous/runtime permission). This means a zero-permission app can:

1. **Register capabilities callback** — enumerate all ranging capabilities (UWB, BLE CS, WiFi RTT technologies)
2. **Register OOB data send listener** — intercept Out-of-Band ranging data from active sessions
3. **Inject OOB lifecycle events** — signal OOB channel close/disconnect/reconnect for active sessions

## Permission Enforcement Analysis

| Scanner TX | Runtime TX | Method | Permission Check | Status |
|---|---|---|---|---|
| 13 | 1 | startRanging | `enforceRangingPermissionForPreflight` (AttributionSource) | ✓ Protected |
| 12 | 2 | reconfigureRangingInterval | `enforceRangingPermission` | ✓ Protected |
| 11 | 3 | addRawDevice | `enforceRangingPermission` | ✓ Protected |
| 10 | 4 | addOobDevice | `enforceRangingPermission` (+ throws "not supported yet") | ✓ Protected |
| 9 | 5 | removeDevice | `enforceRangingPermission` | ✓ Protected |
| 8 | 6 | stopRanging | `enforceRangingPermission` | ✓ Protected |
| **7** | **7** | **registerCapabilitiesCallback** | **NONE** | **VULNERABLE** |
| **6** | **8** | **unregisterCapabilitiesCallback** | **NONE** | **VULNERABLE** |
| **5** | **9** | **oobDataReceived** | **NONE** | **VULNERABLE** |
| **4** | **10** | **deviceOobDisconnected** | **NONE** | **VULNERABLE** |
| **3** | **11** | **deviceOobReconnected** | **NONE** | **VULNERABLE** |
| **2** | **12** | **deviceOobClosed** | **NONE** | **VULNERABLE** |
| **1** | **13** | **registerOobSendDataListener** | **NONE** | **VULNERABLE** |

TX mapping: Runtime TX = 14 - Scanner TX (N=13 methods)

## Permission Required (by protected methods)

```
android.permission.RANGING — protection level: dangerous (runtime permission)
```

Apps must request this permission and user must grant it to use ranging. But the 7 unprotected methods bypass this entirely.

## Runtime Verification

```bash
# registerOobSendDataListener (Runtime TX=13) — SUCCESS, no permission denial
adb shell service call ranging 13
# Result: Parcel(00000000) — SUCCESS

# registerCapabilitiesCallback (Runtime TX=7) — reaches impl, NPE on null callback
adb shell service call ranging 7
# Result: NPE "Attempt to invoke interface method..." — NO permission denial

# unregisterCapabilitiesCallback (Runtime TX=8) — reaches impl, NPE on null callback
adb shell service call ranging 8
# Result: NPE — NO permission denial

# startRanging (Runtime TX=1) — reaches enforceRangingPermissionForPreflight, NPE on null params
adb shell service call ranging 1
# Result: NPE at enforceRangingPermissionForPreflight (params null, not permission denied)

# addOobDevice (Runtime TX=4) — properly reaches enforceRangingPermission, then throws "not supported"
adb shell service call ranging 4
# Result: "Dynamic addition of oob peer not supported yet"
```

## Bytecode Evidence

### registerCapabilitiesCallback (VULNERABLE)
```
[03f870] RangingServiceImpl.registerCapabilitiesCallback:(IRangingCapabilitiesCallback)V
0000: iget-object v0, RangingServiceImpl.mRangingInjector
0002: invoke-virtual RangingInjector.getRangingServiceManager()
0006: invoke-virtual RangingServiceManager.registerCapabilitiesCallback(v1)
0009: return-void
```
**No permission check before delegation.**

### registerOobSendDataListener (VULNERABLE)
```
[03f894] RangingServiceImpl.registerOobSendDataListener:(IOobSendDataListener)V
0000: iget-object v0, RangingServiceImpl.mRangingInjector
0002: invoke-virtual RangingInjector.getRangingServiceManager()
0006: invoke-virtual RangingServiceManager.registerOobSendDataListener(v1)
0009: return-void
```
**No permission check before delegation.**

### startRanging (PROTECTED — for comparison)
```
[03f8e4] RangingServiceImpl.startRanging:(AttributionSource;SessionHandle;RangingPreference;IRangingCallbacks)V
0000: iget-object v0, RangingServiceImpl.mRangingInjector
0002: invoke-virtual RangingInjector.enforceRangingPermissionForPreflight(AttributionSource)
0005: iget-object v1, RangingServiceImpl.mRangingInjector
0007: invoke-virtual RangingInjector.getRangingServiceManager()
000b: invoke-virtual RangingServiceManager.startRanging(...)
```
**Permission check BEFORE delegation.**

## Impact Assessment

### 1. Capability Enumeration (registerCapabilitiesCallback)
- Zero-permission app learns what ranging technologies the device supports
- Reveals UWB chip capabilities, BLE Channel Sounding support, WiFi RTT parameters
- Device fingerprinting: different devices have different ranging capabilities

### 2. OOB Data Interception (registerOobSendDataListener)
- Any app can register to receive OOB (Out-of-Band) ranging data
- OOB data includes device pairing/ranging configuration exchanged between devices
- Could intercept BLE/WiFi channel info used to bootstrap UWB ranging sessions
- Potential for man-in-the-middle on ranging session establishment

### 3. OOB Lifecycle Manipulation (deviceOobClosed/Disconnected/Reconnected, oobDataReceived)
- Any app can inject fake OOB lifecycle events
- `deviceOobClosed` — signal that an OOB channel was closed (DoS against ranging)
- `deviceOobDisconnected` — signal disconnection
- `deviceOobReconnected` — signal reconnection with potentially different parameters
- `oobDataReceived` — inject fake OOB data into the ranging session state machine

### Attack Scenarios

**Scenario A: Ranging DoS**
1. Untrusted app calls `registerCapabilitiesCallback` — learns device supports UWB
2. Monitors for active OOB handles
3. Calls `deviceOobClosed(handle)` — disrupts active ranging session

**Scenario B: Session Hijack Preparation**
1. Untrusted app calls `registerOobSendDataListener`
2. When legitimate app initiates ranging, attacker receives OOB configuration data
3. Attacker learns session parameters (peer addresses, keys exchanged via OOB)
4. Could enable relay attacks on UWB ranging

**Scenario C: Fake OOB Data Injection**
1. Untrusted app calls `oobDataReceived(fakeHandle, maliciousData)`
2. RangingServiceManager processes the data as if from legitimate OOB channel
3. Could corrupt session state or trigger unexpected behavior

## Root Cause

Inconsistent permission enforcement in `RangingServiceImpl`:
- Methods that perform active ranging operations (start/stop/reconfigure/add/remove) all call `enforceRangingPermission()` or `enforceRangingPermissionForPreflight()`
- Registration and OOB lifecycle methods skip permission enforcement entirely
- Likely an oversight: developers protected the "active" operations but forgot the "passive" listener and event-injection methods

## PoC Strategy

Build APK with zero permissions that:
1. Resolves `ranging` binder via ServiceManager
2. Calls `registerCapabilitiesCallback` with a custom callback binder
3. Receives ranging capabilities without any permission
4. Calls `registerOobSendDataListener` with a custom listener
5. Demonstrates receiving OOB data when another app ranges

## Priority

**HIGH** for VRP submission because:
- Brand new Android 16 service (no previous CVE coverage)
- Bypasses a runtime (dangerous) permission requirement
- Affects device ranging security (UWB is used for digital car keys, FindMy, etc.)
- Clear inconsistency with methods that DO enforce permissions
- State mutation possible (OOB lifecycle injection)
