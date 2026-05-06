# PoC: NFC Payment Hijack Chain (V-451 + V-452 + V-456)

## Summary

This PoC demonstrates a complete NFC payment attack chain on Android 15+ exploiting three vulnerabilities in NfcService:

| CVE ID | Method | Permission | Impact |
|--------|--------|-----------|--------|
| V-451 | `INfcAdapter.notifyPollingLoop()` | ZERO | Inject arbitrary NFC polling frames into HAL |
| V-452 | `INfcAdapter.notifyHceDeactivated()` | ZERO | Force-terminate active NFC payment sessions |
| V-456 | `INfcCardEmulation.setPreferredService()` | NFC (normal) | Intercept all NFC APDUs as foreground app |

## Attack Chain

```
[V-452] Kill active payment → [V-451] Inject polling → [V-456] Hijack HCE → Intercept APDUs
```

1. **Phase 1 (V-452)**: Continuously call `notifyHceDeactivated()` to terminate any existing payment session between the victim's phone and an NFC reader
2. **Phase 2 (V-451)**: Inject NFC-A polling frames via `notifyPollingLoop()` to trigger HCE service re-selection
3. **Phase 3 (V-456)**: Our malicious `HijackHceService` is set as preferred and receives all subsequent APDUs

## Root Cause

`NfcService.java` (Android 15 NFC mainline module) exposes `notifyPollingLoop()` and `notifyHceDeactivated()` as Binder methods on `INfcAdapter.Stub` with **ZERO permission checks**:

```java
// NfcService.java — INfcAdapter.Stub implementation:

@Override
public void notifyPollingLoop(PollingFrame frame) {
    // NO NfcPermissions.enforceUserPermissions() call!
    // NO NfcPermissions.enforceAdminPermissions() call!
    ((NativeNfcManager) mDeviceHost).notifyPollingLoopFrame(data.length, data);
}

@Override
public void notifyHceDeactivated() {
    // NO permission check!
    mCardEmulationManager.onHostCardEmulationDeactivated(1);
}
```

Compare with ALL other sensitive methods in the same class which DO check permissions:
- `enable()` → `enforceAdminPermissions()`
- `dispatch()` → `enforceAdminPermissions()`
- `setObserveMode()` → `enforceUserPermissions()` + validates preferred service
- `updateDiscoveryTechnology()` → `enforceUserPermissions()`

## Requirements

- **Device**: Pixel 8/9 or equivalent with NFC support
- **OS**: Android 15 (API 35) or later
- **Permissions**: Only `android.permission.NFC` (normal, auto-granted at install)
- **No root required**
- **No special privileges required**

## Build & Install

```bash
cd poc-nfc-hijack
./gradlew assembleDebug
adb install app/build/outputs/apk/debug/app-debug.apk
```

## Usage

1. Launch "NFC PoC" app
2. Press **"0. Test Binder Access"** — verify access to INfcAdapter binder
3. Individual tests:
   - **V-452: Kill** — starts loop that terminates all NFC payments
   - **V-451: Inject Polling** — injects fake NFC-A frames
   - **V-456: Set Preferred** — registers malicious HCE as preferred
   - **Fingerprint** — discovers installed NFC services
4. **FULL ATTACK CHAIN** — runs all three in sequence

## Verification

```bash
# Monitor NFC service logs:
adb logcat -s NfcService NfcKillService PollingInjector HijackHCE NfcHijack

# Expected output for V-452 (success = no SecurityException):
# NfcKillService: [V-452] HCE deactivation count: 100

# Expected output for V-451 (success = no SecurityException):
# PollingInjector: [V-451] Injection count: 50

# Expected output for V-456 (when phone taps NFC reader):
# HijackHCE: [V-456] INTERCEPTED APDU #1
# HijackHCE:   ★★★ PPSE SELECTED — Payment session starting! ★★★
```

## Impact

### Individual:
- **V-451**: Any app can simulate an NFC reader's presence without physical proximity
- **V-452**: Any app can permanently prevent NFC payments (invisible DoS)
- **V-456**: Foreground app can intercept all payment APDUs

### Combined:
- Full NFC payment MITM without root or special permissions
- Transaction data capture (card AID selection, transaction flow)
- Relay attack enabler (forward APDUs to remote legitimate card)
- Invisible to user (NFC appears enabled, no error messages)

## Affected Versions

- Android 15 (API 35) — `notifyPollingLoop` added without permission check
- Possibly Android 14 for `notifyHceDeactivated` (needs verification)
- NFC mainline module (com.google.android.nfcservices)

## Fix

Add permission checks to both methods:

```java
@Override
public void notifyPollingLoop(PollingFrame frame) {
    NfcPermissions.enforceAdminPermissions(mContext);  // ADD THIS
    // ... existing code
}

@Override
public void notifyHceDeactivated() {
    NfcPermissions.enforceAdminPermissions(mContext);  // ADD THIS
    // ... existing code
}
```

## Disclaimer

This PoC is for authorized security research only (Android VRP submission).
Do not use against systems without explicit authorization.
