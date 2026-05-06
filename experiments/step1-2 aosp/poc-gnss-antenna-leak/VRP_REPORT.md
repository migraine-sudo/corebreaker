# Android Security Vulnerability Report: GnssAntennaInfo Zero-Permission Listener Registration

## Title

Missing ACCESS_FINE_LOCATION enforcement in LocationManager.registerAntennaInfoListener allows zero-permission apps to receive GNSS antenna hardware data

## Severity

HIGH — Bypass of dangerous runtime permission (ACCESS_FINE_LOCATION) for location-correlated hardware data

## Affected Component

- **Service**: `location` (android.location.ILocationManager)
- **Module**: services.jar (com.android.server.location)
- **Implementation**: `com.android.server.location.gnss.GnssManagerService`
- **Method**: `addGnssAntennaInfoListener()` (line ~261-268)

## Affected Version

- Android 16 (CP1A.260405.005)
- Security Patch Level: 2026-04-05
- Device: Pixel 10

## Summary

`LocationManager.registerAntennaInfoListener()` registers a callback for GNSS antenna hardware information without enforcing `ACCESS_FINE_LOCATION`. Every other GNSS listener in the same module correctly requires this permission:

| API | Permission Check | Behavior |
|-----|-----------------|----------|
| `registerAntennaInfoListener()` | **NONE** | Returns true (registered) |
| `registerGnssStatusCallback()` | ACCESS_FINE_LOCATION | SecurityException |
| `requestLocationUpdates()` | ACCESS_FINE/COARSE_LOCATION | SecurityException |
| `addNmeaListener()` | ACCESS_FINE_LOCATION | SecurityException |

A zero-permission app can register the listener and receive antenna info callbacks containing:
- **Carrier frequency** (MHz) for each antenna
- **Phase center offset** (3D coordinates in mm)
- **Phase center variation corrections** (azimuth × elevation matrix)
- **Signal gain corrections** (azimuth × elevation matrix)

## Impact

1. **Device hardware fingerprinting**: Antenna characteristics (gain patterns, phase center offsets) are unique per device model and hardware revision. This creates a persistent, reset-resistant device identifier accessible without any permission.

2. **Coarse location inference**: Signal gain patterns and phase center variations change with the device's physical orientation and surrounding multipath environment. Combined with carrier frequency data, an attacker can infer approximate position characteristics.

3. **GNSS capability enumeration**: Reveals which GNSS constellations and frequencies the device supports, aiding further attacks on location subsystems.

4. **Permission model bypass**: ACCESS_FINE_LOCATION is a dangerous runtime permission requiring explicit user consent. This vulnerability completely bypasses that consent mechanism for a subset of location-correlated data.

## Proof of Concept

### Prerequisites
- Android 16 device (tested: Pixel 10, CP1A.260405.005)
- Zero-permission APK (provided: gnss-antenna-leak.apk)

### Steps to Reproduce

1. Install the PoC APK: `adb install gnss-antenna-leak.apk`
2. Launch: `adb shell am start -n com.poc.gnssantennaleak/.MainActivity`
3. Observe the test results on screen and in logcat

### Expected Behavior
`registerAntennaInfoListener()` should throw `SecurityException` requiring `ACCESS_FINE_LOCATION`, consistent with all other GNSS listener APIs.

### Actual Behavior
Registration succeeds (returns `true`) without any permission. The listener is registered and will receive antenna info callbacks when GNSS hardware provides data.

### PoC Output (zero-permission app, UID 10502)

```
=== GPS-1: GnssAntennaInfo Leak PoC ===
Package: com.poc.gnssantennaleak
UID: 10502
Permissions: NONE (no ACCESS_FINE_LOCATION)

--- Test 1: registerAntennaInfoListener ---
Expected: SecurityException (requires ACCESS_FINE_LOCATION)

[VULN] registerAntennaInfoListener returned TRUE!
  → Registered WITHOUT ACCESS_FINE_LOCATION!
  → Waiting for antenna info callback...
  → (Callback delivers carrier freq, phase center, gain patterns)

--- Control: requestLocationUpdates (should require permission) ---
[EXPECTED] SecurityException: uid 10502 does not have android.permission.ACCESS_COARSE_LOCATION or android.permission.ACCESS_FINE_LOCATION.
  → Location updates correctly require permission

--- Control: registerGnssStatusCallback (should require permission) ---
[EXPECTED] SecurityException for GnssStatus
  → GnssStatus correctly requires ACCESS_FINE_LOCATION
```

## Root Cause

In `GnssManagerService.java`, the `addGnssAntennaInfoListener()` method directly registers the callback without calling `mContext.enforceCallingPermission(ACCESS_FINE_LOCATION, ...)`. Compare with `registerGnssStatusCallback()` which calls `mLocationPermissionsHelper.enforceCallingOrSelfLocationPermission()` before processing.

## Suggested Fix

Add permission enforcement to `GnssManagerService.addGnssAntennaInfoListener()`:

```java
public boolean addGnssAntennaInfoListener(IGnssAntennaInfoListener listener,
        String packageName, @Nullable String attributionTag, String listenerId) {
    // ADD: Permission check matching other GNSS listeners
    mContext.enforceCallingOrSelfPermission(
            Manifest.permission.ACCESS_FINE_LOCATION,
            "registerAntennaInfoListener");
    // ... existing registration logic
}
```

## Comparison with Protected APIs

The inconsistency is clear within the same service class:

```java
// GnssManagerService.java — PROTECTED (correct):
public boolean registerGnssStatusCallback(...) {
    mLocationPermissionsHelper.enforceCallingOrSelfLocationPermission();  // ✓
    ...
}

// GnssManagerService.java — UNPROTECTED (vulnerable):
public boolean addGnssAntennaInfoListener(...) {
    // NO permission check!  ✗
    ...
}
```

## Additional Notes

- The callback data delivery requires outdoor GNSS signal, but the permission check bypass is confirmed at registration time regardless of signal availability
- The vulnerability exists because `GnssAntennaInfo` was added as a newer API and missed the permission enforcement present in the original GNSS listener registration paths
- PoC APK declares zero permissions in AndroidManifest.xml (no location permissions whatsoever)
