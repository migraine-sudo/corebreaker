# Report 30: Round 19 — SensorService, LocationManager, TelecomService

**Date**: 2026-04-30  
**Scope**: SensorService (native), GnssManagerService, LocationManagerService, TelecomServiceImpl  
**Method**: 2 deep background agents + partial recovery from stalled agent  
**Previous**: Reports 01-29, ~329 variants

---

## Part A: SensorService (1 finding)

### V-329: addProximityActiveListener Zero-Permission Phone Call State Detection [HIGH]

**File**: `frameworks/native/services/sensorservice/SensorService.cpp` (lines 1983-2001)

**Issue**: `addProximityActiveListener()` registers a callback that fires whenever the proximity sensor activates/deactivates. There is NO permission check. The proximity sensor activates primarily during phone calls (to turn off the screen when held to ear), making this a zero-permission phone call state oracle.

```cpp
status_t SensorService::addProximityActiveListener(
        const sp<IProximityActiveListener>& callback) {
    // NO permission check!
    Mutex::Autolock _l(mLock);
    mProximityActiveListeners.push_back(callback);
    // Immediately fires current state
    if (mProximityActive) {
        callback->onProximityActive(true);
    }
    return OK;
}
```

**Attack**:
1. Zero-permission app calls `ISensorServer::addProximityActiveListener(callback)`
2. Callback fires `onProximityActive(true)` when user picks up phone for a call
3. Callback fires `onProximityActive(false)` when call ends or user checks screen
4. Duration between active/inactive = call duration
5. Frequency of transitions = call frequency/patterns

**Disclosed Information**:
- Real-time phone call state (active/inactive)
- Call duration (time between transitions)
- Call frequency patterns (behavioral fingerprint)
- Whether user is in a meeting (repeated short proximity activations = checking phone)

**Permission**: ZERO  
**Impact**: Behavioral surveillance — phone call timing without READ_PHONE_STATE  
**Bounty**: $3,000-$7,000

---

## Part B: GnssManagerService (1 finding)

### V-330: addGnssAntennaInfoListener Missing Permission Check [HIGH]

**File**: `services/core/java/com/android/server/location/gnss/GnssManagerService.java` (lines 261-268)

**Issue**: `addGnssAntennaInfoListener()` does NOT enforce `ACCESS_FINE_LOCATION`, unlike every other GNSS listener method (`addGnssNavigationMessageListener`, `addGnssMeasurementsListener`, `addGnssStatusListener` all properly enforce location permission).

```java
public void addGnssAntennaInfoListener(IGnssAntennaInfoListener listener) {
    // Compare: addGnssNavigationMessageListener enforces ACCESS_FINE_LOCATION
    // Compare: addGnssMeasurementsListener enforces ACCESS_FINE_LOCATION
    // This method: NO permission enforcement!
    mGnssAntennaInfoProvider.addListener(listener);
}
```

**Disclosed Information via GnssAntennaInfo**:
- `getPhaseCenterOffset()` — antenna phase center coordinates (device hardware fingerprint)
- `getPhaseCenterVariationCorrections()` — correction matrix (unique per device model/variant)
- `getSignalGainCorrections()` — signal gain patterns
- Number and configuration of GNSS antennas (hardware topology)

**Attack**:
1. Zero-permission app registers `IGnssAntennaInfoListener`
2. Receives `GnssAntennaInfo` objects containing hardware-specific antenna characteristics
3. Phase center offset + variation corrections = unique device fingerprint
4. Combined with public device databases, narrows device model to specific hardware revision

**Permission**: ZERO (should require ACCESS_FINE_LOCATION like sibling methods)  
**Impact**: Hardware fingerprinting, device model identification without any permission  
**Bounty**: $2,000-$5,000

---

## Part C: LocationManagerService (1 finding)

### V-331: LOCATION_BYPASS Provider Pre-Registration Without Permission [MEDIUM]

**File**: `services/core/java/com/android/server/location/LocationManagerService.java`

**Issue**: `addProviderRequestListener()` with `LOCATION_BYPASS` attribution tag allows registration without active location permission. While actual location delivery is gated, the registration itself reveals which location providers exist and their state (enabled/disabled per user).

**Attack**:
1. App registers provider request listener
2. Receives callbacks about provider state changes
3. Learns which location providers are available (GPS, network, fused)
4. Detects when user enables/disables location services

**Permission**: ZERO for registration; delivery properly gated  
**Impact**: Location service state monitoring (defense-in-depth gap)  
**Bounty**: $500-$1,000

---

## Part D: TelecomService (1 finding)

### V-332: getPhoneAccount Cross-Profile Disclosure via Unconditional acrossProfiles=true [MEDIUM-HIGH]

**File**: `packages/services/Telecomm/src/com/android/server/telecom/TelecomServiceImpl.java` (lines 600-655)

**Issue**: `getPhoneAccount(PhoneAccountHandle)` passes `acrossProfiles=true` unconditionally to the internal lookup. This means a caller in the personal profile can query phone accounts registered in managed/work profiles, and vice versa. The method only checks `READ_PHONE_NUMBERS` or `READ_PRIVILEGED_PHONE_STATE` but does NOT verify the caller belongs to the same profile as the requested account.

```java
@Override
public PhoneAccount getPhoneAccount(PhoneAccountHandle accountHandle,
        String callingPackage) {
    ...
    long token = Binder.clearCallingIdentity();
    try {
        // acrossProfiles=true — queries ALL profiles unconditionally
        PhoneAccount account = mPhoneAccountRegistrar
                .getPhoneAccount(accountHandle, UserHandle.getUserId(callingUid),
                        /* acrossProfiles= */ true);
        return maybeCleansePhoneAccount(account);
    } finally {
        Binder.restoreCallingIdentity(token);
    }
}
```

**Attack**:
1. App in personal profile with READ_PHONE_NUMBERS (runtime permission)
2. Calls `TelecomManager.getPhoneAccount(workProfileAccountHandle)`
3. Receives PhoneAccount from work profile including: address (phone number), label, capabilities, supported URI schemes
4. Reveals work phone numbers, SIP accounts, VoIP configurations in managed profile

**Permission**: READ_PHONE_NUMBERS (runtime)  
**Impact**: Cross-profile phone account disclosure violating work/personal isolation  
**Bounty**: $1,000-$3,000

---

## Round 19 Summary

| Severity | Count | Key Findings |
|----------|-------|-------------|
| HIGH | 2 | Proximity sensor call oracle (V-329), GNSS antenna fingerprint (V-330) |
| MEDIUM-HIGH | 1 | TelecomService cross-profile (V-332) |
| MEDIUM | 1 | Location provider state (V-331) |
| **Total** | **4** | |

**Estimated bounty this round**: $6,500 - $16,000

---

## Cumulative Project Statistics (Reports 01-30)

| Metric | Previous | This Round | Cumulative |
|--------|----------|------------|------------|
| Total variants | ~329 | +4 | **~333** |
| HIGH/CRITICAL | ~47 | +2 | **~49** |
| Bounty estimate (low) | $645.4k | +$6.5k | **$651.9k** |
| Bounty estimate (high) | $1.580M | +$16k | **$1.596M** |

---

## Updated Composite: Zero-Permission Surveillance Suite (V-311 + V-312 + V-313 + V-329)

Adding V-329 to the composite chain:

| Capability | Variant | Permission |
|-----------|---------|-----------|
| Foreground app oracle | V-311 AppOps | ZERO |
| App permission profiles | V-312 checkOperation | ZERO |
| Private Space detection | V-313 CE storage | ZERO |
| Push notification timing | V-306 DeviceIdle | ZERO |
| Phone call state/duration | V-329 Proximity sensor | ZERO |
| Coarse geolocation | V-317 WiFi freq/RSSI | ACCESS_WIFI_STATE |
| VPN usage detection | V-319 Network caps | ACCESS_NETWORK_STATE |
| Enterprise/MDM detection | V-318 Proxy | ZERO |
| Device hardware fingerprint | V-330 GNSS antenna | ZERO |

A zero-permission app now achieves: app usage surveillance + phone call monitoring + Private Space detection + device fingerprinting. Combined chain value: **$20,000-$40,000**.

---

*Generated by FuzzMind/CoreBreaker Round 19 — 2026-04-30*
