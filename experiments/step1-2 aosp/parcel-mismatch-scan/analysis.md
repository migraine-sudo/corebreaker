# Parcel Mismatch Scan — Analysis Report

**Target**: Pixel 10 framework.jar (Android 16, CP1A.260405.005, 2026-04-05 security patch)
**Date**: 2026-04-30
**Scanner**: scan_v3.py (stream-based, dexdump -d bytecode analysis)
**Classes scanned**: 73 priority targets (new in Android 15/16)

---

## Summary

| Severity | Count | Notes |
|----------|-------|-------|
| TRUE POSITIVE | 1 | SatelliteModemEnableRequestAttributes |
| FALSE POSITIVE (branch counting) | 5 | Conditional paths / loops inflate static count |
| FALSE POSITIVE (lazy deser) | 1 | GenericDocumentWrapper uses deferred unparceling |
| MEDIUM (benign) | 1 | IdentityCheckStatus writeBoolean/readByte equivalent |
| OK (matched) | 64 | |

---

## Confirmed Finding: SatelliteModemEnableRequestAttributes

**Class**: `android.telephony.satellite.SatelliteModemEnableRequestAttributes`
**Module**: Telephony Satellite (Android 16)

### Vulnerability

`writeToParcel()` serializes `mSatelliteSubscriptionInfo` by directly calling:
```
mSatelliteSubscriptionInfo.writeToParcel(dest, flags)
```
This writes inline without class descriptor or non-null marker.

`<init>(Parcel)` deserializes using:
```
readParcelable(classLoader, SatelliteSubscriptionInfo.class)
```
Which expects a class name string + object data.

### Exploitability: LOW

The IPC path uses a separate AIDL-generated stub version (`android.telephony.satellite.stub.SatelliteModemEnableRequestAttributes`) which correctly uses `writeTypedObject()`. The non-stub version is only used within system_server's telephony stack and doesn't cross privilege boundaries.

---

## Full Framework Scan (2117 Parcelables)

- **755 classes** showed count mismatches (false positives from branches/loops)
- **5 classes** showed reads > writes
- After manual verification: **ALL are false positives** except SatelliteModemEnableRequestAttributes (LOW severity)

### Conclusion on Parcel Mismatch in 2025-2026

Modern Android framework code is largely immune to classical Parcel mismatch exploitation:
1. `@DataClass`-generated code produces consistent write/read pairs
2. AIDL-generated stubs use `writeTypedObject/readTypedObject` correctly
3. `LazyBundle` and `BaseBundle.unparcel()` mitigations make exploitation significantly harder

**Recommendation**: Parcel mismatch research on framework.jar is no longer productive for EoP bugs.

---

## Scanner Limitations

1. **No CFG analysis**: Counts all Parcel calls regardless of control flow
2. **No inter-procedural tracking**: Cannot follow helper methods beyond `readFromParcel()`
3. **Static counting**: Cannot distinguish conditional from unconditional writes
