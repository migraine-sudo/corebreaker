# [V-XX] Vulnerability Title

## Summary

One-paragraph description of the vulnerability.

## Severity

- **Type**: EoP / ID / RCE / DoS
- **Severity**: Critical / High / Medium / Low
- **CVSS**: X.X
- **User Interaction**: None / Required (describe)
- **Privileges Required**: None / Low / High

## Affected Component

- **AOSP Path**: `services/core/java/com/android/server/...`
- **Class**: `ClassName`
- **Method**: `methodName()`
- **Line**: XXXX

## Affected Versions

- Android XX+ (tested on Android XX, patch level YYYY-MM-DD)
- Pixel X / Emulator

## Root Cause

Technical description of why the vulnerability exists.

## Reproduction Steps

1. Install PoC APK (`poc/v-XX/app-debug.apk`)
2. ...
3. ...
4. Observe: ...

## PoC Code

```java
// Key exploit code snippet
```

## Expected Behavior

What should happen (secure behavior).

## Actual Behavior

What actually happens (insecure behavior).

## Evidence

- Logcat: `evidence/v-XX-logcat.txt`
- Screenshot: `evidence/v-XX-screenshot.png`

## Impact

What an attacker can achieve. Concrete scenario.

## Suggested Fix

```java
// Proposed patch
```

## Related CVEs

- CVE-YYYY-XXXXX (describe relation — variant of, bypass of, etc.)

## References

- AOSP Source: https://cs.android.com/...
- Android Security Bulletin: https://source.android.com/docs/security/bulletin/...
