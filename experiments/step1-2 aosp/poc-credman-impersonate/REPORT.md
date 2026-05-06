# V-395: CredentialManager getCandidateCredentials Missing enforceCallingPackage

## Vulnerability Details

The `getCandidateCredentials()` method in `CredentialManagerService.java` does NOT call `enforceCallingPackage()` to validate that the `callingPackage` parameter matches `Binder.getCallingUid()`. This allows any zero-permission app to impersonate another package when requesting credential candidate information from credential providers.

In contrast, the adjacent method `executeGetCredential()` correctly validates the caller's identity before processing the request.

**Root Cause**: When `getCandidateCredentials` was implemented, the developer used `constructCallingAppInfo(callingPackage, ...)` to build the caller identity, but never added the corresponding `enforceCallingPackage(callingPackage, callingUid)` check that exists in all other credential-related methods.

**Source**: `services/credentials/java/com/android/server/credentials/CredentialManagerService.java`

```java
// Line 486-540 — getCandidateCredentials: NO enforceCallingPackage()
public ICancellationSignal getCandidateCredentials(
        GetCredentialRequest request,
        IGetCandidateCredentialsCallback callback,
        IBinder clientBinder,
        final String callingPackage) {
    Slog.i(TAG, "starting getCandidateCredentials with callingPackage: " + callingPackage);
    // ... NO enforceCallingPackage(callingPackage, callingUid) HERE ...
    constructCallingAppInfo(callingPackage, userId, request.getOrigin()),  // Line 508: uses UNVERIFIED pkg
    // ...
}

// Line 543-554 — executeGetCredential: HAS enforceCallingPackage()
public ICancellationSignal executeGetCredential(
        GetCredentialRequest request,
        IGetCredentialCallback callback,
        final String callingPackage) {
    // ...
    enforceCallingPackage(callingPackage, callingUid);  // Line 554: VALIDATES caller identity
    // ...
}
```

The `enforceCallingPackage` implementation (line 1106):
```java
private void enforceCallingPackage(String callingPackage, int callingUid) {
    int packageUid = pm.getPackageUid(callingPackage, ...);
    if (packageUid != callingUid) {
        throw new SecurityException(callingPackage + " does not belong to uid " + callingUid);
    }
}
```

## Impact

### Attack Conditions
- Target device: Android 14+ with CredentialManager enabled
- Attacker: Any installed app with **ZERO permissions**
- No user interaction required

### Impact Effects
1. **Package impersonation**: Any app can pose as another package (e.g., Chrome, banking apps) when requesting credential candidates from providers
2. **Credential metadata exposure**: Credential providers (Google Password Manager) respond with credential metadata (usernames, credential types, provider info) intended for the impersonated app
3. **Phishing enablement**: Attacker learns which sites/services have saved credentials for the target app, enabling targeted phishing attacks

### What CANNOT be accessed (boundaries confirmed)
- Cannot retrieve actual passwords or passkeys (requires user interaction through system UI)
- Cannot directly execute credential retrieval (`executeGetCredential` has enforceCallingPackage)

### Attack Scenario
1. Malicious app with zero permissions installed on device
2. App calls `getCandidateCredentials` with `callingPackage="com.android.chrome"` via raw Binder transact
3. Google Password Manager receives request appearing from Chrome → responds with credential candidates for Chrome
4. Attacker learns: which websites have saved passwords in Chrome, which accounts exist
5. Attacker uses this information to craft targeted phishing pages

### Severity
- **Information Disclosure + Privilege Escalation** (impersonation)
- Enables credential metadata theft without any permission
- Defeats the CredentialManager's package identity verification design

## Reproduction Steps

### Prerequisites
- Android 14+ device with CredentialManager enabled (tested on Android 16, SDK 36, security patch 2026-04-05)
- At least one credential provider configured (Google Password Manager)

### App-based verification (definitive test)
1. Build and install `apk/` project (**ZERO permissions** in manifest)
2. Launch "CredMan Impersonate PoC"
3. Tap "4. Full Chain (All Steps)"
4. Check logcat output (`adb logcat -s CredManLeak`):
   - Code 2 SPOOFED → BLOCKED by enforceCallingPackage (executePrepareGetCredential)
   - Code 3 → Server accepts spoofed package
5. Verify server-side: `adb logcat | grep CredentialManager:`
   - `starting getCandidateCredentials with callingPackage: com.google.android.gms`
   - NO SecurityException thrown for the spoofed package

### Minimal ADB + logcat verification
```bash
# 1. Install zero-permission PoC
adb install poc-credman.apk

# 2. Run the app and tap "4. Full Chain"
adb shell am start -n com.poc.credmanleak/.MainActivity

# 3. Check server-side logs:
adb logcat | grep "CredentialManager:"
# Expected output:
#   starting getCandidateCredentials with callingPackage: com.google.android.gms
#   (NO "does not belong to uid" SecurityException)

# 4. Compare with protected method (executeGetCredential):
#   starting executeGetCredential with callingPackage: com.google.android.gms
#   → throws SecurityException: com.google.android.gms does not belong to uid 10493
```

### Key comparison demonstrating the vulnerability:
| Method | Transaction Code | Spoofed Package | Result |
|--------|-----------------|-----------------|--------|
| `executePrepareGetCredential` | 2 | com.google.android.gms | **BLOCKED** by enforceCallingPackage |
| `getCandidateCredentials` | 3 | com.google.android.gms | **ACCEPTED** — no enforceCallingPackage |
| `executeGetCredential` | 1 | com.google.android.gms | **BLOCKED** by enforceCallingPackage |

**Expected (vulnerable)**: getCandidateCredentials accepts spoofed package; server log shows the impersonated package name
**Expected (patched)**: SecurityException thrown before method body executes

## Device Fingerprint

| Field | Value |
|-------|-------|
| AOSP Source | `services/credentials/java/com/android/server/credentials/CredentialManagerService.java` |
| Vulnerable Method | `getCandidateCredentials(GetCredentialRequest, IGetCandidateCredentialsCallback, IBinder, String)` — line 486 |
| Missing Check | No `enforceCallingPackage(callingPackage, callingUid)` call between line 486-540 |
| Secure Comparison | `executeGetCredential()` at line 554 calls `enforceCallingPackage()` |
| Secure Comparison 2 | `executePrepareGetCredential()` at line 612 calls `enforceCallingPackage()` |
| enforceCallingPackage impl | Line 1106-1119 — verifies `pm.getPackageUid(callingPackage) == callingUid` |
| Unvalidated Usage | `constructCallingAppInfo(callingPackage, userId, origin)` at line 508 |
| AIDL Interface | `android.credentials.ICredentialManager` |
| Transaction Code | FIRST_CALL_TRANSACTION + 2 (code 3) |
| Affected Versions | Android 14+ (CredentialManager introduction) through Android 16 |
| Tested On | Pixel, Android 16 (SDK 36), security patch 2026-04-05 |
| PoC App UID | 10493 (regular untrusted app) |
| Permissions Required | NONE |

## Suggested Fix

Add `enforceCallingPackage` to `getCandidateCredentials` before any use of `callingPackage`:

```java
public ICancellationSignal getCandidateCredentials(
        GetCredentialRequest request,
        IGetCandidateCredentialsCallback callback,
        IBinder clientBinder,
        final String callingPackage) {
    final int callingUid = Binder.getCallingUid();
    enforceCallingPackage(callingPackage, callingUid);  // ADD THIS
    // ... rest of method
}
```
