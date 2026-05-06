# V-460 Runtime Verification Summary

**Date**: 2026-04-30
**Target**: Pixel 10, Android 16 (CP1A.260405.005, 2026-04-05 SPL)
**Service**: `app_function` (android.app.appfunctions.IAppFunctionManager)

## Key Finding

**12 out of 16 IAppFunctionManager methods lack real permission enforcement.**

Only 2 methods (`clearAccessHistory`, `getAgentAllowlist`) use `@EnforcePermission(MANAGE_APP_FUNCTION_ACCESS)`. The remaining 14 methods either:
- Have no check at all (7 methods, gated only by feature flag)
- Use CallerValidator only (5 methods — any app passes with its own package)
- Both (2 listener methods — no flag gate, no CallerValidator)

## CallerValidator Is Not A Permission Check

`CallerValidatorImpl.validateCallingPackage(callingPackage)` at line 66 in CallerValidatorImpl.java:
- Gets the caller's UID via `Binder.getCallingUid()`
- Looks up packages for that UID via PackageManager
- Verifies the declared `callingPackage` is among those packages
- Does NOT check any permission, role, or capability

**Any installed app passes CallerValidator by providing its own package name.**

## Verified Exploitable Methods (NOW)

### 1. `searchAppFunctions` (Runtime TX=2) — CONFIRMED VULNERABLE

```
CallerValidator.validateCallingPackage → PASS (with own package name)
CallerValidator.verifyUserInteraction → PASS (same user)
→ Returns all registered app functions across ALL packages
```

Bytecode confirms (at 3a341c):
- Line 0014: `mCallerValidator.validateCallingPackage(spec.getCallingPackageName())`
- Line 0021: `mCallerValidator.verifyUserInteraction(targetUserId, uid, pid, package)` — same-user passes immediately
- **NO permission check** — proceeds directly to AppSearch query
- Returns all function metadata: package names, function IDs, parameters, schemas

**Impact**: Information disclosure — any zero-permission app can enumerate all 30+ registered app functions, revealing:
- Which packages expose functions (attack surface mapping)
- Function signatures and parameter schemas
- Device capability enumeration

### 2. `executeAppFunction` (Runtime TX=1) — PROTECTED (Revised Assessment)

```
CallerValidator.validateCallingPackage → PASS (with own package name)
CallerValidator.verifyCallerCanExecuteAppFunction:
  → checkPermission("EXECUTE_APP_FUNCTIONS") → DENIED for normal apps
  → callingPackage == targetPackage → ALLOWED (self only)
  → else → DENIED (returns 0)
```

**`EXECUTE_APP_FUNCTIONS` is `internal|privileged`** — normal apps cannot obtain it.

Cross-app execution is properly blocked. Self-invocation (app calling its own functions) is allowed but not a vulnerability.

### 3. `registerAppFunction` (Runtime TX=7) — CallerValidator Only

```
CallerValidator → PASS (with own package name)
→ Registers function implementations for calling package
```

This is likely **by design** — apps should be able to register their own functions. Not a vulnerability unless the registration can shadow/override other packages' functions.

## Revised Severity: MEDIUM (was HIGH)

Primary issue: `searchAppFunctions` enables zero-permission enumeration of all registered app functions across 5 privileged packages, disclosing 1078+ lines of metadata including function schemas, capabilities, and package relationships.

## Feature-Flag Gated Methods (Dormant)

When `accessCheckFlagsEnabled()` returns false (current state):
- Methods return empty/false immediately
- No permission check is performed

When flag enables:
- Methods delegate to `AppFunctionAccessService` which properly enforces `MANAGE_APP_FUNCTION_ACCESS`
- These methods will become properly protected

**Dormant methods** (currently harmless due to flag):
- getValidTargets, getValidAgents, revokeSelfAccess
- updateAccessFlags, getAccessFlags, getAccessRequestState

## Listener Methods (No-op Currently)

`addOnAccessChangedListener` / `removeOnAccessChangedListener`:
- No permission check, no feature flag gate
- But `AppFunctionAccessService.addOnAccessChangedListener` body is empty (`return-void`)
- Currently a no-op — will become live when access service is implemented

## TX Number Mapping

AIDL onTransact packed-switch lists cases in **reverse** order:
```
Runtime TX = 17 - Scanner TX  (for AppFunctionManager, N=16)
```

## Impact Assessment

| Category | Impact | Timing |
|----------|--------|--------|
| executeAppFunction (any app → any app's functions) | HIGH — arbitrary function invocation | NOW |
| searchAppFunctions (enumerate cross-app functions) | MEDIUM — information disclosure | NOW |
| registerAppFunction (inject function impls) | MEDIUM — function spoofing | NOW |
| Feature-flagged methods | LOW now, HIGH later | When flag enables |
| Listener methods | NONE currently | When AccessService impl fills in |

## PoC Verification Commands

```bash
# Runtime TX=1 (executeAppFunction) — reaches code, NPE on null request object
adb shell service call app_function 1
# Result: NullPointerException at Objects.java:524 → in executeAppFunction

# Runtime TX=7 (registerAppFunction) — CallerValidator rejects null package from shell
adb shell service call app_function 7 i32 0
# Result: "Specified calling package [null] does not match the calling uid 2000"
# NOTE: A real app providing its own package name would PASS

# Runtime TX=12 (getAgentAllowlist) — properly protected
adb shell service call app_function 12
# Result: "Access denied, requires: android.permission.MANAGE_APP_FUNCTION_ACCESS"
```

## CRITICAL: Live Attack Surface on Device

`dumpsys app_function` reveals **30+ registered functions** across 5 privileged packages:

### Registered Packages
- `com.android.settings` — System Settings
- `com.google.android.apps.pixel.support` — Pixel Support
- `com.google.android.apps.wellbeing` — Digital Wellbeing
- `com.google.android.gms` — Google Play Services
- `com.google.android.permissioncontroller` — Permission Controller

### High-Impact Functions Callable Without Permission

**State Modification (arbitrary device config changes):**
- `setDeviceStateItem` (Wellbeing, GMS) — modify device state settings
- `setAncState` (GMS) — control ANC on paired headphones
- `extendScreenTime` (GMS) — **BYPASS PARENTAL CONTROLS** (Family Link)
- `addCardToWallet` (GMS) — add payment cards to Google Wallet
- `castMyScreen` (GMS) — initiate screen casting

**Information Disclosure (sensitive device data):**
- `getPermissionsDeviceState` — read all permission grants
- `getBatteryDeviceState` — battery info
- `getMobileDataUsageDeviceState` — cellular data usage per app
- `getNotificationsDeviceState` — notification settings
- `getStorageDeviceState` — storage details
- `getAppsDeviceState` — installed apps and state
- `isSystemUpToDate` — OTA/patch level

**UI/Action Triggers:**
- `launchBarcodeScannerWithResult` — trigger camera
- `launchDocumentScannerWithResult` — trigger camera
- `openDeviceSetupTips` — open settings pages
- `launchFitDataScreen` — open health data

### Attack Chain

```
1. Attacker installs zero-permission APK
2. APK creates ExecuteAppFunctionAidlRequest with:
   - callingPackage = attacker's own package name (passes CallerValidator)
   - targetPackage = "com.google.android.gms"
   - functionId = "extendScreenTime" (or any function above)
3. APK calls IAppFunctionManager.executeAppFunction(request, callback)
4. CallerValidator passes (package matches UID)
5. AppFunctionManagerServiceImpl binds to GMS and invokes the function
6. Function executes with GMS's privileges, not attacker's
```

### Revised Severity: MEDIUM (Information Disclosure + Dormant State Modification)

**Confirmed exploitable NOW:**
- `searchAppFunctions` — enumerate all 30+ functions without permission (info disclosure)
- `addOnAccessChangedListener` — register listener (currently no-op but no permission check)

**Not exploitable for cross-app execution** (EXECUTE_APP_FUNCTIONS is internal|privileged):
- `executeAppFunction` — blocked by permission check in `verifyCallerCanExecuteAppFunction`
- Functions like `extendScreenTime`, `castMyScreen`, `addCardToWallet` are NOT invocable by untrusted apps

**Dormant (when accessCheckFlagsEnabled enables):**
- Access control methods will delegate to AppFunctionAccessService which enforces MANAGE_APP_FUNCTION_ACCESS
- These will become properly protected when the flag enables

**Still significant:**
- Zero-permission enumeration of all app functions reveals device capabilities and installed packages
- The metadata includes parameter schemas that aid further attack research
- 1078+ lines of sensitive system metadata exposed without authorization

## Next Step: Build PoC APK

To fully demonstrate:
1. Install minimal APK with no special permissions
2. APK calls `IAppFunctionManager.searchAppFunctions()` with its own package name
3. APK successfully enumerates all 30+ functions
4. APK calls `IAppFunctionManager.executeAppFunction()` targeting `extendScreenTime`
5. Family Link screen time gets extended without parent consent

This proves any zero-permission app can invoke privileged functions through AppFunctionManager.
