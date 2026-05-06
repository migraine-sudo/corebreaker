# Round 7 Deep-Dive Audit — AccountManager, AMS, WiFi, VirtualDevice, HealthConnect

**Date:** 2026-04-29
**Scope:** 5 high-value targets with detailed source code reading
**Method:** Line-by-line source review of downloaded AOSP source files (6,778-19,483 lines each)
**Target:** Pixel 10 (frankel), Android 16, CP1A.260405.005, patch 2026-04-05

---

## Executive Summary

| Service | Lines Read | Findings | Top Severity |
|---------|-----------|----------|-------------|
| AccountManagerService | 6,778 | 3 | MED |
| ActivityManagerService (process mgmt) | 19,483 | 1 useful, 2 non-issue | LOW |
| WifiServiceImpl | 9,198 | 3 | MED |
| VirtualDeviceManager/Impl | 2,941 | 3 | MED-HIGH |
| HealthConnectServiceImpl | 3,669 | 4 | MED |
| **TOTAL** | **~42,000** | **14** | **MED-HIGH** |

### Top Priority Findings

| ID | Severity | Service | Issue |
|----|----------|---------|-------|
| VDM-1/2 (V-181) | MED-HIGH | VirtualDevice | Mirror display input injection targets physical display |
| HC-1 (V-180) | MED | HealthConnect | Read-by-ID skips enforceSelfRead (acknowledged TODO) |
| WIFI-1 (V-182) | MED | WiFi | getChannelData weaker permission than getScanResults |
| ACCT-1 (V-183) | MED | AccountManager | type=null bypasses ownership check |

---

## 1. AccountManagerService

### ACCT-1 [MED] — getAccountsByTypeForPackage type=null Ownership Bypass (V-183)
- **File:** `AccountManagerService.java`, line 4780
- **Method:** `getAccountsByTypeForPackage(null, targetPackage)`
- **Issue:** When `type == null`, the condition `(type != null && !isAccountManagedByCaller)` evaluates to false, skipping the ownership check. Authenticator app can query accounts visible to any arbitrary package.
- **Impact:** Cross-type account enumeration from authenticator perspective.

### ACCT-2 [LOW-MED] — finishSession Bundle Not Caller-Bound
- **File:** `AccountManagerService.java`, line 3844
- **Issue:** Encrypted session bundle can be used by any caller, not bound to the app that started the session. `appInfo` putAll can overwrite authenticator-set values before KEY_CALLER_UID/PID are corrected.

### ACCT-3 [MED] — getAccountsAsUserForPackage UID Reassignment
- **File:** `AccountManagerService.java`, line 4634-4638
- **Issue:** When authenticator manages the requested type, `callingUid = packageUid` is reassigned. Authenticator views accounts from target package's perspective including USER_MANAGED_NOT_VISIBLE accounts.

---

## 2. ActivityManagerService (Process Management)

### AMS-P-1 [LOW] — killBackgroundProcesses Properly Restricted
- **Verdict:** NOT exploitable. Without signature-level `KILL_ALL_BACKGROUND_PROCESSES`, can only kill own processes. Correctly implemented.

### AMS-P-3 [INFORMATIONAL] — getRunningAppProcesses Properly Mitigated
- **Verdict:** Since Android 10, returns only caller's own processes without `REAL_GET_TASKS` (signature level). Correctly implemented.

---

## 3. WifiServiceImpl

### WIFI-1 [MED] — getChannelData Weaker Permission (V-182)
- **File:** `WifiServiceImpl.java`, line 4841-4863
- **Issue:** `getScanResults()` requires location permission + location enabled. `getChannelData()` only requires `NEARBY_WIFI_DEVICES`. Returns frequency/AP-count distribution — a location fingerprint. `neverForLocation` flag bypasses location permission requirement.

### WIFI-2 [LOW] — setWifiEnabled Dialog Spam for Pre-Q Apps
- **File:** `WifiServiceImpl.java`, line 1392
- **Issue:** Pre-Q targeting apps can repeatedly trigger wifi-enable confirmation dialog. DoS by design.

### WIFI-3 [LOW-MED] — connect() NFC UID Blanket Access
- **File:** `WifiServiceImpl.java`, line 6957
- **Issue:** NFC UID has blanket `connect()` access. Acknowledged TODO(b/343881335).

---

## 4. VirtualDeviceManager

### VDM-1 [MED-HIGH] — INJECT_EVENTS Bypasses Display Ownership (V-181)
- **File:** `VirtualDeviceImpl.java`, line 1622
- **Issue:** `checkVirtualInputDeviceDisplayIdAssociation()` completely skips display ownership check when caller has `INJECT_EVENTS`. Platform-signed app can bind virtual input device to any display including physical.

### VDM-2 [MED] — Mirror Display Input Injection to Physical Display (V-181)
- **File:** `VirtualDeviceImpl.java`, lines 1430, 1629
- **Issue:** `getTargetDisplayIdForInput()` follows mirror chains to physical display. `checkVirtualInputDeviceDisplayIdAssociation` explicitly allows mirror displays (`isMirror()` passes untrusted check). App with `CREATE_VIRTUAL_DEVICE` + NEARBY_DEVICE_STREAMING CDM association can inject events to physical display.

### VDM-3 [LOW] — getVirtualDevices No Permission Check
- **File:** `VirtualDeviceManagerService.java`, line 554
- **Issue:** Any app can enumerate active virtual devices, IDs, names, policies.

---

## 5. HealthConnectManager

### HC-1 [MED] — Read-by-ID Skips enforceSelfRead (V-180)
- **File:** `HealthConnectServiceImpl.java`, lines 712-716
- **Issue:** `maybeEnforceOnlyCallingPackageDataRequested` explicitly skipped for read-by-ID path. Acknowledged TODO(b/309778116). App with only WRITE permission could read other apps' records via UUIDs obtained from change logs.

### HC-2 [LOW-MED] — getChangeLogs Reveals Other Apps' Record UUIDs
- **File:** `HealthConnectServiceImpl.java`, line 986
- **Issue:** Change logs include UUIDs of records written by other apps. Feeds into HC-1 for cross-app data access chain.

### HC-3 [INFORMATIONAL] — Background Read Error Message Leaks Package Name
- Minor bug: missing space in error message concatenation.

### HC-4 [LOW] — Rate Limiting Per-UID Not Per-Package
- Shared-UID apps share rate limit quota. Minimal practical impact.

---

## Quality Verification Update (Round 6 Findings)

Based on the verification agent's results:

| Finding | Original | Verified | Action |
|---------|----------|----------|--------|
| V-176 (CDM-1) | HIGH | **FALSE POSITIVE** | Downgraded — processor has caller checks |
| V-167 (DMS-1) | HIGH | **CONFIRMED** | No change |
| V-168 (CPA-1) | MED | **CONFIRMED** | No change |
| V-177 (AUD-2) | MED | **PARTIALLY CONFIRMED** | AUD-3 mic mute is false positive; AUD-2 volume adjust confirmed |
| V-171 (SET-1) | HIGH | **LOW** | SubSettings exported=false — needs trampoline chain |

---

## Cumulative Audit Statistics (Rounds 1-7)

- **Total services/components audited:** 47+
- **Total lines of source code reviewed:** ~150,000+
- **Total findings:** ~160+ candidates
- **Status files:** 58
- **Confirmed HIGH findings:** V-167 (DMS overrideHdrTypes), V-06 (FREEFORM CVE bypass)
- **False positives identified and corrected:** V-176, V-177 (partial), V-171 (severity downgrade)
