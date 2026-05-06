# Round 20 Deep Scan — AMS/ATMS/ActiveServices + Connectivity/Wifi/P2P + UserMgr/AppOps/Power/Settings/PermissionManager

**Date:** 2026-04-29
**Scope:** 3 parallel agent audits + direct manual audits of ContentProviderHelper, LockTaskController, LockSettingsService, ShortcutService, LauncherAppsService, SliceManagerService, DownloadProvider, TrustManagerService, AutofillManagerService

---

## Executive Summary

| Module | Findings | Estimated Bounty Range |
|--------|----------|----------------------|
| AMS/ATMS/ActiveServices (AM-*, AT-*, AS-*) | 14 | $19,100 - $37,700 |
| Connectivity/Wifi/WifiP2p (CS-*, W-*, WP-*) | 16 | $7,750 - $17,250 |
| UserMgr/AppOps/Power/Settings/PermMgr (UM-*, AO-*, PM-*, SP-*, PR-*) | 14 | $15,250 - $33,750 |
| Direct audits (clean) | 0 | $0 |
| **TOTAL** | **44** | **$42,100 - $88,700** |

---

## Module 1: AMS/ATMS/ActiveServices (14 findings)

### AT-1 [HIGH] — startActivityAsCaller Confused Deputy + BAL Exemption ($5,000-$10,000)
- **File:** ActivityTaskManagerService.java:1637-1740
- Unconditionally sets `setAllowBalExemptionForSystemProcess(true)` and `setFilterCallingUid(0)` when triggered from resolver
- Combined with `ignoreTargetSecurity=true` path allows bypassing target exported/permission checks

### AM-1 [HIGH] — moveTaskToFront BAL Check Effectively Bypassed ($3,000-$5,000)
- **File:** ActivityTaskManagerService.java:2256-2284
- BAL blocking condition requires `!isBackgroundActivityStartsEnabled()` which is always false in production
- Any app with REORDER_TASKS (normal permission) can bring any task to foreground

### AS-1 [MEDIUM] — FGS BFSL Bypass via Binding Client Privilege Chain ($3,000-$5,000)
- **File:** ActiveServices.java:8240-8360
- Background app can leverage a foreground app's binding to bypass BFSL restrictions for startForeground()

### AM-2 [MEDIUM] — sendIntentSender User Redirect Creates Unmanaged PendingIntentRecord ($2,000-$4,000)
- **File:** ActivityManagerService.java:5564-5644
- Visible background users can redirect PendingIntents to their own user space without INTERACT_ACROSS_USERS

### AT-2 [MEDIUM] — startActivityFromGameSession callingPackage from Untrusted Intent ($2,000-$3,000)
- **File:** ActivityTaskManagerService.java:1847-1886
- Method validates `callingPackage` parameter but uses `intent.getPackage()` for ActivityStarter — mismatch

### AS-3 [MEDIUM] — peekService Returns IBinder Without Binding Lifecycle ($1,000-$3,000)
- **File:** ActiveServices.java:1750-1772
- Exported service's IBinder obtained without going through onBind() authorization

### AM-3 [MEDIUM] — startInstrumentation Signature Bypass on Debug Builds ($1,000-$2,000)
- Root UID on IS_DEBUGGABLE builds can instrument any package without signature match

### AM-6 [MEDIUM] — killBackgroundProcesses via Normal Permission ($500-$1,000)
- KILL_BACKGROUND_PROCESSES is normal-level — apps can kill background processes

### AS-2 [LOW] — SHORT_SERVICE FGS Timeout Indefinitely Extendable ($500-$1,500)
- Repeated startForeground() with SHORT_SERVICE extends timeout, circumventing time limit

### AT-3 [LOW] — getTaskDescriptionIcon Incomplete Path Traversal ($500-$1,000)
### AM-7 [LOW] — Service Lifecycle Methods Missing Caller Ownership ($500-$1,000)
### AT-4 [LOW] — startActivityIntentSender Global App Switch Manipulation ($500-$1,000)
### AM-4 [LOW] — getProcessLimit Info Leak Without Permission ($100-$200)
### AM-5 [INFO] — clearApplicationUserData Resets Own Permissions (by design)

---

## Module 2: Connectivity/Wifi/WifiP2p (16 findings)

### WP-1 [HIGH] — EXTRA_PARAM_KEY_INTERNAL_MESSAGE Permission Bypass ($2,000-$5,000)
- **File:** WifiP2pServiceImpl.java:6897-6913
- Client-controlled Bundle flag `EXTRA_PARAM_KEY_INTERNAL_MESSAGE=true` bypasses `checkNearbyDevicesPermission()`
- Affects DISCOVER_PEERS, CONNECT, CREATE_GROUP, REQUEST_DEVICE_INFO, REQUEST_GROUP_INFO, REQUEST_PEERS, SET_VENDOR_ELEMENTS

### W-2 [MEDIUM] — Bulk WiFi Password Disclosure via getPrivilegedConfiguredNetworks ($1,000-$2,000)
- **File:** WifiServiceImpl.java:3557-3598
- Returns all WiFi passwords to callers with READ_WIFI_CREDENTIAL (no user consent)

### WP-3 [MEDIUM] — P2P Connection Info Leaks Group Owner IP Without Permission ($500-$1,000)
- REQUEST_CONNECTION_INFO returns WifiP2pInfo (group owner IP) without location/nearby check

### WP-5 [LOW-MED] — P2P Group Passphrase Not Redacted ($500-$1,000)
- REQUEST_GROUP_INFO returns passphrase without credential-specific permission check

### CS-1 [MEDIUM] — CaptivePortal appResponse Unprivileged Network Disconnect ($500-$1,000)
- APP_RETURN_UNWANTED path has no permission check — DoS via intercepted CaptivePortal Binder

### CS-2 [MEDIUM] — Cross-UID NetworkInfo Disclosure ($500-$1,000)
- getNetworkInfoForUid accepts arbitrary uid with only ACCESS_NETWORK_STATE

### W-1 [MEDIUM] — SoftAP Passphrase Exposure via CONFIG_OVERRIDE ($500-$1,000)
### W-3 [MEDIUM] — Current WiFi Password Leak ($500-$1,000)
### W-4 [LOW] — Pre-Q Apps Force WiFi Disconnect ($250-$500)
### W-5 [LOW] — DUMP Permission Enables Show-Key Logging ($250-$500)
### W-6 [LOW] — Last Hotspot Passphrase Queryable ($250-$500)
### CS-3 [LOW] — Unprivileged Network Revalidation Forcing ($250-$500)
### WP-2 [LOW] — P2P NetworkInfo Without Permission ($100-$250)
### WP-6 [LOW] — STOP_DISCOVERY No Permission Check ($100-$250)
### CS-4 [INFO] — Shell Firewall Manipulation ($0-$250)
### WP-4 [INFO] — P2P State Queries No Permission ($0-$100)

---

## Module 3: UserMgr/AppOps/Power/Settings/PermissionManager (14 findings)

### PR-3 [HIGH] — Inverted UID Check in updatePermissionFlagsForAllApps ($5,000-$10,000)
- **File:** PermissionManagerServiceImpl.java:902-906
- Conditional logic inverted: non-system callers get UNMODIFIED flagMask (including FLAG_PERMISSION_SYSTEM_FIXED)
- Non-system callers with GRANT_RUNTIME_PERMISSIONS can clear SYSTEM_FIXED flag from ALL apps

### SP-1 [HIGH] — Secure Settings Reset Hardcodes USER_SYSTEM ($3,000-$7,000)
- **File:** SettingsProvider.java:1869-1871
- `MUTATION_OPERATION_RESET` uses `UserHandle.USER_SYSTEM` instead of `owningUserId`
- Privileged app in user 10 resets user 0's secure settings

### PR-2 [MEDIUM] — Non-System Can Clear FLAG_PERMISSION_APPLY_RESTRICTION ($2,000-$5,000)
- flagMask not stripped of APPLY_RESTRICTION for non-system callers, only flagValues is

### AO-1 [MEDIUM] — Profile Owner UID Check Allows Shared-UID Apps to Modify AppOps ($1,000-$3,000)
- enforceManageAppOpsModes checks UID match only, not component identity

### SP-4 [MEDIUM] — Cross-User Ringtone Cache Write with INTERACT_ACROSS_USERS ($1,000-$2,000)
### SP-2 [MEDIUM] — Legacy Apps Write Non-Public System Settings ($500-$1,500)
### AO-2 [MEDIUM] — checkOperation Leaks Other Apps' AppOp Modes ($500-$1,500)
### UM-3 [MEDIUM] — XOR Toggle for Admin Flag (TOCTOU risk) ($500-$1,000)
### PM-3 [LOW] — SYSTEM_WAKELOCK Attribution Evasion ($500-$1,000)
### UM-1 [LOW] — getUserSerialNumber/getUserHandle No Permission Check ($500-$1,000)
### PM-2 [LOW] — Wake Lock Tag Log Injection ($250-$500)
### UM-4 [LOW] — getUserCreationTime Leaks Profile Creation Timestamps ($250-$500)
### PR-1 [LOW] — Dynamic Permissions Can Impersonate System Permissions ($250-$500)
### UM-2 [INFO] — hasUserRestrictionOnAnyUser Currently Mitigated ($0-$250)

---

## Module 4: Direct Audit Results (Clean)

| Service | Lines | Result |
|---------|-------|--------|
| LockSettingsService | 3,879 | Well-defended. All APIs require ACCESS_KEYGUARD_SECURE_STORAGE. Escrow tokens properly gated. |
| LockTaskController | 1,112 | Properly validates callingUid for stop/start. Auth-level logic correct. |
| ContentProviderHelper | 2,028 | Thorough permission checking via checkContentProviderPermission(). setStrict() on query builders. |
| ShortcutService | 5,499 | verifyCaller checks package-UID match and userId. verifyShortcutInfoPackage validates ownership. |
| LauncherAppsService | 2,928 | canAccessProfile properly validates cross-user. startActivityAsUser validates CATEGORY_LAUNCHER + exported. |
| SliceManagerService | 725 | enforceAccess + enforceCrossUser + verifyCaller. Properly gated. |
| DownloadProvider | ~1,800 | setStrict/setStrictColumns/setStrictGrammar. isFilenameValid validation. |
| TrustManagerService | 2,551 | enforceReportPermission (ACCESS_KEYGUARD_SECURE_STORAGE). handleIncomingUser for cross-user. |
| AutofillManagerService | 2,280 | userId == UserHandle.getUserId(getCallingUid()) assertion. MANAGE_AUTO_FILL for management APIs. |

---

## Top 10 Highest-Value Findings (This Round)

| Rank | ID | Finding | Est. Max |
|------|-----|---------|----------|
| 1 | AT-1 | startActivityAsCaller confused deputy + BAL exemption | $10,000 |
| 2 | PR-3 | Inverted UID check — non-system clears SYSTEM_FIXED | $10,000 |
| 3 | SP-1 | Secure settings reset targets wrong user | $7,000 |
| 4 | AM-1 | moveTaskToFront BAL check ineffective | $5,000 |
| 5 | AS-1 | FGS BFSL bypass via binding chain | $5,000 |
| 6 | WP-1 | P2P INTERNAL_MESSAGE permission bypass | $5,000 |
| 7 | PR-2 | APPLY_RESTRICTION flag clearable by non-system | $5,000 |
| 8 | AM-2 | PendingIntent user redirect | $4,000 |
| 9 | AT-2 | Game session callingPackage mismatch | $3,000 |
| 10 | AS-3 | peekService bypasses onBind() lifecycle | $3,000 |

---

## Cumulative Project Status

| Metric | Before Round 20 | After Round 20 |
|--------|----------------|----------------|
| Reports | 01-30 | 01-31 |
| Total variants | 203 | **247** |
| New findings this round | — | 44 |
| Estimated bounty range | $357k-$849k+ | **$399k-$938k+** |
| Modules audited | ~27 | **~36** |
| Services marked clean | 9 | **18** |

---

## Methodology

- **3 parallel background agents** for large codebases (AMS/ATMS/ActiveServices, Connectivity/Wifi/P2P, UserMgr/AppOps/Power/Settings/PermissionManager)
- **Direct manual audit** of 9 additional services (LockSettingsService, LockTaskController, ContentProviderHelper, ShortcutService, LauncherAppsService, SliceManagerService, DownloadProvider, TrustManagerService, AutofillManagerService)
- Focus: BAL bypasses, cross-user access, permission flag manipulation, FGS restriction bypass, P2P permission bypass, PendingIntent abuse
