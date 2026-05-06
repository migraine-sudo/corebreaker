# Round 4 Deep Scan — Framework/System Service Comprehensive Audit

**Date:** 2026-04-29
**Scope:** 12 previously uncovered AOSP modules (Bluetooth, Telephony/SMS/MMS, Storage/MediaProvider, PMS/Bundle, NMS, DPMS, IME, JobScheduler, NetworkPolicy, VPN, Display, Dream) + direct audit of 7 system services (AlarmManager, VibratorManager, AccountManager, WallpaperManager, Clipboard, UriGrants, MediaProjection, ContentService, Accessibility)

---

## Executive Summary

| Module | Findings | Estimated Bounty Range |
|--------|----------|----------------------|
| Bluetooth (B-*) | 11 | $18,000 - $45,000 |
| Telephony/SMS/MMS (T-*) | 15 | $11,800 - $28,500 |
| Storage/MediaProvider (S-*) | 10 | $6,800 - $14,500 |
| PMS/Installer/Bundle (P-*) | 10 | $49,500 - $98,000 |
| NMS (N-*) | 5 | $3,500 - $9,500 |
| DPMS (D-*) | 5 | $7,200 - $12,500 |
| IME (I-*) | 4 | $1,800 - $5,300 |
| JobScheduler/NetworkPolicy/VPN/Display/Dream | 12 | $5,500 - $16,000 |
| Direct audits (clean) | 0 | $0 |
| **TOTAL** | **72** | **$104,100 - $229,300** |

---

## Module 1: Bluetooth (11 findings)

### B-9 [HIGH] — PBAP/MAP Permission Grant via Spoofed Intent ($5,000-$10,000)
- **File:** BluetoothPbapService.java / BluetoothMapService.java
- Any app with BLUETOOTH_CONNECT can send spoofed `ACTION_CONNECTION_ACCESS_REPLY` to grant remote device phonebook/message access

### B-5 [MEDIUM-HIGH] — OPP File Acceptance Bypass ($3,000-$5,000)
- **File:** BluetoothOppReceiver.java
- Unprotected `ACTION_ACCEPT` intent allows accepting incoming OPP file transfers

### B-1 [MEDIUM-HIGH] — Exported BluetoothOppReceiver ($2,000-$5,000)
- Triggers OPP transfer without device picker interaction

### B-2 through B-11 — Additional Bluetooth findings including service state manipulation, GATT operation injection, adapter state changes, PAN/HID profile issues. Combined: $8,000-$25,000

---

## Module 2: Telephony/SMS/MMS (15 findings)

### T-10 [MEDIUM-HIGH] — Raw SMS Table Injection for SMS Spoofing ($2,000-$5,000)
- **File:** SmsProvider.java:261,685
- `content://sms/raw` accessible without default SMS app check; allows injecting crafted PDUs

### T-2/T-3/T-4 [MEDIUM] — SQL Injection Cluster ($3,000-$9,000)
- **File:** SmsProvider.java:209,218,290 / MmsProvider.java:170,186,240 / TelephonyProvider.java:4983
- Unparameterized URI path segments concatenated into SQL WHERE clauses

### T-6/T-7 [MEDIUM] — Shell Command Permission Gaps ($2,000-$4,000)
- **File:** TelephonyShellCommand.java:1280-1366, 943-976
- Barring info injection and data connectivity toggle without shell UID check

### T-9 [MEDIUM] — MMS Part File Race (0666 permissions) ($1,000-$2,000)
- **File:** MmsProvider.java:614-636
- World-readable/writable window during file creation

### T-1, T-5, T-8, T-11-T-15 — Debug flag, broadcast leaks, carrier privilege enumeration, etc. Combined: $3,800-$8,500

---

## Module 3: Storage/MediaProvider (10 findings)

### S-6 [MEDIUM] — Cross-User Media Access via Stale Clone Pair ($1,000-$3,000)
- Pre-S upgraded devices: `isAppCloneUserPair` cache stale, enables cross-user media queries

### S-12 [MEDIUM] — MediaProvider Picker FUSE Path Injection ($1,000-$3,000)
- Crafted authority in `handlePickerFileOpen` bypasses scoped storage

### S-7 [MEDIUM] — Work Profile User Silently Rewritten ($1,000-$2,000)
- `LocalCallingIdentity.fromBinder` rewrites work profile to owner user

### S-1 through S-14 — DownloadProvider bypass, thumbnail leaks, FUSE mount manipulation. Combined: $3,800-$6,500

---

## Module 4: PMS/Installer/Bundle (10 findings) ⭐ HIGHEST VALUE

### P-4 [MEDIUM] — Self-Changing Bundle via Length Mismatch ($15,000-$30,000)
- **File:** Parcel.java:4611-4620
- `readValue` length-prefix mismatch only logs `Slog.wtfStack()`, does NOT throw
- Foundation for self-changing bundle attacks (CVE-2017-13288 family)
- Requires finding current Parcelable mismatch gadget for maximum payout

### P-1 [HIGH] — parseUri() Unsanitized extendedLaunchFlags ($10,000-$15,000)
- **File:** Intent.java:8293-8294
- `extendedLaunchFlags=` field parsed with NO sanitization (unlike `launchFlags` which applies IMMUTABLE_FLAGS)
- Allows setting security-critical extended flags: MISSING_CREATOR_TOKEN, NESTED_INTENT_KEYS_COLLECTED

### P-2 [MEDIUM-HIGH] — fillIn() Unconditional mExtendedFlags OR ($7,000-$12,000)
- **File:** Intent.java:11685
- `mExtendedFlags |= other.mExtendedFlags` — no masking, no IMMUTABLE equivalent
- PendingIntent.send() allows attacker to ADD any extended flag

### P-3 [MEDIUM] — LazyValue Not Handled in deepCopyValue() ($5,000-$10,000)
- **File:** BaseBundle.java:653-682
- Shared mutable state between bundles via uncopied LazyValue references

### P-5 [LOW-MEDIUM] — Deserialization Before Type Check ($3,000-$7,000)
- **File:** Parcel.java:5386-5395
- `readSerializableInternal` when loader==null: type check AFTER `readObject()`

### P-6 through P-10 — Installer name spoofing, mOriginalIntent injection, emergency install bypass, fillIn exception swallowing, verification agent scope. Combined: $9,500-$19,000

---

## Module 5: NotificationManagerService (5 findings)

### N-2 [MEDIUM-HIGH] — Cross-User URI Grant via Embedded User ID ($1,000-$3,000)
- **File:** NMS:10716-10733
- Content URI with embedded user ID causes cross-user permission grant

### N-5 [LOW-MEDIUM] — Privileged Listener Sound URI → Arbitrary Content URI Access ($1,000-$3,000)
- Channel sound URI update converts NLS access to arbitrary URI read

### N-1, N-3, N-4 — Auto-group PendingIntent, undefused Bundle, cross-profile listener leak. Combined: $1,500-$3,500

---

## Module 6: DevicePolicyManagerService (5 findings) ⭐ CRITICAL

### D-1/D-5 [CRITICAL] — STOPSHIP: bindDeviceAdminServiceAsUser Non-Exported Bypass ($3,000-$5,000)
- **File:** DPMS:18544-18595, 19139-19140
- `STOPSHIP(b/37624960)` comment: `exported` check was meant to be removed before release
- Non-exported services exempt from BIND_DEVICE_ADMIN permission requirement
- Device owner can bind to ANY non-exported service in admin package across users

### D-3 [MEDIUM] — Bugreport URI Grant with SHELL_UID ($500-$1,000)
- Uses Process.SHELL_UID for URI permission check — overly broad grant

### D-2, D-4 — UID disclosure in key alias broadcast, delegate restriction scope. Combined: $700-$1,500

---

## Module 7: InputMethodManagerService (4 findings)

### I-2 [MEDIUM] — Missing Cross-User Check in Stylus Handwriting Delegation ($1,000-$3,000)
- **File:** IMMS:3364-3383
- `prepareStylusHandwritingDelegation` skips `INTERACT_ACROSS_USERS_FULL` check

### I-1 [MEDIUM] — Self-Reported Display ID Trusted ($500-$1,500)
- Concurrent multi-user: fabricated display ID used for user resolution

### I-3, I-4 — IME picker display validation, stale perceptibility value. Combined: $300-$800

---

## Module 8: Job/Network/VPN/Display/Dream (12 findings)

### DR-1 [MEDIUM] — testDream Skips validateDream → Arbitrary Service Binding ($1,000-$3,000)
- **File:** DreamManagerService.java:1113
- `WRITE_DREAM_STATE` (normal permission) → bind to ANY service as system

### DR-2 [MEDIUM] — registerDreamOverlayService Hijack ($1,000-$3,000)
- **File:** DreamManagerService.java:1041
- Any app with `WRITE_DREAM_STATE` registers malicious overlay for all dreams

### NP-2 [MEDIUM] — Subscription Plan Owner via System Property ($1,000-$3,000)
- `NETWORK_SETTINGS` app can claim ownership of any subscription's plan

### DM-1 [MEDIUM] — isUidPresentOnDisplay No Permission Check ($500-$1,500)
- **File:** DisplayManagerService.java:4502
- Any app can enumerate UIDs present on any display

### DM-2 [MEDIUM] — overrideHdrTypes No Permission Check ($500-$1,000)
- Any app can override HDR types on any display

### NP-3, NP-1, DM-3, DR-3, V-1, NP-4 — SomeArgs race, fake plan property, Wifi display disconnect, dream token leak, VPN config scope, network policy subscriber leak. Combined: $1,500-$4,500

---

## Direct Audit Results (Clean — No Significant Findings)

| Service | Lines | Result |
|---------|-------|--------|
| AlarmManagerService | 5,592 | Well-protected. FLAG_IDLE_UNTIL stripped for non-SYSTEM_UID |
| VibratorManagerService | 3,008 | Hardened. Bypass flags properly stripped |
| AccountManagerService | 6,778 | Minor: `decryptedBundle.putAll(appInfo)` — but UID/PID overwritten after |
| WallpaperManagerService | 4,190 | Proper SET_WALLPAPER/READ_WALLPAPER_INTERNAL checks |
| ClipboardService | 1,634 | AppOps + virtual device isolation + focus checks |
| UriGrantsManagerService | 1,870 | Thorough 3-phase permission validation on grants |
| MediaProjectionManagerService | 1,632 | @EnforcePermission(MANAGE_MEDIA_PROJECTION) on all methods |
| ContentService | 1,983 | Bundle.setDefusable on all extras, proper account/authority checks |
| AccessibilityManagerService | 6,808 | resolveCallingUserIdEnforcingPermissions properly validates cross-user |

---

## Top 10 Highest-Value Findings (by estimated bounty)

| Rank | ID | Finding | Est. Max |
|------|-----|---------|----------|
| 1 | P-4 | Self-changing bundle (wtfStack not throw) | $30,000 |
| 2 | P-1 | parseUri() unsanitized extendedLaunchFlags | $15,000 |
| 3 | P-2 | fillIn() unconditional mExtendedFlags OR | $12,000 |
| 4 | B-9 | PBAP/MAP spoofed permission grant | $10,000 |
| 5 | P-3 | LazyValue shared mutable state | $10,000 |
| 6 | P-5 | Post-deserialization type check | $7,000 |
| 7 | B-5 | OPP acceptance bypass | $5,000 |
| 8 | D-1/D-5 | STOPSHIP: non-exported service binding | $5,000 |
| 9 | T-10 | Raw SMS table injection | $5,000 |
| 10 | B-1 | Exported BluetoothOppReceiver | $5,000 |

---

## Cumulative Project Status

| Metric | Before Round 4 | After Round 4 |
|--------|---------------|---------------|
| Reports | 01-12 | 01-13 |
| Total variants | 131 | **203** |
| New findings this round | — | 72 |
| Estimated bounty range | $253k-$620k+ | **$357k-$849k+** |
| Modules audited | ~15 | **~27** |
| Services marked clean | — | 9 |

---

## Methodology

- **4 parallel background agents** for large codebases (Bluetooth, Telephony, Storage, PMS/Bundle, NMS/DPMS/IME, Job/Network/VPN/Display/Dream)
- **Direct manual audit** for 9 smaller/medium services
- Focus: permission bypass, cross-user access, intent/bundle injection, serialization, URI grant escalation, exported component abuse
- All findings mapped to Google VRP Android bounty categories
