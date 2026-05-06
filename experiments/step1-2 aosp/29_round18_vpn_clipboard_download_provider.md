# Report 29: Round 18 — VpnManagerService, ClipboardService, DownloadProvider

**Date**: 2026-04-29  
**Scope**: VpnManagerService/Vpn.java, ClipboardService, DownloadProvider, PrintManagerService  
**Method**: 2 deep background agents  
**Previous**: Reports 01-28, ~322 variants

---

## Part A: VpnManagerService (2 findings)

### V-322: VPN Profile Store Zero-Permission Read/List/Write [HIGH]

**File**: `services/core/java/com/android/server/VpnManagerService.java` (lines 1020-1073)

**Issue**: Four Binder-exposed methods for VPN profile storage (`getFromVpnProfileStore`, `putIntoVpnProfileStore`, `removeFromVpnProfileStore`, `listFromVpnProfileStore`) have ZERO permission checks. The `list` method has no feature flag guard, so it ALWAYS works.

```java
@Override
@Nullable
public byte[] getFromVpnProfileStore(@NonNull String name) {
    return mVpnProfileStore.get(name);  // NO permission check!
}

@Override
public boolean putIntoVpnProfileStore(@NonNull String name, @NonNull byte[] blob) {
    return mVpnProfileStore.put(name, blob);  // NO permission check!
}

@Override
public boolean removeFromVpnProfileStore(@NonNull String name) {
    return mVpnProfileStore.remove(name);  // NO permission check!
}

@Override
@NonNull
public String[] listFromVpnProfileStore(@NonNull String prefix) {
    return mVpnProfileStore.list(prefix);  // NO permission check!
}
```

**Attack**:
1. Any app calls `ServiceManager.getService("vpn_management")` (accessible via `app_api_service` SELinux type)
2. Calls `IVpnManager.listFromVpnProfileStore("")` to enumerate ALL VPN profile names
3. Profile names reveal: VPN server hostnames, whether lockdown VPN is configured, platform VPN package identifiers (format: `PLATFORM_VPN{userId}_{packageName}`)
4. If `disable_legacy_keystore_get` flag is not enabled, `getFromVpnProfileStore` returns full VPN credentials
5. If `disable_legacy_keystore_put_v2` is not enabled, `putIntoVpnProfileStore` allows overwriting VPN profiles

**Disclosed Information**:
- VPN server hostnames embedded in profile names
- Lockdown VPN existence (`Credentials.LOCKDOWN_VPN` entry)
- Platform VPN app identifiers (`PLATFORM_VPN{userId}_{packageName}`)
- App exclusion list data (`VPNAPPEXCLUDED_{userId}_{packageName}`)
- Potentially full VPN credentials (certificates, PSKs) if `get` not flag-guarded

**Permission**: ZERO  
**Impact**: VPN credential disclosure + integrity (profile corruption/deletion)  
**Bounty**: $5,000-$10,000

---

### V-323: setAppExclusionList Confused Deputy — Excludes Apps from Active VPN Regardless of Package [MEDIUM]

**File**: `Vpn.java` (lines 4355-4363)

**Issue**: `setAppExclusionList(packageName, excludedApps)` stores exclusions for the specified package but `updateAppExclusionList(excludedApps)` immediately updates the CURRENTLY RUNNING VPN regardless of whether `packageName` matches the running VPN.

```java
public synchronized boolean setAppExclusionList(@NonNull String packageName,
        @NonNull List<String> excludedApps) {
    enforceNotRestrictedUser();
    if (!storeAppExclusionList(packageName, excludedApps)) return false;
    updateAppExclusionList(excludedApps);  // Updates RUNNING VPN regardless of packageName!
    return true;
}
```

**Permission**: NETWORK_SETTINGS (signature-level)  
**Bounty**: $500-$1,000

---

## Part B: ClipboardService (2 findings)

### V-324: Cross-Profile Clipboard Propagation to Private Space [MEDIUM]

**File**: `services/core/java/com/android/server/clipboard/ClipboardService.java` (lines 957-998)

**Issue**: Clipboard cross-profile propagation uses `DISALLOW_CROSS_PROFILE_COPY_PASTE` (source) and `DISALLOW_SHARE_INTO_MANAGED_PROFILE` (target). If Private Space doesn't set `DISALLOW_SHARE_INTO_MANAGED_PROFILE`, clipboard content from main profile propagates to Private Space automatically.

```java
List<UserInfo> related = getProfiles(userId, true);
for (int i = 0; i < size; i++) {
    int id = related.get(i).id;
    if (id != userId) {
        final boolean canCopyIntoProfile = !hasRestriction(
                UserManager.DISALLOW_SHARE_INTO_MANAGED_PROFILE, id);
        if (canCopyIntoProfile) {
            // Copies clip to related profile INCLUDING Private Space
        }
    }
}
```

**Impact**: Apps in Private Space can read clipboard content from main profile, violating isolation  
**Permission**: App must be installed in Private Space  
**Bounty**: $1,000-$3,000 (if exploitable on stock Pixel 10)

---

### V-325: Clipboard Listener Registration Without AppOps Check [LOW-MEDIUM]

**File**: `ClipboardService.java` (lines 744-769)

**Issue**: `addPrimaryClipChangedListener()` does NOT check `clipboardAccessAllowed` / OP_READ_CLIPBOARD. An app with clipboard access denied by user can still register a listener (though dispatch is properly gated).

**Permission**: ZERO  
**Impact**: Defense-in-depth gap, resource accumulation  
**Bounty**: $500-$1,000

---

## Part C: DownloadProvider (3 findings)

### V-326: addCompletedDownload File Ownership Hijacking — Scoped Storage Bypass [HIGH]

**File**: `packages/providers/DownloadProvider/src/com/android/providers/downloads/DownloadProvider.java` (lines 1094-1124, 873-901)

**Issue**: `addCompletedDownload` allows any app to claim ownership of files in `/storage/emulated/0/Download/` that have null `owner_package_name` in MediaStore. Files transferred via USB/MTP, adb push, or created outside MediaStore have null ownership.

```java
// checkWhetherCallingAppHasAccess (line 1148):
if (fetchedOwnerPackageName != null && packageNames != null) {
    // Only blocks if owner is non-null AND doesn't match caller
    // Files with null owner PASS this check silently!
}

// After successful insert (lines 885-886):
mediaValues.put(MediaStore.Downloads.OWNER_PACKAGE_NAME,
        Helpers.getPackageForUid(getContext(), filteredValues.getAsInteger(Constants.UID)));
// Attacker now OWNS the file in MediaStore!
```

**Attack**:
1. User transfers `tax_returns.pdf` to Downloads/ via USB cable
2. MediaStore indexes it with `owner_package_name = null`
3. Malicious app calls `DownloadManager.addCompletedDownload("x", "x", false, "application/pdf", "/storage/emulated/0/Download/tax_returns.pdf", fileSize, false)`
4. DownloadProvider: file exists in Downloads, owner is null → check passes
5. MediaStore ownership updated to attacker's package
6. URI grant (READ+WRITE) issued to attacker at `content://downloads/all_downloads/<id>`
7. Attacker reads file content; URI grant is non-revocable (per V-299)

**Permission**: INTERNET (normal, auto-granted)  
**Impact**: Read/write access to user files in Downloads/ folder, bypasses scoped storage for USB-transferred files  
**Bounty**: $3,000-$7,000

---

### V-327: getType() Cross-App Download MIME Type and Existence Oracle [MEDIUM]

**File**: `DownloadProvider.java` (lines 621-649)

**Issue**: `getType()` queries MIME type for ANY download ID without UID ownership check. `getType()` is exempt from provider permission checks by framework design.

```java
case MY_DOWNLOADS_ID:
case ALL_DOWNLOADS_ID: {
    final String id = getDownloadIdFromUri(uri);
    final SQLiteDatabase db = mOpenHelper.getReadableDatabase();
    final String mimeType = DatabaseUtils.stringForQuery(db,
            "SELECT " + Downloads.Impl.COLUMN_MIME_TYPE + " FROM " + DB_TABLE +
            " WHERE " + Downloads.Impl._ID + " = ?",
            new String[]{id});
    // NO UID ownership check! Queries ANY download by any app
```

**Attack**: Enumerate download IDs 1-100000, learn MIME types of all apps' downloads. Reveals download patterns (APKs, PDFs, images, videos).

**Permission**: ZERO  
**Bounty**: $500-$1,000

---

### V-328: call(CALL_CREATE_EXTERNAL_PUBLIC_DIR) Without Permission [LOW]

**File**: `DownloadProvider.java` (lines 681-696)

**Issue**: `call()` method's `CALL_CREATE_EXTERNAL_PUBLIC_DIR` case has NO permission check. Any app can force creation of standard directories.

**Permission**: ZERO  
**Bounty**: $100-$250

---

## Round 18 Summary

| Severity | Count | Key Findings |
|----------|-------|-------------|
| HIGH | 2 | VPN profile store zero-perm (V-322), DownloadProvider file hijacking (V-326) |
| MEDIUM | 3 | VPN exclusion list (V-323), clipboard cross-profile (V-324), getType() oracle (V-327) |
| LOW-MEDIUM | 1 | Clipboard listener (V-325) |
| LOW | 1 | Directory creation (V-328) |
| **Total** | **7** | |

**Estimated bounty this round**: $10,600 - $23,250

---

## Cumulative Project Statistics (Reports 01-29)

| Metric | Previous | This Round | Cumulative |
|--------|----------|------------|------------|
| Total variants | ~322 | +7 | **~329** |
| HIGH/CRITICAL | ~45 | +2 | **~47** |
| Bounty estimate (low) | $634.8k | +$10.6k | **$645.4k** |
| Bounty estimate (high) | $1.557M | +$23.25k | **$1.580M** |

---

## V-322 VRP Report Draft

### Title: VpnManagerService Profile Store Methods Lack Permission Checks — Zero-Permission VPN Configuration Disclosure

### Summary
`IVpnManager.listFromVpnProfileStore()`, `getFromVpnProfileStore()`, `putIntoVpnProfileStore()`, and `removeFromVpnProfileStore()` in VpnManagerService have zero permission checks. The VpnManagerService binder is accessible to third-party apps via the `vpn_management` service name (SELinux type: `app_api_service`). Any app can enumerate VPN profile names (which contain server hostnames), detect lockdown VPN configuration, and potentially extract full VPN credentials depending on legacy keystore feature flags.

### Steps to Reproduce
1. Build a zero-permission app with the following code:
```java
IBinder binder = ServiceManager.getService("vpn_management");
IVpnManager vpnManager = IVpnManager.Stub.asInterface(binder);
String[] profiles = vpnManager.listFromVpnProfileStore("");
// Returns all VPN profile names including server hostnames
```
2. Install on stock Pixel 10 with one or more VPN profiles configured
3. Run the app — observe VPN server names, lockdown status, platform VPN packages

### Impact
- Information disclosure: VPN server names, lockdown configuration
- Integrity: If put/remove not flag-guarded, profile corruption/deletion
- Privacy: Reveals user's VPN usage patterns and providers

### Severity
HIGH (Zero-permission information disclosure of security-sensitive configuration)

---

*Generated by FuzzMind/CoreBreaker Round 18 — 2026-04-29*
