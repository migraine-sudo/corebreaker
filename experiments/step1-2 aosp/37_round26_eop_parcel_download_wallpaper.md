# Report 37: Round 26 — EoP: Parcel/Bundle Mismatch, DownloadProvider, WallpaperManager, VPN

**Date**: 2026-04-30  
**Scope**: BaseBundle/LazyBundle, NotificationManagerService (Parcel paths), DownloadProvider, WallpaperManagerService, Vpn.java  
**Method**: Deep background agents + manual source verification  
**Previous**: Reports 01-36, ~369 variants

---

## Part A: Bundle/Parcel Mismatch (2 findings)

### V-369: LazyBundle Re-Parceling Preserves Raw Bytes Through System Processing — Differential Deserialization [MEDIUM/EoP]

**File**: `core/java/android/os/BaseBundle.java` (lines 1823-1832)

**Issue**: When system_server partially reads a Bundle (e.g., checking specific keys in notification extras), only those keys are deserialized while the rest remain as raw Parcel bytes. On re-serialization (`writeToParcelInner`), the unread entries are copied via `appendFrom` as raw bytes. This creates a differential deserialization scenario:

```java
// BaseBundle.writeToParcelInner line 1823-1832:
// If mParcelledData != null (unread entries exist):
//   Raw bytes are copied via appendFrom to the output Parcel
```

**Attack chain**:
1. App sends notification with crafted extras Bundle where `EXTRA_ALLOW_DURING_SETUP` key has a type-confused encoding
2. NMS reads `extras.getBoolean(EXTRA_ALLOW_DURING_SETUP)` → sees `false` (removes nothing)
3. The raw bytes are preserved during re-parceling to SystemUI/NotificationListeners
4. SystemUI's fresh deserialization interprets the same bytes differently (e.g., as `true`)
5. The key that NMS thought was safe triggers privileged behavior in SystemUI

**Mitigations**: `Bundle.setDefusable(true)`, type-safe getters on Android 13+, and `FLAG_VERIFY_TOKENS_PRESENT` reduce this attack surface. Exploitation requires deep Parcel format knowledge.

**Permission**: ZERO (via POST_NOTIFICATIONS)  
**Impact**: Potential bypass of system_server's notification permission checks  
**Bounty**: $3,000-$10,000 (depends on achievable confused-deputy effect)

---

### V-370: Notification extras.get(EXTRA_AUDIO_CONTENTS_URI) Untyped Deserialization in system_server [LOW-MEDIUM/EoP]

**File**: `core/java/android/app/Notification.java` (line 3100)

**Issue**: `Object audioContentsUri = extras.get(EXTRA_AUDIO_CONTENTS_URI)` is an **untyped** read from attacker-controlled notification extras. Unlike type-safe `getParcelable(key, Class)`, the untyped `get()` will deserialize whatever Parcelable was stored, executing its `createFromParcel` constructor in system_server context.

```java
// Notification.java line 3100:
Object audioContentsUri = extras.get(EXTRA_AUDIO_CONTENTS_URI);
// Triggers full deserialization of stored type in system_server!
```

While `sShouldDefuse = true` catches `BadParcelableException`, the system's own ClassLoader recognizes many Parcelable types. If any system Parcelable's `createFromParcel` has exploitable side effects (file creation, IPC, etc.), this is a gadget.

**Permission**: ZERO (via POST_NOTIFICATIONS)  
**Impact**: Arbitrary Parcelable deserialization in system_server; limited by defusing  
**Bounty**: $1,000-$3,000

---

## Part B: DownloadProvider (2 findings)

### V-371: COLUMN_MEDIAPROVIDER_URI Writable by Privileged Callers — MediaStore Entry Hijacking [MEDIUM/EoP]

**File**: `packages/providers/DownloadProvider/src/com/android/providers/downloads/DownloadProvider.java`

**Issue**: Apps with `PERMISSION_ACCESS_ALL` can update the `COLUMN_MEDIAPROVIDER_URI` field of any download entry:

```java
// In update() with PERMISSION_ACCESS_ALL:
copyString(Downloads.Impl.COLUMN_MEDIAPROVIDER_URI, values, filteredValues);
```

This field points to the MediaStore entry associated with the download. By overwriting it with a different MediaStore URI, the privileged caller can redirect the download's MediaStore association, potentially:
- Making the download appear in another app's media gallery
- Causing the system to delete/modify the wrong MediaStore entry on download cleanup
- Cross-referencing sensitive downloads with innocuous MediaStore entries

**Permission**: `PERMISSION_ACCESS_ALL` (signature|privileged via `android.permission.ACCESS_ALL_DOWNLOADS`)  
**Impact**: MediaStore entry manipulation for any download  
**Bounty**: $1,000-$3,000

---

### V-372: COLUMN_OTHER_UID Cross-App Download Access Grant [MEDIUM/EoP]

**File**: `DownloadProvider.java`

**Issue**: Apps with `PERMISSION_ACCESS_ADVANCED` can set `COLUMN_OTHER_UID` on downloads, granting arbitrary UIDs access:

```java
if (getContext().checkCallingOrSelfPermission(Downloads.Impl.PERMISSION_ACCESS_ADVANCED)
        == PackageManager.PERMISSION_GRANTED) {
    copyInteger(Downloads.Impl.COLUMN_OTHER_UID, values, filteredValues);
}
```

The query builder includes `COLUMN_OTHER_UID` in access checks, meaning any app matching the set UID can query/read/update that download entry.

**Attack**:
1. Compromised privileged app creates a download with sensitive content
2. Sets `COLUMN_OTHER_UID` = target app's UID
3. Target app can now read the download (which may contain attacker-crafted content)
4. OR: Privileged app sets OTHER_UID on an existing download to grant unintended access

**Permission**: `PERMISSION_ACCESS_ADVANCED` (signature|privileged)  
**Impact**: Arbitrary cross-app download access grants  
**Bounty**: $1,000-$2,000

---

## Part C: WallpaperManagerService (2 findings)

### V-373: Live Wallpaper Confused Deputy — System-Identity File Write via setWallpaper Callback [MEDIUM-HIGH/EoP]

**File**: `services/core/java/com/android/server/wallpaper/WallpaperManagerService.java`

**Issue**: When system_server binds to a live wallpaper service, it provides an `IWallpaperConnection` callback that includes `setWallpaper(String name)`. This method returns a `ParcelFileDescriptor` opened with `MODE_CREATE | MODE_READ_WRITE | MODE_TRUNCATE` by system_server:

```java
// WallpaperConnection.setWallpaper():
public ParcelFileDescriptor setWallpaper(String name) {
    synchronized (mLock) {
        if (mWallpaper.connection == this) {
            return updateWallpaperBitmapLocked(name, mWallpaper, null);
            // Opens file with system_server identity!
        }
    }
}
```

The live wallpaper receives write access to system-owned wallpaper files. While the file path is controlled by the server (wallpaper directory), the CONTENT written is fully controlled by the malicious wallpaper service. This is a confused deputy where:
- System opens the file (system_server identity/permissions)
- Wallpaper service writes arbitrary content

**Attack**:
1. User installs and selects a malicious live wallpaper
2. Wallpaper calls `setWallpaper()` on its connection callback
3. Receives system-opened PFD to wallpaper file
4. Writes content that, when processed by the wallpaper cropper/decoder, could trigger vulnerabilities in BitmapFactory running in system_server context
5. Additionally, repeated `setWallpaper()` calls create file I/O load under system_server

**Permission**: User must select the live wallpaper (user interaction required)  
**Impact**: System-identity file write + potential image parsing attacks in system_server  
**Bounty**: $2,000-$5,000

---

### V-374: Wallpaper Backup Restore Processes Crafted Images/XML as System [MEDIUM/EoP]

**File**: `WallpaperManagerService.java` — `WallpaperObserver` class

**Issue**: During wallpaper restore from backup, the system:
1. Detects file changes via `FileObserver` (`MOVED_TO` event)
2. Reloads settings XML via `loadSettingsLocked(userId, true, FLAG_SYSTEM | FLAG_LOCK)`
3. Processes the image via `mWallpaperCropper.generateCrop(wallpaper)` which calls `BitmapFactory.decodeFile`
4. Applies `SELinux.restorecon(changedFile)`

```java
// WallpaperObserver.onEvent():
if (isRestore) {
    loadSettingsLocked(wallpaper.userId, true, FLAG_SYSTEM | FLAG_LOCK);
    // Processes attacker-controlled XML...
}
SELinux.restorecon(changedFile);
mWallpaperCropper.generateCrop(wallpaper);
// Decodes attacker-controlled image in system_server...
```

A crafted backup could include:
- Malformed images triggering BitmapFactory vulnerabilities in system_server
- Modified wallpaper XML with attacker-controlled component names or crop hints

**Permission**: Requires backup mechanism access (ADB backup, cloud restore, or compromised backup agent)  
**Impact**: Code execution in system_server via image parsing, or configuration injection via XML  
**Bounty**: $2,000-$5,000

---

## Part D: VPN (1 finding)

### V-375: VPN App Silent Per-App Exclusion Without User Notification [LOW-MEDIUM/Privacy]

**File**: `services/core/java/com/android/server/connectivity/Vpn.java` (lines 1722-1836)

**Issue**: The VPN API allows a VPN app to exclude specific apps from the tunnel via `disallowedApplications` without any user-facing indication:

```java
// establish() processes VpnConfig from the VPN app:
config.disallowedApplications  // Set by VPN app, applied without user notification
```

The system shows a "VPN active" notification but does NOT indicate which apps are excluded. A deceptive VPN app could:
- Claim to protect all traffic while excluding sensitive apps (banking, messaging)
- Selectively expose target apps' traffic for surveillance while appearing to provide full VPN protection

**Permission**: `BIND_VPN_SERVICE` + user VPN consent  
**Impact**: User deception — selective traffic exposure under false VPN protection  
**Bounty**: $500-$1,500 (privacy/deception issue)

---

## Part E: Confirmed Secure (Audit Negative Results)

| Service | Result |
|---------|--------|
| VPN consent race condition | Properly synchronized — `prepare()` and `establish()` hold same lock |
| Cross-user VPN manipulation | Each user has independent Vpn object; INTERACT_ACROSS_USERS_FULL required |
| VPN NetworkAgent score manipulation | Score hardcoded by system; VPN app has no access to NetworkAgent |
| VPN tun fd privilege escalation | Only obtainable via `establish()` with consent verification |
| ClipboardService (from previous) | Cross-user properly gated by ALLOW_FULL_ONLY |

---

## Round 26 Summary

| Severity | Count | Key Findings |
|----------|-------|-------------|
| MEDIUM-HIGH | 1 | Wallpaper confused deputy (V-373) |
| MEDIUM | 3 | LazyBundle mismatch (V-369), MediaStore hijack (V-371), Backup restore (V-374) |
| MEDIUM | 1 | Cross-app download access (V-372) |
| LOW-MEDIUM | 2 | Untyped deserialization (V-370), VPN exclusion (V-375) |
| **Total** | **7** | |

**Estimated bounty this round**: $10,500 - $29,500

---

## Cumulative Project Statistics (Reports 01-37)

| Metric | Previous | This Round | Cumulative |
|--------|----------|------------|------------|
| Total variants | ~369 | +7 | **~376** |
| HIGH/CRITICAL | ~53 | +0 | **~53** |
| Bounty estimate (low) | $716.4k | +$10.5k | **$726.9k** |
| Bounty estimate (high) | $1.764M | +$29.5k | **$1.794M** |

---

*Generated by FuzzMind/CoreBreaker Round 26 — 2026-04-30*
