# V-466: PackageArchiver Intent Redirect — Assessment

**Date**: 2026-05-01
**Target**: Pixel 10, Android 16 (CP1A.260405.005, 2026-04-05 SPL)
**Class**: `com.android.server.pm.PackageArchiver$UnarchiveIntentSender`
**Verdict**: NOT EXPLOITABLE (design weakness, insufficient for VRP)

---

## Summary

`UnarchiveIntentSender.send()` extracts a nested Intent from a result and calls `Context.startActivityAsUser()` from system_server context. However, multiple mitigations prevent exploitation.

## Flow Traced

```
1. Launcher taps archived app
2. → requestUnarchiveOnActivityStart() creates UnarchiveIntentSender (wraps in IntentSender)
3. → requestUnarchive() sends ACTION_UNARCHIVE_PACKAGE broadcast to installer
4. → Installer downloads/installs APK, calls reportUnarchivalStatus(status, ...)
5. → PackageInstallerSession.reportUnarchivalStatus() validates caller is session owner
6. → lambda$reportUnarchivalStatus$14 calls PackageArchiver.notifyUnarchivalListener()
7. → notifyUnarchivalListener() builds result Intent with:
   - UNARCHIVE_STATUS (from installer, int)
   - If error: android.intent.extra.INTENT = createErrorDialogIntent() result
   - android.intent.extra.USER = UserHandle.of(userId)
8. → Sends result via IntentSender.sendIntent() to each launcher IntentSender
9. → UnarchiveIntentSender.send() triggers:
   - Checks UNARCHIVE_STATUS != 0
   - Extracts android.intent.extra.INTENT (the error dialog Intent)
   - Extracts android.intent.extra.USER (UserHandle)
   - Checks isAppTopVisible(mCallerPackageName) — launcher must be visible
   - Sets FLAG_ACTIVITY_NEW_TASK on intent
   - Calls Context.startActivityAsUser(intent, userHandle)
```

## Why NOT Exploitable

### 1. Intent is constructed server-side (trusted)

`createErrorDialogIntent()` builds the launched Intent entirely within system_server:
- Action: hardcoded `com.android.intent.action.UNARCHIVE_ERROR_DIALOG`
- Extras: UNARCHIVE_STATUS (int), USER (from userId), REQUIRED_BYTES (long), INSTALLER_PACKAGE_NAME (string), INSTALLER_TITLE (from system lookup), PACKAGE_NAME (trusted)
- PendingIntent from installer is stored as extra (but typed as PendingIntent, not Intent)

The installer **cannot inject an arbitrary Intent** into this flow. All it can control is:
- Status code (int)
- Required bytes (long)  
- PendingIntent (its own, for retry)

### 2. Implicit intent resolved to system handler

The `UNARCHIVE_ERROR_DIALOG` implicit intent resolves to:
```
com.google.android.packageinstaller/com.android.packageinstaller.UnarchiveErrorActivity
```
This is registered at `mPriority=1`. Third-party apps cannot set priority > 0, so the system PackageInstaller always wins resolution.

### 3. isAppTopVisible check

`UnarchiveIntentSender.send()` checks `isAppTopVisible(mCallerPackageName)` — the launcher that initiated the unarchive must be in the foreground. This prevents background triggering.

### 4. Installer UID validation

`PackageInstallerService.reportUnarchivalStatus()` calls `isCallingUidOwner(session)` — only the actual session owner (verified installer) can report status. A random app cannot call this.

### 5. No component control

Even though the Intent is implicit, the action is hardcoded and the system handler always wins resolution. An attacker cannot:
- Change the action (it's hardcoded in system_server)
- Redirect to a different component (system handler has priority)
- Inject extras that would cause unintended behavior (extras are status/info only)

## Potential Design Improvements (not vulns)

1. Should use `setPackage("com.google.android.packageinstaller")` or `setComponent()` on the error dialog Intent — defense-in-depth
2. Should use explicit intent for `UNARCHIVE_DIALOG` too — same rationale
3. The lack of package restriction is a code quality issue, not a security vulnerability given priority-based resolution

## Comparison with Known Vuln Patterns

The classic Android Intent redirect (CVE-2023-21292, CVE-2023-20944) requires:
- Attacker-controlled Intent extracted from user-provided data
- Started by system without validation

This case does NOT match because:
- Intent content is system-generated, not attacker-provided
- Status code from installer is an int, not an Intent
- The only Parcelable from the installer is a PendingIntent (its own), which cannot be confused with an Intent during `getParcelableExtra("...", Intent.class)`

## Verdict

**NOT reportable.** The Intent launched by `startActivityAsUser` is entirely constructed within system_server from trusted state. The installer can only influence integer status codes and a PendingIntent object (which is its own and typed differently from Intent). No intent redirect is possible.

---

## Lessons Learned

- `startActivityAsUser` with implicit intent in system_server is a code smell but NOT automatically a vulnerability
- Key question for intent redirect: "Can an external/untrusted party control the Intent object?"
- Priority-based intent resolution effectively prevents implicit intent hijack from third-party apps (priority > 0 requires system signature)
- PendingIntent vs Intent type mismatch in `getParcelableExtra(key, Class)` provides natural type safety
