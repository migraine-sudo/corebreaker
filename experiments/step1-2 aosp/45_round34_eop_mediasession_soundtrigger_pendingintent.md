# Report 45: Round 34 — EoP: MediaSession Policy Manipulation, SoundTrigger Hotword Kill, PendingIntent Immutability Bypass

**Date**: 2026-04-30  
**Scope**: MediaSessionService, SoundTriggerService, PendingIntentRecord, VoiceInteractionManagerService  
**Method**: Deep background agents + manual source verification  
**Previous**: Reports 01-44, ~424 variants

---

## Part A: MediaSessionService (3 findings)

### V-424: setSessionPolicies Zero-Permission — Media Key Event Stealing via Policy Manipulation [MEDIUM-HIGH/EoP]

**File**: `services/core/java/com/android/server/media/MediaSessionService.java` (lines ~2187-2201)

**Issue**: `setSessionPolicies` has ZERO permission checks. Any app with a valid session token can manipulate another app's session policies:

```java
@Override
public void setSessionPolicies(MediaSession.Token token, int policies) {
    final long callingIdentityToken = Binder.clearCallingIdentity();
    try {
        synchronized (mLock) {
            MediaSessionRecord record = getMediaSessionRecordLocked(token);
            FullUserRecord user = getFullUserRecordLocked(record.getUserId());
            if (record != null && user != null) {
                record.setSessionPolicies(policies);
                user.mPriorityStack.updateMediaButtonSessionBySessionPolicyChange(record);
            }
        }
    } finally {
        Binder.restoreCallingIdentity(callingIdentityToken);
    }
}
// NO permission check! Only needs a valid MediaSession.Token
```

Setting `SESSION_POLICY_IGNORE_BUTTON_SESSION` on a victim's session causes `updateMediaButtonSessionBySessionPolicyChange` to reassign the media button session — redirecting all hardware media key events away from the victim.

**Attack**:
1. Attacker app with NLS access obtains victim media app's session token via `getActiveSessions()`
2. Calls `setSessionPolicies(victimToken, SESSION_POLICY_IGNORE_BUTTON_SESSION)`
3. Victim's session is stripped of media button session status
4. Attacker's own session (created simultaneously) becomes the new media button session
5. All hardware media keys (play/pause, HEADSETHOOK) now route to attacker
6. HEADSETHOOK long-press triggers voice assistant launch from system context — attacker intercepts

**Permission**: Requires valid session token (NLS for cross-app, or own session for self)  
**Impact**: Media key event hijacking; can steal hardware button events from any media app  
**Bounty**: $3,000-$7,000

---

### V-425: addSession2TokensListener Missing Permission Check — Zero-Permission Session2 Enumeration [MEDIUM/Info → EoP Enabler]

**File**: `MediaSessionService.java` (lines ~1554-1578)

**Issue**: `addSession2TokensListener` does NOT call `enforceMediaPermissions()`, unlike its Session1 counterpart `addSessionsListener`. Any same-user app can register:

```java
@Override
public void addSession2TokensListener(ISession2TokensListener listener, int userId) {
    final int pid = Binder.getCallingPid();
    final int uid = Binder.getCallingUid();
    final long token = Binder.clearCallingIdentity();
    try {
        int resolvedUserId = handleIncomingUser(pid, uid, userId, null);
        // NO enforceMediaPermissions()! Compare with addSessionsListener which does check.
        synchronized (mLock) {
            mSession2TokensListenerRecords.add(
                new Session2TokensListenerRecord(listener, resolvedUserId));
        }
    } finally { ... }
}
```

Receives callbacks with `List<Session2Token>` containing: uid, package name, session type, and ISession2Token binder.

**Attack**:
1. Zero-permission app registers Session2 tokens listener
2. Receives real-time notifications of all MediaSession2 creation/destruction
3. Learns which apps are running, what media is playing, usage patterns
4. Session2Token Binder reference could enable further interaction with discovered sessions

**Permission**: ZERO (same-user)  
**Impact**: Real-time media session surveillance; app enumeration; usage pattern fingerprinting  
**Bounty**: $1,000-$3,000

---

### V-426: isTrusted Permission Oracle — Caller-Controlled PID/UID Reveals NLS and MEDIA_CONTENT_CONTROL Status [LOW-MEDIUM/Info]

**File**: `MediaSessionService.java` (lines ~2133-2149)

**Issue**: The `isTrusted` method accepts caller-supplied `controllerPid` and `controllerUid` and checks those against permission databases:

```java
@Override
public boolean isTrusted(String controllerPackageName, int controllerPid, int controllerUid) {
    final int uid = Binder.getCallingUid();
    // filterAppAccess uses real caller...
    if (LocalServices.getService(PackageManagerInternal.class)
            .filterAppAccess(controllerPackageName, uid, userId)) { return false; }
    
    final long token = Binder.clearCallingIdentity();
    try {
        // ...but permission checks use CALLER-SUPPLIED values:
        return hasMediaControlPermission(controllerPid, controllerUid)
            || hasEnabledNotificationListener(userId, controllerPackageName, controllerUid);
    } finally { ... }
}
```

**Attack**:
1. Enumerate UIDs from 10000-19999 (app UIDs)
2. For each: call `isTrusted(packageName, 0, uid)`
3. `true` result reveals the app has MEDIA_CONTENT_CONTROL or active NLS
4. NLS status is security-sensitive (these apps can read all notifications)

**Permission**: ZERO  
**Impact**: Permission/NLS status disclosure for any app  
**Bounty**: $500-$1,500

---

## Part B: SoundTriggerService (1 finding)

### V-427: setInPhoneCallState Zero-Permission — Disable All Hotword Detection System-Wide [MEDIUM/DoS+EoP]

**File**: `services/core/java/com/android/server/soundtrigger/SoundTriggerService.java` (line ~464)

**Issue**: The `setInPhoneCallState` test API is exposed via the Binder interface with ZERO permission checks:

```java
@Override
public void setInPhoneCallState(boolean isInPhoneCall) {
    Slog.i(TAG, "Overriding phone call state: " + isInPhoneCall);
    mDeviceStateHandler.onPhoneCallStateChanged(isInPhoneCall);
    // NO permission check! NO @EnforcePermission annotation!
}
```

When `isInPhoneCall = true`, `DeviceStateHandler.computeState()` returns `SoundTriggerDeviceState.DISABLE` which disables ALL sound trigger sessions:
```java
private SoundTriggerDeviceState computeState() {
    if (mIsPhoneCallOngoing) {
        return SoundTriggerDeviceState.DISABLE;  // Overrides everything!
    }
    // ...
}
```

**Attack**:
1. App calls `IServiceManager.getService("soundtrigger")` to get SoundTriggerService binder
2. Calls `setInPhoneCallState(true)` — ZERO permission needed
3. ALL hotword detection disabled system-wide ("Hey Google" stops working)
4. Google Assistant cannot be voice-activated
5. Persists until `setInPhoneCallState(false)` is called or device restart
6. User cannot easily diagnose why voice activation stopped working

**Mitigations**: SELinux policy may block third-party app access to `soundtrigger` service. Requires verification on stock Pixel.

**Permission**: ZERO (if SELinux allows binder access)  
**Impact**: System-wide hotword/voice assistant denial-of-service  
**Bounty**: $1,000-$3,000

---

## Part C: PendingIntentRecord (2 findings)

### V-428: ActivityOptions.getPendingIntentLaunchFlags Bypasses FLAG_IMMUTABLE — Launch Flag Injection [MEDIUM-HIGH/EoP]

**File**: `services/core/java/com/android/server/am/PendingIntentRecord.java` — `sendInner`

**Issue**: Even for PendingIntents created with `FLAG_IMMUTABLE`, the sender can inject launch flags via `ActivityOptions.getPendingIntentLaunchFlags()`:

```java
// This happens OUTSIDE the immutability check:
finalIntent.addFlags(opts.getPendingIntentLaunchFlags());
// FLAG_IMMUTABLE only prevents fillIn() from being called:
if (!immutable) {
    if (intent != null) {
        int changes = finalIntent.fillIn(intent, key.flags);
    }
}
// But launch flags are ALWAYS added regardless of immutability
```

The sender can inject flags like `FLAG_ACTIVITY_NEW_TASK`, `FLAG_ACTIVITY_CLEAR_TASK`, `FLAG_ACTIVITY_MULTIPLE_TASK` that affect task creation and management behavior.

**Attack**:
1. Obtain a reference to any immutable PendingIntent (from notifications, alarms, system broadcasts)
2. Create `ActivityOptions` with `setPendingIntentLaunchFlags(FLAG_ACTIVITY_NEW_TASK | FLAG_ACTIVITY_CLEAR_TASK)`
3. Send the PendingIntent with these options
4. The immutable PI's activity is launched in a new task, clearing the creator's existing task
5. Combined with task affinity (V-363), the new task can be hijacked

**Permission**: Must obtain PendingIntent reference (via NLS, broadcast interception, or PI exposure)  
**Impact**: Task manipulation and destruction via launch flag injection on immutable PendingIntents  
**Bounty**: $3,000-$7,000

---

### V-429: Foreground Sender BAL Privilege Transfer to Background PI Creator [MEDIUM/EoP]

**File**: `PendingIntentRecord.java` — sendInner BAL handling

**Issue**: When a foreground app sends a PendingIntent, its BAL privilege transfers to the (possibly background) PI creator for broadcast/service types:

```java
// For broadcast/service PIs:
if (uid != callingUid && controller.mAtmInternal.isUidForeground(callingUid)) {
    return getBackgroundStartPrivilegesAllowedByCaller(options, callingUid, null);
}
```

If sender (foreground) ≠ creator (background), and sender is foreground, the PI dispatch gets the sender's BAL privileges. The creator's code then executes with BAL capability it shouldn't have.

**Attack chain**:
1. Malicious background app creates a PendingIntent (broadcast type) that when triggered, starts a FGS or activity
2. App tricks/coordinates with a foreground app to send this PI (e.g., via notification action tap)
3. The foreground app's BAL privilege transfers to the PI dispatch
4. Background app's broadcast receiver fires with BAL → can start activities from background

**Mitigations**: `DEFAULT_RESCIND_BAL_PRIVILEGES_FROM_PENDING_INTENT_SENDER` (enabled post-TIRAMISU) limits this to `ALLOW_FGS` instead of full `ALLOW_BAL` for targeting U+ apps. But pre-U apps still get full BAL transfer.

**Permission**: Must trick foreground app into sending attacker's PI  
**Impact**: Background activity launch via foreground sender privilege transfer (pre-U apps)  
**Bounty**: $2,000-$5,000

---

## Part D: VoiceInteractionManagerService (1 finding)

### V-430: showSessionFromSession Injects Unvalidated Extras into Contextual Search Intent [LOW-MEDIUM/EoP]

**File**: `services/voiceinteraction/java/com/android/server/voiceinteraction/VoiceInteractionManagerService.java` (line ~1009)

**Issue**: When `showSessionFromSession` triggers contextual search, the caller-provided `sessionArgs` bundle is passed directly as extras to the contextual search intent:

```java
// In getContextualSearchIntent:
launchIntent.putExtras(args);  // sessionArgs from VIS, passed directly as intent extras
```

The caller (active VoiceInteractionService) can inject arbitrary extras that the contextual search activity may trust. While the target activity is restricted to `config_defaultContextualSearchPackageName` (resolved with `MATCH_FACTORY_ONLY`), the injected extras could manipulate the search behavior.

**Permission**: Must be the active VoiceInteractionService  
**Impact**: Extra injection into contextual search intent; limited by package restriction  
**Bounty**: $500-$1,000

---

## Part E: Confirmed Secure (Additional Audit Negative Results)

| Service | Result |
|---------|--------|
| VoiceInteractionManager cross-user | Per-user VoiceInteractionManagerServiceImpl with bindServiceAsUser |
| VoiceInteractionManager session token | System-generated Binder() object, unforgeable |
| VoiceInteractionManager role validation | RoleManager-gated, requires user consent |
| SoundTrigger session permissions | All session methods check MANAGE_SOUND_TRIGGER (signature) |
| SoundTrigger identity delegation | SOUNDTRIGGER_DELEGATE_IDENTITY properly enforced |
| SoundTrigger cross-user models | Per-session user scoping via bindServiceAsUser |
| MediaSession cross-user sessions | verifySessionsRequest → handleIncomingUser enforces INTERACT_ACROSS_USERS_FULL |
| MediaSession callback injection | ISessionCallback tied to creator, not replaceable |
| MediaRouter2 cross-user routing | Requires MEDIA_ROUTING_CONTROL + INTERACT_ACROSS_USERS_FULL |
| IMMS (full audit) | Hardened: setInputMethod removed from AIDL, per-user isolation, anti-tapjacking |
| DPMS (full audit) | Hardened: CallerIdentity binding, DPC type hierarchy, delegation isolation |
| PendingIntentRecord cross-user send | Allowed by design (executes in creator's user context) |

---

## Round 34 Summary

| Severity | Count | Key Findings |
|----------|-------|-------------|
| MEDIUM-HIGH | 2 | Session policy manipulation (V-424), Immutable PI flag bypass (V-428) |
| MEDIUM | 3 | Session2 enumeration (V-425), Hotword kill (V-427), BAL transfer (V-429) |
| LOW-MEDIUM | 2 | Permission oracle (V-426), Contextual search extras (V-430) |
| **Total** | **7** | |

**Estimated bounty this round**: $11,000 - $27,500

---

## Cumulative Project Statistics (Reports 01-45)

| Metric | Previous | This Round | Cumulative |
|--------|----------|------------|------------|
| Total variants | ~424 | +7 | **~431** |
| HIGH/CRITICAL | ~57 | +0 | **~57** |
| Bounty estimate (low) | $819.9k | +$11k | **$830.9k** |
| Bounty estimate (high) | $2.055M | +$27.5k | **$2.083M** |

---

## Updated Priority VRP Submissions (Top 10)

Based on all findings across 45 reports:

1. **V-201**: MediaSessionService zero-perm class instantiation in system_server ($20k-$30k)
2. **V-376/V-377**: Accessibility service enable without dialog via backup+shortcut ($5k-$15k)
3. **V-385**: NLS PendingIntent extraction bypasses content redaction ($5k-$15k)
4. **V-395**: CredentialManager getCandidateCredentials missing enforceCallingPackage ($5k-$15k)
5. **V-361**: PendingIntent mCallingUid BAL task insertion bypass ($5k-$15k)
6. **V-333**: Permission framework inverted ternary ($5k-$15k)
7. **V-344-346**: Zero-permission Private Space surveillance chain ($8k-$15k)
8. **V-415**: Zero-permission DeviceConfig flag read ($3k-$10k)
9. **V-362+V-363**: SAW + task affinity = StrandHogg on Android 16 ($3k-$7k)
10. **V-428**: Immutable PendingIntent launch flag bypass ($3k-$7k)

---

*Generated by FuzzMind/CoreBreaker Round 34 — 2026-04-30*
