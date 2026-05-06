# Report 40: Round 29 — EoP: TelecomService Call Manipulation, Final Consolidation

**Date**: 2026-04-30  
**Scope**: TelecomServiceImpl, CallScreeningServiceFilter, CompanionDeviceManager (additional)  
**Method**: Deep background agents + manual source verification  
**Previous**: Reports 01-39, ~392 variants

---

## Part A: TelecomServiceImpl (3 findings)

### V-392: ANSWER_PHONE_CALLS Permission Enables Call Termination — Telephony DoS [MEDIUM/EoP]

**File**: `packages/services/Telecomm/src/com/android/server/telecom/TelecomServiceImpl.java` (lines 1513-1542, 3126-3163)

**Issue**: `endCall()` uses the same `enforceAnswerCallPermission` check as `acceptRingingCall`, meaning any app with just `ANSWER_PHONE_CALLS` (a standard runtime permission) can terminate:
- Active calls (`disconnectCall`)
- Ringing calls (`rejectCall`)
- Dialing, pulling, and on-hold calls

```java
// endCall() - line 1519:
enforceAnswerCallPermission(callingPackage, callingPid, callingUid);
// Same permission as acceptRingingCall!

// Line 3033-3048 (enforceAnswerCallPermission):
// Checks MODIFY_PHONE_STATE first, then falls back to ANSWER_PHONE_CALLS
```

Emergency calls are protected (CVE fix b/132438333), and self-managed calls require privileged callers.

**Attack**:
1. Malicious app requests `ANSWER_PHONE_CALLS` (not unusual for communication apps)
2. Runs background service monitoring call state
3. Persistently terminates all incoming/active calls as DoS
4. OR: Selectively terminates calls from specific contacts (combined with call state detection)

**Permission**: ANSWER_PHONE_CALLS (runtime, user-grantable)  
**Impact**: Persistent telephony denial-of-service — user cannot maintain calls  
**Bounty**: $2,000-$5,000

---

### V-393: Default Dialer Silent USSD/MMI Code Execution with clearCallingIdentity [MEDIUM/EoP]

**File**: `TelecomServiceImpl.java` (lines 1674-1749)

**Issue**: `handlePinMmi()` allows the default dialer to execute arbitrary MMI/USSD codes. After the permission check, `Binder.clearCallingIdentity()` is called and the MMI string is passed to TelephonyManager with Telecom's system-level identity:

```java
// Line 1683:
final long identity = Binder.clearCallingIdentity();
// Line 1686:
return getTelephonyManager(subId).handlePinMmi(dialString);
// No sanitization of dialString!
```

No sanitization is performed on the `dialString` parameter — it passes directly to the telephony framework.

**Attack**:
1. Malicious app becomes default dialer (user must select it)
2. Silently executes call forwarding USSD: `*21*+attacker_number#`
3. All incoming calls redirected to attacker's number
4. OR: Executes premium service subscription USNDs
5. OR: Queries network information via supplementary service codes

**Permission**: Default dialer role (user-selected)  
**Impact**: Silent call forwarding, premium service activation, network info disclosure  
**Bounty**: $2,000-$5,000

---

### V-394: Call Screening Service Silent Rejection Without Call Log Entry [LOW-MEDIUM/EoP]

**File**: `CallScreeningServiceFilter.java` (lines 114-144)

**Issue**: A user-chosen call screening app (`ROLE_CALL_SCREENING`) can silently reject calls AND suppress the notification for missed calls. While the call log suppression has been partially mitigated (user-chosen apps now always add to call log), the **notification suppression** still works:

```java
// CallFilteringResult:
shouldSkipNotification = true;  // User-chosen screening app can set this
// Result: Call is rejected, added to call log, but NO notification shown
```

**Attack**: Screening app silently rejects specific incoming calls. User sees no missed call notification. The only evidence is buried in the call log if the user manually checks.

**Permission**: ROLE_CALL_SCREENING (user-granted role)  
**Impact**: Selective call suppression with hidden evidence  
**Bounty**: $500-$1,500

---

## Part B: Session Consolidation — Top EoP Findings Summary

### Tier 1: HIGH/CRITICAL (Actionable VRP Submissions)

| ID | Finding | Severity | Permission | Est. Bounty |
|----|---------|----------|------------|-------------|
| V-333 | Inverted ternary in updatePermissionFlagsForAllApps | HIGH | Sig\|installer | $5k-$15k |
| V-340 | PendingIntent fillIn URI grant (mechanism confirmed, no gadget) | MEDIUM | — | $1k-$3k |
| V-361 | PendingIntent mCallingUid BAL task insertion bypass | HIGH | PI reference | $5k-$15k |
| V-376 | A11y backup/restore enables service without dialog | HIGH | Backup restore | $5k-$15k |
| V-377 | A11y shortcut restore + volume key bypass chain | HIGH | Backup + user | $5k-$10k |
| V-385 | NLS PendingIntent extraction bypasses redaction | HIGH | NLS access | $5k-$15k |

### Tier 2: MEDIUM-HIGH (Strong Submissions)

| ID | Finding | Severity | Permission | Est. Bounty |
|----|---------|----------|------------|-------------|
| V-344+345+346 | Private Space zero-perm detection chain | MEDIUM-HIGH | ZERO | $8k-$15k |
| V-349 | ControlsRequestReceiver cross-user as SYSTEM | MEDIUM-HIGH | ZERO | $2k-$5k |
| V-362 | SAW universal BAL + ASM bypass | MEDIUM-HIGH | SAW | $3k-$7k |
| V-365 | NFC BT OOB pairing + HID injection | MEDIUM-HIGH | Physical | $3k-$7k |
| V-388 | Self-managed companion permanent FGS | MEDIUM-HIGH | Normal perm | $2k-$5k |

### Tier 3: MEDIUM (Valuable Reports)

| ID | Finding | Severity | Permission | Est. Bounty |
|----|---------|----------|------------|-------------|
| V-335 | getMimeTypeFilterAsync clearCallingIdentity bypass | MEDIUM | ZERO | $1k-$3k |
| V-336 | AccountManager session bundle merge attack | MEDIUM | ZERO | $1k-$3k |
| V-338 | Notification BAL allowlisting at enqueue | MEDIUM | Notifications | $1k-$3k |
| V-357 | Vold reset CE re-unlock without keyguard | MEDIUM-HIGH | Vold crash | $3k-$7k |
| V-363 | Task affinity hijacking (ASM disabled) | MEDIUM | BAL | $2k-$5k |
| V-369 | LazyBundle re-parcel differential deserialization | MEDIUM | ZERO | $3k-$10k |
| V-378 | performGlobalAction bypasses TAKE_SCREENSHOT capability | MEDIUM | A11y | $2k-$5k |
| V-380 | Cross-profile Doze bypass by appId | MEDIUM | Multi-profile | $1k-$3k |
| V-386 | Cross-user NLS access to work/private space | MEDIUM | NLS | $3k-$7k |

---

## Round 29 Summary

| Severity | Count | Key Findings |
|----------|-------|-------------|
| MEDIUM | 2 | Call termination DoS (V-392), USSD execution (V-393) |
| LOW-MEDIUM | 1 | Call screening suppression (V-394) |
| **Total** | **3** | |

**Estimated bounty this round**: $4,500 - $11,500

---

## Cumulative Project Statistics (Reports 01-40)

| Metric | Previous | This Round | Cumulative |
|--------|----------|------------|------------|
| Total variants | ~392 | +3 | **~395** |
| HIGH/CRITICAL | ~56 | +0 | **~56** |
| Bounty estimate (low) | $758.9k | +$4.5k | **$763.4k** |
| Bounty estimate (high) | $1.880M | +$11.5k | **$1.891M** |

---

## Final Session Statistics (Rounds 20-29, Reports 31-40)

| Metric | Start of Session | End of Session | Delta |
|--------|-----------------|----------------|-------|
| Total variants | ~333 | ~395 | **+62** |
| HIGH/CRITICAL | ~49 | ~56 | **+7** |
| Reports | 30 | 40 | **+10** |
| Bounty estimate (low) | $651.9k | $763.4k | **+$111.5k** |
| Bounty estimate (high) | $1.596M | $1.891M | **+$295k** |

---

## Recommended Priority VRP Submissions

Based on novelty, exploitability, and estimated reward:

1. **V-376/V-377**: Accessibility service enable without warning dialog (backup + shortcut chain)
2. **V-385**: NLS PendingIntent extraction bypasses content redaction  
3. **V-344/V-345/V-346**: Zero-permission Private Space surveillance chain
4. **V-361**: PendingIntent mCallingUid BAL bypass
5. **V-333**: Permission framework inverted ternary
6. **V-362 + V-363**: SAW + task affinity = StrandHogg still alive on Android 16

---

*Generated by FuzzMind/CoreBreaker Rounds 20-29 Consolidation — 2026-04-30*
