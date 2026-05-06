# Report 34: Round 23 — EoP: SystemUI ControlsRequestReceiver, Settings Fragment Injection, SearchResultTrampoline

**Date**: 2026-04-30  
**Scope**: SystemUI exported components, Settings app exported activities, SubSettings, SearchResultTrampoline  
**Method**: Deep background agent  
**Previous**: Reports 01-33, ~349 variants

---

## Part A: SystemUI (2 findings)

### V-349: ControlsRequestReceiver Zero-Permission Cross-User Activity Launch as SYSTEM [MEDIUM-HIGH/EoP]

**File**: `packages/SystemUI/src/com/android/systemui/controls/management/ControlsRequestReceiver.kt`

**Issue**: `ControlsRequestReceiver` is an **exported broadcast receiver with NO permission requirement**. When it receives a broadcast, it:
1. Extracts `EXTRA_COMPONENT_NAME` and `ControlsProviderService.EXTRA_CONTROL` from the intent
2. Validates the package in the ComponentName is in the foreground (via `getUidImportance`)
3. Starts `ControlsRequestDialog` **as `UserHandle.SYSTEM`**: `context.startActivityAsUser(activityIntent, UserHandle.SYSTEM)`

```kotlin
// ControlsRequestReceiver - exported, no permission
override fun onReceive(context: Context, intent: Intent) {
    val componentName = intent.getParcelableExtra(Intent.EXTRA_COMPONENT_NAME, ...)
    val control = intent.getParcelableExtra(ControlsProviderService.EXTRA_CONTROL, ...)
    // Foreground check uses the package from caller-controlled ComponentName
    if (isPackageForeground(context, componentName.packageName)) {
        val activityIntent = Intent(context, ControlsRequestDialog::class.java)
        // ... set extras from caller ...
        context.startActivityAsUser(activityIntent, UserHandle.SYSTEM)  // EoP!
    }
}
```

**Attack**:
1. Malicious app running in foreground sends broadcast to `ControlsRequestReceiver`
2. Sets `EXTRA_COMPONENT_NAME` pointing to its own package (passes foreground check)
3. Sets `EXTRA_CONTROL` with a crafted Control object containing attacker-controlled strings
4. `ControlsRequestDialog` starts as SYSTEM user — crosses user boundary
5. From a secondary user or work profile, this crosses the user isolation boundary

**Permission**: ZERO  
**Impact**: Cross-user activity launch — a secondary user/work profile/Private Space app triggers SYSTEM-user activity. Limited by what ControlsRequestDialog does (shows confirmation), but the boundary violation is the EoP.  
**Bounty**: $2,000-$5,000

---

### V-350: SystemUI Exported Components Without Permission — UI Spoofing Suite [LOW-MEDIUM]

**File**: `packages/SystemUI/AndroidManifest.xml`

**Issue**: Multiple SystemUI components are exported with ZERO permission requirement:
- `MediaOutputDialogReceiver` — accepts `EXTRA_PACKAGE_NAME`, shows media dialog for arbitrary package
- `ForegroundServicesDialog` — accepts `packages` string array, displays arbitrary package names in system-styled dialog
- `VolumePanelDialogReceiver` — show/dismiss volume panel
- `KeyboardShortcutsReceiver` — trigger keyboard shortcuts display
- `BrightnessDialog` — trigger brightness dialog

**Attack**: A zero-permission app can:
1. Send broadcast to `ForegroundServicesDialog` with forged package list → system-styled dialog shows arbitrary packages as "using device resources" (social engineering)
2. Send broadcast to `MediaOutputDialogReceiver` with target package name → interrupts user's media session management
3. Repeatedly trigger `VolumePanelDialogReceiver` → UI harassment

**Permission**: ZERO  
**Impact**: UI spoofing with system-app styling, social engineering enablement  
**Bounty**: $500-$1,500

---

## Part B: Settings App (3 findings)

### V-351: SubSettings.isValidFragment() Returns True for ALL Fragments — Latent Arbitrary Fragment Injection [HIGH (latent)]

**File**: `packages/apps/Settings/src/com/android/settings/SubSettings.java`

**Issue**: `SubSettings.isValidFragment()` unconditionally returns `true` for ANY fragment class name, completely bypassing the `SettingsGateway.ENTRY_FRAGMENTS` allowlist that `SettingsActivity.isValidFragment()` enforces.

```java
// SubSettings.java - NO validation!
@Override
protected boolean isValidFragment(String fragmentName) {
    Log.d("SubSettings", "Launching fragment " + fragmentName);
    return true;  // ANY fragment class accepted!
}
```

Currently, `SubSettings` is declared `android:exported="false"`, so it cannot be directly reached by external apps. However, this is a **time bomb**: if any future code path routes an external caller's fragment name through SubSettings (e.g., via a deep link handler or intent forwarding), it immediately becomes arbitrary code execution in the Settings system-UID process.

**Current exploitability**: Not directly exploitable from external apps due to `exported=false`.  
**Risk**: Any internal routing vulnerability (like SearchResultTrampoline) that reaches SubSettings with caller-controlled fragment name = CRITICAL arbitrary fragment injection in system_server context.

**Permission**: N/A (latent)  
**Impact**: If triggered, arbitrary code execution in system UID via fragment instantiation  
**Bounty**: $1,000-$3,000 (hardening issue / latent vulnerability)

---

### V-352: SearchResultTrampoline Intent.parseUri Without Selector Stripping [MEDIUM/EoP]

**File**: `packages/apps/Settings/src/com/android/settings/search/SearchResultTrampoline.java`

**Issue**: `SearchResultTrampoline` is an exported activity that processes `EXTRA_SETTINGS_EMBEDDED_DEEP_LINK_INTENT_URI` via `Intent.parseUri()`. While the caller is verified (must be Settings, SettingsIntelligence, or signature-allowlisted), the parsed Intent's **selector is NOT stripped**.

```java
// Deep link path:
final String intentUriString = intent.getStringExtra(
    Settings.EXTRA_SETTINGS_EMBEDDED_DEEP_LINK_INTENT_URI);
intent = Intent.parseUri(intentUriString, Intent.URI_INTENT_SCHEME);
intent.setData(data);
// NOTE: Selector is NOT stripped! Compare to EmbeddedDeepLinkUtils which strips it.
```

The `EmbeddedDeepLinkUtils.getTrampolineIntent()` properly strips selectors:
```kotlin
if (detailIntent.selector != null) {
    detailIntent.setSelector(null)
}
```

**Attack**: If an attacker can compromise or impersonate SettingsIntelligence (which has a broader attack surface), they can launch arbitrary intents with Settings' system-UID identity via the Intent selector bypass.

**Permission**: Must impersonate allowlisted caller (SettingsIntelligence or signature-matched)  
**Impact**: Arbitrary intent launch with system UID if caller verification is bypassed  
**Bounty**: $1,000-$3,000

---

### V-353: Settings Fragment Arguments Bundle Injection for All Exported Activities [LOW-MEDIUM]

**File**: `packages/apps/Settings/src/com/android/settings/SettingsActivity.java`

**Issue**: All 100+ exported `Settings$*Activity` subclasses accept `EXTRA_SHOW_FRAGMENT_ARGUMENTS` from external callers. While the fragment class is determined by manifest metadata (not caller-controlled), the **arguments Bundle is fully caller-controlled**.

```java
// SettingsActivity.launchSettingFragment():
Bundle initialArguments = intent.getBundleExtra(EXTRA_SHOW_FRAGMENT_ARGUMENTS);
switchToFragment(initialFragmentName, initialArguments, true, ...);
```

Notable extras that flow from arguments to privileged operations:
- `EXTRA_USER_HANDLE` / `Intent.EXTRA_USER_ID` — influences which user's settings are displayed
- In `ChooseLockGeneric`: `mUserId = Utils.getSecureTargetUser(..., arguments, ...)` — could influence lock screen target user
- Fragment-specific parameters that may trigger privileged behaviors

**Attack**: External app launches `Settings$SecuritySettingsActivity` with `EXTRA_SHOW_FRAGMENT_ARGUMENTS` containing `EXTRA_USER_ID` pointing to another user. If `getSecureTargetUser` doesn't properly validate, attacker could view/modify another user's security settings.

**Permission**: ZERO  
**Impact**: Potential cross-user settings manipulation depending on individual fragment validation  
**Bounty**: $500-$2,000

---

## Round 23 Summary

| Severity | Count | Key Findings |
|----------|-------|-------------|
| MEDIUM-HIGH | 1 | ControlsRequestReceiver cross-user (V-349) |
| HIGH (latent) | 1 | SubSettings isValidFragment bypass (V-351) |
| MEDIUM | 1 | SearchResultTrampoline selector (V-352) |
| LOW-MEDIUM | 2 | SystemUI UI spoofing (V-350), fragment args injection (V-353) |
| **Total** | **5** | |

**Estimated bounty this round**: $5,000 - $14,500

---

## Cumulative Project Statistics (Reports 01-34)

| Metric | Previous | This Round | Cumulative |
|--------|----------|------------|------------|
| Total variants | ~349 | +5 | **~354** |
| HIGH/CRITICAL | ~51 | +1 (latent) | **~52** |
| Bounty estimate (low) | $684.9k | +$5k | **$689.9k** |
| Bounty estimate (high) | $1.680M | +$14.5k | **$1.695M** |

---

*Generated by FuzzMind/CoreBreaker Round 23 — 2026-04-30*
