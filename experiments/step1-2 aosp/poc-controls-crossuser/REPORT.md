# V-349: SystemUI ControlsRequestReceiver Zero-Permission Cross-User Activity Launch

## Vulnerability Details

SystemUI's `ControlsRequestReceiver` is an **exported broadcast receiver with NO permission requirement**. Upon receiving a broadcast, it starts `ControlsRequestDialog` as `UserHandle.SYSTEM`, regardless of the sender's user. This allows an app in a work profile or secondary user to trigger an activity launch in the system user's context — a cross-user EoP.

**Root Cause**: The receiver performs a foreground check on the **EXTRA_COMPONENT_NAME** from the attacker-controlled intent, not on the actual broadcast sender. A foreground malicious app simply sets `EXTRA_COMPONENT_NAME` to its own package, passes the check, and triggers `startActivityAsUser(intent, UserHandle.SYSTEM)`.

**Source**: `packages/SystemUI/src/com/android/systemui/controls/management/ControlsRequestReceiver.kt`

```kotlin
// Exported, NO android:permission attribute
override fun onReceive(context: Context, intent: Intent) {
    val componentName = intent.getParcelableExtra(Intent.EXTRA_COMPONENT_NAME, ...)
    val control = intent.getParcelableExtra(ControlsProviderService.EXTRA_CONTROL, ...)

    // Foreground check uses ATTACKER-CONTROLLED package name:
    if (isPackageForeground(context, componentName.packageName)) {
        val activityIntent = Intent(context, ControlsRequestDialog::class.java)
        // ... copies extras from caller ...
        context.startActivityAsUser(activityIntent, UserHandle.SYSTEM)  // EoP!
    }
}
```

## Impact

### Who is affected
All Android 11+ devices with SystemUI Controls support (device controls). The vulnerability is exploitable from work profiles, secondary users, and Private Space.

### Attack scenario
1. App installed in work profile (userId=10) runs in foreground
2. Sends broadcast to `com.android.systemui/.controls.management.ControlsRequestReceiver`
3. Sets `EXTRA_COMPONENT_NAME` = own package (passes foreground check)
4. Optionally includes a crafted `Control` object with attacker-controlled strings
5. SystemUI starts `ControlsRequestDialog` as system user (userId=0)
6. Activity launches **cross user boundary** — work profile app triggered system-user UI

### Severity assessment
- **Direct impact**: Cross-user activity launch (EoP boundary violation)
- **ControlsRequestDialog**: Shows a device controls confirmation UI with attacker-controlled content (control title, subtitle, device type)
- **Potential escalation**: If the dialog's "Add" action performs operations as system user without re-checking the initiator, further EoP possible
- **Social engineering**: Attacker-controlled strings appear in a system-styled dialog

## Reproduction Steps

### Setup
1. Create a work profile on test device:
   ```bash
   adb shell pm create-user --profileOf 0 --managed TestWork
   adb shell am start-user <userId>
   ```
2. Install PoC APK in the work profile:
   ```bash
   adb install --user <workUserId> poc-controls.apk
   ```

### Execution
1. Launch "Controls CrossUser PoC" in the work profile
2. Tap "3. Check User Context" — confirms non-primary user
3. Tap "1. Send Broadcast (Basic)" or "2. Send with Control Object"
4. Observe: `ControlsRequestDialog` appears in system user context

### Single-user verification (limited)
On primary user, the dialog still starts as system user (same user in this case).
Confirm via logcat:
```bash
adb logcat -s ControlsRequest SystemUI | grep -i "startActivity\|ControlsRequest"
```

**Expected (vulnerable)**: Dialog appears; logcat shows activity started as SYSTEM
**Expected (patched)**: SecurityException or broadcast silently dropped

## Fingerprint

| Field | Value |
|-------|-------|
| AOSP Source | `packages/SystemUI/src/com/android/systemui/controls/management/ControlsRequestReceiver.kt` |
| Receiver | `com.android.systemui.controls.management.ControlsRequestReceiver` |
| Export Status | `exported="true"`, no `android:permission` attribute |
| Trigger | Broadcast with `Intent.EXTRA_COMPONENT_NAME` parcelable extra |
| EoP Call | `context.startActivityAsUser(activityIntent, UserHandle.SYSTEM)` |
| Foreground Check | `isPackageForeground(context, componentName.packageName)` — uses attacker-supplied ComponentName |
| Dialog | `ControlsRequestDialog` (SystemUI internal activity) |
| Extra Data | `ControlsProviderService.EXTRA_CONTROL` (Parcelable, attacker-controlled content) |
| Affected Versions | Android 11+ (Device Controls introduction) |
| Tested On | Pixel, Android 15 |

## Suggested Fix

1. Add `android:permission="android.permission.BIND_CONTROLS"` to the receiver declaration
2. Verify the broadcast sender's identity matches the ComponentName's package:
```kotlin
if (componentName.packageName != callerPackageName) {
    Log.w(TAG, "Sender doesn't match component package")
    return
}
```
3. Remove `UserHandle.SYSTEM` hardcoding — use the sender's user handle instead
