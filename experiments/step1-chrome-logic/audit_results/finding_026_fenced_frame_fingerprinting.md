# Finding 026: Multiple APIs Leak Fingerprinting Data from Fenced Frames

## Summary

Fenced Frames are designed to prevent cross-context information leakage for privacy-preserving ads. However, several Web APIs are accessible from fenced frames with plain JavaScript and leak fingerprinting-relevant information, undermining the privacy guarantee.

## Affected APIs

### 1. `navigator.mediaDevices.enumerateDevices()` — Device Fingerprinting
**Files:**
- `content/browser/browser_interface_binders.cc:981-986` — `MediaDevicesDispatcherHost` bound without fenced frame check
- `content/browser/renderer_host/media/media_devices_dispatcher_host.cc:127-156` — No fenced frame check

**Issue:** Returns device count and hashed device IDs without requiring any permission. Labels are redacted but the device count and groupId values are returned, enabling device fingerprinting.

### 2. `navigator.devicePosture` — Physical Device State
**Files:**
- `content/browser/browser_interface_binders.cc:828` — `DevicePostureProvider` bound without fenced frame check

**Issue:** Reveals whether the device is in "continuous" or "folded" state. Cross-context side channel.

### 3. `speechSynthesis.getVoices()` — System/Locale Fingerprinting
**Files:**
- `content/browser/browser_interface_binders.cc:911-912` — `SpeechSynthesis` bound without fenced frame check

**Issue:** Returns full list of installed TTS voices (name, language, local/remote). Highly system-specific, strong fingerprinting signal.

### 4. `EyeDropper` — Visual Info Leak from Embedding Page
**Files:**
- `content/browser/browser_interface_binders.cc:1193` — `EyeDropperChooser` bound without fenced frame check
- `content/browser/eye_dropper_chooser_impl.cc:19-37` — Only user activation check

**Issue:** Fenced frame can use EyeDropper to pick pixel colors from the embedding page, leaking visual information across the isolation boundary.

### 5. `navigator.mediaSession` — Cross-Context UI Manipulation
**Files:**
- `content/browser/browser_interface_binders.cc:1204` — `MediaSessionService` bound without fenced frame check

**Issue:** Fenced frame can set misleading media metadata in OS notifications, social engineering vector.

## Root Cause

Fenced frames restrict APIs through three layers:
1. Explicit `IsNestedWithinFencedFrame()` checks (only BatteryMonitor, ComputePressure, Bluetooth, HID, Serial, etc.)
2. Permissions Policy via `kFencedFrameAllowedFeatures` (only kPrivateAggregation, kSharedStorage, kSharedStorageSelectUrl)
3. Permission prompts blocked by `PermissionControllerImpl`

APIs that don't use any of these three mechanisms are accessible from fenced frames with plain JavaScript.

## Attack Scenario

1. Ad auction serves ad content in a fenced frame
2. The fenced frame JavaScript calls `navigator.mediaDevices.enumerateDevices()`
3. Device count + hashed device IDs create a fingerprint
4. Combined with `speechSynthesis.getVoices()` and `navigator.devicePosture`, creates a highly unique identifier
5. Fingerprint is exfiltrated via `sendBeacon` to the ad server (allowed by fenced frame design)
6. Cross-site user tracking achieved despite fenced frame isolation

## Impact

- **Privacy**: Defeats the purpose of fenced frames as a privacy-preserving ad container
- **Fingerprinting**: Combined API access creates strong fingerprinting vector
- **Cross-boundary info leak**: EyeDropper leaks visual information from embedding page

## Exploitability

- **No compromised renderer needed**: All APIs accessible with plain JavaScript
- **No user interaction needed**: Except EyeDropper (requires user click)
- **No permissions needed**: enumerateDevices, getVoices, devicePosture all work without permission grants

## VRP Value

Medium — Privacy violation in a privacy-focused feature. The fingerprinting data can be exfiltrated through allowed channels (sendBeacon), making this a practical attack. Individual APIs are low-medium severity, but the combination is significant.

## Chromium Awareness

No TODO comments found for any of these gaps. The fenced frame API restriction list appears to have been built incrementally rather than from a comprehensive audit.
