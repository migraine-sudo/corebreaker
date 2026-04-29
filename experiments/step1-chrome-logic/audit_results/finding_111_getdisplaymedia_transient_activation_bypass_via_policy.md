# Finding 111: getDisplayMedia() Transient User Activation Can Be Bypassed via Enterprise Policy

## Severity: MEDIUM

## Location
- `chrome/browser/media/webrtc/display_media_access_handler.cc`, lines 272-283
- `chrome/browser/media/webrtc/capture_policy_utils.cc`, lines 142-166

## Description

The `getDisplayMedia()` API requires a transient user activation (user gesture) before showing the screen capture picker. However, this requirement can be completely bypassed via the enterprise policy `kScreenCaptureWithoutGestureAllowedForOrigins`.

The browser-side check:

```cpp
// display_media_access_handler.cc:272
if (!rfh->HasTransientUserActivation() &&
    capture_policy::IsTransientActivationRequiredForGetDisplayMedia(
        web_contents)) {
    std::move(callback).Run(..., MediaStreamRequestResult::NO_TRANSIENT_ACTIVATION, ...);
    return;
}
```

And the policy bypass in `capture_policy_utils.cc`:

```cpp
bool IsTransientActivationRequiredForGetDisplayMedia(WebContents* contents) {
    if (!base::FeatureList::IsEnabled(
            blink::features::kGetDisplayMediaRequiresUserActivation)) {
        return false;  // Feature flag can disable the requirement entirely
    }
    // ...
    return !policy::IsOriginInAllowlist(
        contents->GetURL(), prefs,
        prefs::kScreenCaptureWithoutGestureAllowedForOrigins);
}
```

There are two bypass paths:
1. **Feature flag**: `kGetDisplayMediaRequiresUserActivation` can be disabled, removing the user activation requirement for all origins.
2. **Enterprise policy**: `kScreenCaptureWithoutGestureAllowedForOrigins` allows specific origins to bypass the gesture requirement entirely.

Additionally, the code comment at line 272-275 reveals an interesting race condition:
```
// Renderer process should already check for transient user activation
// before sending IPC, but just to be sure double check here as well. This
// is not treated as a BadMessage because it is possible for the transient
// user activation to expire between the renderer side check and this check.
```

This means a compromised renderer that sends the IPC without user activation will not be killed -- the request will simply be rejected silently.

## Impact

- On managed devices, the enterprise policy could allow specific origins to trigger screen capture without user gesture, potentially enabling silent screen capture if combined with auto-accept policies.
- The feature flag mechanism means a single flag flip removes the gesture requirement globally.
- The non-BadMessage treatment of gesture-less requests means a compromised renderer repeatedly sending requests is not penalized.

## Exploitability

MEDIUM -- requires either enterprise policy misconfiguration, feature flag manipulation, or a compromised renderer. Not directly exploitable from normal web content. However, in managed environments where `kScreenCaptureWithoutGestureAllowedForOrigins` is overly broad, a web application on the allowlist can programmatically trigger screen capture without user interaction.
