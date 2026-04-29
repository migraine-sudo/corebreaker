# Finding 079: Fenced Frame Focus Boundary Enforcement Disabled (kFencedFramesEnforceFocus)

## Summary

The `kFencedFramesEnforceFocus` feature flag is DISABLED by default. When disabled, focus changes that cross the fenced frame boundary are detected but only trigger `DumpWithoutCrashing` instead of killing the renderer. A compromised renderer can move focus across the fenced frame boundary.

## Affected Files

- `content/public/common/content_features.cc:449` — `kFencedFramesEnforceFocus` DISABLED_BY_DEFAULT
- `content/browser/renderer_host/render_frame_host_impl.cc:6172-6177` — Focus enforcement gated

## Details

```cpp
// render_frame_host_impl.cc:6172-6177
if (base::FeatureList::IsEnabled(features::kFencedFramesEnforceFocus)) {
    bad_message::ReceivedBadMessage(
        GetProcess(), bad_message::RFH_FOCUS_ACROSS_FENCED_BOUNDARY);
} else {
    base::debug::DumpWithoutCrashing();  // Log only, don't kill
}
```

## Attack Scenario (requires compromised renderer)

### Focus-based phishing in fenced frame ads

1. User sees a fenced frame ad on a banking site
2. The compromised renderer in the ad's fenced frame shifts focus to the parent page's password field
3. User's keystrokes go to the ad instead of the banking form
4. Credentials captured by the ad

### Fenced frame side-channel communication

1. Fenced frame and embedder share a focus side-channel
2. By shifting focus back and forth across the fenced frame boundary, bits of information can be communicated
3. This violates the fenced frame's information isolation guarantee

## Impact

- **Requires compromised renderer**: The focus change must be initiated by a compromised renderer
- **Known issue**: crbug.com/40274134
- **Focus hijacking**: Can intercept user input in phishing scenarios
- **Privacy leak**: Focus-based side channel across fenced frame boundary

## VRP Value

**Low-Medium** — Requires compromised renderer. Focus hijacking enables phishing but is detectable by observant users.
