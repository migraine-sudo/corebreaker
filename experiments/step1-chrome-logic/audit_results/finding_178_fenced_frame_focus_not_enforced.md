# Finding 178: Fenced Frame Focus Enforcement Disabled (kFencedFramesEnforceFocus)

## Summary

The `kFencedFramesEnforceFocus` feature is DISABLED by default. When disabled, a renderer that attempts to focus across a fenced frame boundary is not terminated via bad_message — instead, Chrome only calls `DumpWithoutCrashing()`. This weakens the fenced frame isolation boundary.

## Affected Files

- `content/public/common/content_features.cc:449` — Feature DISABLED_BY_DEFAULT
- `content/browser/renderer_host/render_frame_host_impl.cc:6169-6178` — Non-enforcing fallback

## Details

```cpp
// content_features.cc:448-449
// Enables browser-side focus verification when crossing fenced boundaries.
BASE_FEATURE(kFencedFramesEnforceFocus, base::FEATURE_DISABLED_BY_DEFAULT);

// render_frame_host_impl.cc:6169-6178
// TODO(crbug.com/40274134): We will later badmessage the renderer, but, for
// now, we will dump without crashing to monitor if any legitimate cases are
// reaching this point.
if (base::FeatureList::IsEnabled(features::kFencedFramesEnforceFocus)) {
    bad_message::ReceivedBadMessage(
        GetProcess(), bad_message::RFH_FOCUS_ACROSS_FENCED_BOUNDARY);
} else {
    base::debug::DumpWithoutCrashing();
}
return false;
```

Additionally, `kIsolateFencedFrames` is also DISABLED by default (`content_features.cc:591`), meaning fenced frames don't even get process isolation.

## Attack Scenario

1. Ad in a fenced frame (FLEDGE ad rendering) attempts to focus elements in the embedding page
2. The renderer sends a focus request across the fenced boundary
3. Browser detects the cross-boundary focus but only dumps without crashing
4. While the `return false` prevents focus in this specific code path, a compromised renderer in the same process (since kIsolateFencedFrames is also disabled) can directly manipulate focus
5. The ad can detect focus state changes to fingerprint user interactions with the embedding page

### Combined with kIsolateFencedFrames disabled

Since fenced frames share a renderer process with the embedding page:
1. A compromised fenced frame renderer can directly access the embedding page's DOM
2. Process isolation is the primary defense for fenced frames, and it's disabled
3. The fenced frame's information barrier is reduced to renderer-side checks

## Impact

- **No compromised renderer required** (for focus probing): Can attempt focus changes and observe timing
- **Compromised renderer required** (for full bypass): Process sharing defeats the isolation boundary
- **Privacy violation**: Fenced frames are meant to be opaque to embedding pages
- **Known issue**: TODO at crbug.com/40274134 acknowledges enforcement is pending

## VRP Value

**Medium** — Fenced frames are a key Privacy Sandbox primitive. Both focus enforcement and process isolation being disabled significantly weakens their privacy guarantees. The focus enforcement gap is particularly concerning for click-jacking and interaction fingerprinting.
