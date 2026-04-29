# Finding 070: Fenced Frame Config Leaks Parent Permissions and Origin to Cross-Origin Content

## Summary

When a `FencedFrameConfig` or `FencedFrameProperties` is redacted for cross-origin content inside the fenced frame, the `effective_enabled_permissions_` and `parent_permissions_info_` fields are copied directly without redaction. This leaks the parent's permissions policy declarations and origin to content inside the fenced frame, violating the fenced frame's privacy guarantee.

## Affected Files

- `content/browser/fenced_frame/fenced_frame_config.cc:182-185` — Config redaction
- `content/browser/fenced_frame/fenced_frame_config.cc:304-307` — Properties redaction

## Details

```cpp
// fenced_frame_config.cc:182-185 (RedactFor method)
redacted_config.effective_enabled_permissions_ =
    effective_enabled_permissions_;
redacted_config.parent_permissions_info_ = parent_permissions_info_;
```

```cpp
// fenced_frame_config.cc:304-307 (Properties RedactFor method)
// Same pattern - copied without redaction regardless of entity type
```

The `RedactFor()` method takes an `entity` parameter (`kEmbedder`, `kSameOriginContent`, `kCrossOriginContent`) and selectively redacts fields based on who should see them. However, `effective_enabled_permissions_` and `parent_permissions_info_` are always copied in full.

`parent_permissions_info_` includes:
- The parent frame's **origin** (identifies the embedding site)
- The parent frame's **permissions policy declarations** (reveals which APIs the embedder uses)

## Attack Scenario

### Cross-site identity leak in privacy-preserving ads

1. `https://advertiser.example` runs a Protected Audience auction
2. The winning ad loads in a fenced frame at `https://ad-cdn.example/ad.html`
3. The ad content (cross-origin to the embedder) reads `parent_permissions_info_`
4. This reveals `https://advertiser.example` as the embedding origin
5. The ad now knows which site it's displayed on, defeating the purpose of fenced frames

### Permissions policy fingerprinting

1. The same ad loads on different sites
2. Each site has different permissions policy declarations (e.g., `camera`, `microphone`, `geolocation`)
3. The ad reads the parent's permissions policy from the unredacted field
4. This creates a fingerprint of the embedding site, enabling cross-site tracking

## Impact

- **No compromised renderer required**: The unredacted data is sent to the renderer in normal operation
- **Privacy violation**: Fenced frames are specifically designed to prevent information flow from embedder to content
- **Cross-site tracking**: Knowing the embedding origin is the exact information fenced frames are supposed to hide
- **Affects Protected Audience and Shared Storage**: Both privacy-sensitive APIs create fenced frames

## VRP Value

**Medium** — Privacy information leak in a privacy-preserving feature. The embedding origin is high-value information for cross-site tracking, and the whole point of fenced frames is to prevent this leak.
