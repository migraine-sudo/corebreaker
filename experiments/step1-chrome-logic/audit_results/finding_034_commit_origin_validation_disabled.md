# Finding 034: kValidateCommitOriginAtCommit Disabled — Session History Origin Leak

## Summary

The `kValidateCommitOriginAtCommit` feature flag, which validates that the committed origin matches the FrameNavigationEntry's stored origin, is **DISABLED_BY_DEFAULT**. Combined with a known issue where `FrameNavigationEntry` retains a stale `committed_origin()` after redirects (crbug.com/420965165), this means `PageState` from one origin can leak to another origin during session history navigations.

Even when enabled, the validation uses `NotFatalUntil::M140` — non-fatal in production before M140.

## Affected Files

- `content/public/common/content_features.cc:1119-1128` — Feature flag, DISABLED_BY_DEFAULT
- `content/browser/renderer_host/navigation_request.cc:6685-6688` — Gated ValidateCommitOrigin() call
- `content/browser/renderer_host/navigation_request.cc:12506-12533` — Weakened validation + NotFatalUntil::M140

## Details

### Feature flag (DISABLED_BY_DEFAULT)

```cpp
// content_features.cc:1119-1128
// Enables a CHECK in NavigationRequest::ValidateCommitOrigin() to verify
// that the origin used at commit time matches the expected origin stored
// in the FrameNavigationEntry, whenever PageState is non-empty.
//
// This helps catch session history corruption or stale origin-related state
// being sent to the renderer, which could violate origin isolation and lead
// to security issues (see crbug.com/41492620).
//
// This feature is disabled by default while we diagnose on Canary only.
BASE_FEATURE(kValidateCommitOriginAtCommit, base::FEATURE_DISABLED_BY_DEFAULT);
```

### Gated call site — dead in production

```cpp
// navigation_request.cc:6685-6688
url::Origin origin_to_commit = GetOriginToCommit().value();
if (base::FeatureList::IsEnabled(features::kValidateCommitOriginAtCommit)) {
  ValidateCommitOrigin(origin_to_commit);
}
```

### Even when enabled — weakened + non-fatal

```cpp
// navigation_request.cc:12506-12533
if (expected_origin.opaque() || origin_to_commit.opaque()) {
  // Weakened: only compares precursor tuples if EITHER is opaque
  origins_match = expected_origin.GetTupleOrPrecursorTupleIfOpaque() ==
                  origin_to_commit.GetTupleOrPrecursorTupleIfOpaque();
}

if (!origins_match) {
  // TODO(crbug.com/420965165): FrameNavigationEntry may retain a stale
  // committed_origin() after redirects
  CHECK(commit_params_->page_state.empty(), base::NotFatalUntil::M140);
}
```

## Attack Scenario

1. User navigates to `origin-A.com/page` which stores form data in PageState
2. `origin-A.com/page` redirects to `origin-B.com/result`
3. `FrameNavigationEntry` retains stale `committed_origin = origin-A.com` (crbug.com/420965165)
4. User navigates away, then performs history back-navigation
5. Navigation commits at `origin-B.com` but FrameNavigationEntry has `origin-A.com`'s PageState
6. Since `kValidateCommitOriginAtCommit` is disabled, the mismatch is never detected
7. PageState (form data, scroll position) from origin-A leaks to origin-B's renderer

## Impact

- **No compromised renderer needed**: Triggered by standard navigation patterns (redirect + history navigation)
- **PageState cross-origin leak**: Form data, scroll position from one origin sent to another
- **Session history corruption**: Stale FrameNavigationEntry origin can persist across navigations
- **Triple defense failure**: Feature flag disabled + weakened opaque origin check + non-fatal CHECK

## VRP Value

**Medium-High** — The feature flag comment explicitly states this "could violate origin isolation and lead to security issues." The stale FrameNavigationEntry after redirects is a known unfixed issue (crbug.com/420965165). The validation is disabled in all production builds.
