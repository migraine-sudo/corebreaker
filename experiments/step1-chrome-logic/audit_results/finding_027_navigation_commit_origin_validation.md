# Finding 027: Commit Origin Validation Disabled by Default

## Summary

The feature `kValidateCommitOriginAtCommit` (content_features.cc:1128) is `FEATURE_DISABLED_BY_DEFAULT`. This means session history corruption (stale origin in FrameNavigationEntry) goes undetected in production. A history navigation could deliver PageState (serialized DOM, form data, scroll position) to a wrong-origin document.

## Affected Files

- `content/public/common/content_features.cc:1128` — Feature definition (DISABLED_BY_DEFAULT)
- `content/browser/renderer_host/navigation_request.cc:6686-6688` — Feature check gating call
- `content/browser/renderer_host/navigation_request.cc:12490-12535` — ValidateCommitOrigin implementation
- `content/browser/renderer_host/navigation_controller_impl.cc:2876-2888` — Subframe origin check limited to HTTP(S)

## Details

### Feature disabled

```cpp
// content_features.cc:1128
BASE_FEATURE(kValidateCommitOriginAtCommit, base::FEATURE_DISABLED_BY_DEFAULT);
```

### Weakened check even when enabled

```cpp
// navigation_request.cc:12506-12515
// Current weakened check: allows precursor tuple comparison if *either*
// origin is opaque. This is a temporary workaround because sandbox
// navigations do not currently clear PageState properly.
if (expected_origin.opaque() || origin_to_commit.opaque()) {
    origins_match = expected_origin.GetTupleOrPrecursorTupleIfOpaque() ==
                    origin_to_commit.GetTupleOrPrecursorTupleIfOpaque();
}
```

Two distinct opaque origins (from different sandboxed iframes) with the same precursor pass this check, allowing potential PageState cross-contamination.

### Subframe history origin check excludes non-HTTP(S)

```cpp
// navigation_controller_impl.cc:2883-2886
if (current_top_url.SchemeIsHTTPOrHTTPS() &&
    dest_top_url.SchemeIsHTTPOrHTTPS() &&
    current_top_url.DeprecatedGetOriginAsURL() !=
        dest_top_url.DeprecatedGetOriginAsURL()) {
    bad_message::ReceivedBadMessage(...);
}
```

file:, about:blank, and opaque origins are excluded from this check.

## Impact

- Session history corruption could deliver serialized PageState to wrong-origin documents
- Not exploitable without corrupted history state OR redirect/CSP edge cases (see crbug.com/420965165)
- Compromised renderer NOT required for the history corruption itself

## VRP Value

**Low** — Chromium team is actively working on this:
- Feature exists but is disabled pending bug fixes (crbug.com/421948889)
- CHECK at line 12530 has `base::NotFatalUntil::M140`
- Multiple crbug references indicate active tracking
- Practical exploitation would require triggering FrameNavigationEntry corruption first

## Chromium Awareness

Fully known — explicit feature flag, TODO comments, and multiple crbug references.
