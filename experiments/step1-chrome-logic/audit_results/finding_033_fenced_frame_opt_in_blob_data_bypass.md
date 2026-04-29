# Finding 033: Fenced Frame Supports-Loading-Mode Opt-In Bypassed by blob:/data: URLs

## Summary

The `Supports-Loading-Mode: fenced-frame` header requirement for content loaded inside fenced frames is completely bypassed for blob: and data: URLs. This means arbitrary content can be loaded into a fenced frame (which normally requires the server's explicit opt-in) by constructing blob: or data: URLs.

## Affected Files

- `content/browser/renderer_host/navigation_request.cc:4913-4916` — Opt-in enforcement skipped for blob/data URLs

## Details

```cpp
// navigation_request.cc:4913-4916
const bool should_enforce_fenced_frame_opt_in =
    response_head_->headers && frame_tree_node_->IsInFencedFrameTree() &&
    !(url.IsAboutBlank() || url.SchemeIsBlob() ||
      url.SchemeIs(url::kDataScheme));
```

The fenced frame opt-in mechanism requires content loaded inside fenced frames to explicitly declare via HTTP header that it consents to being loaded in a fenced frame. This is a consent mechanism designed to ensure that only cooperating origins serve content inside the privacy-restricted fenced frame context.

However, blob: and data: URLs are unconditionally exempted from this check. This means:
1. Any JavaScript context that can navigate a fenced frame can load arbitrary content via data: URL without the target content ever opting in
2. A blob: URL created by the page can be loaded into a fenced frame without opt-in

## Attack Scenario

1. A page creates a fenced frame (from FLEDGE/Protected Audiences auction)
2. The winning ad has a URL that opts in via `Supports-Loading-Mode: fenced-frame`
3. JavaScript within the fenced frame can navigate itself to a data: URL:
   ```javascript
   window.location = 'data:text/html,<script>/* arbitrary code running in fenced frame context */</script>';
   ```
4. The data: URL content runs inside the fenced frame without ever having opted in

## Impact

- The opt-in bypass itself is Low severity since fenced frame restrictions (storage nonce, etc.) still apply regardless of the header
- The main concern is that the opt-in mechanism's purpose — ensuring content explicitly consents to the restricted fenced frame environment — is undermined
- Content loaded via data:/blob: URLs inherits fenced frame restrictions but was never asked to consent to them

## VRP Value

**Low** — The opt-in header is more of a consent mechanism than a security boundary. Fenced frame privacy restrictions (nonce-based StorageKey, etc.) still apply. The blob/data exemption is likely intentional for same-origin content loading within fenced frames.
