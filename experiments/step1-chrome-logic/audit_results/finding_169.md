# Finding 169: WebView Prerender Activation Relaxes Initiator Origin, Transition Type, and X-Header Checks

## Summary
The prerender activation compatibility check in `PrerenderHost::AreInitialPrerenderNavigationParamsCompatibleWithNavigation()` consults `ShouldAllowPartialParamMismatchOfPrerender2()` to relax multiple security-relevant checks on Android WebView. When `allow_partial_mismatch` is true, the following checks are skipped: (1) `initiator_frame_token` comparison, (2) `initiator_origin` comparison, (3) page transition type comparison, and (4) all `X-` prefixed HTTP headers. This means a prerender initiated by one origin can be activated by a navigation from a completely different origin in WebView.

## Affected Files
- `content/browser/preloading/prerender/prerender_host.cc` (lines 1055-1057) - `allow_partial_mismatch` delegation to WebContents
- `content/browser/preloading/prerender/prerender_host.cc` (lines 1111-1113) - Initiator frame token skip
- `content/browser/preloading/prerender/prerender_host.cc` (lines 1245-1248) - Initiator origin skip
- `content/browser/preloading/prerender/prerender_host.cc` (lines 1256-1261) - Transition type skip
- `content/browser/preloading/prerender/prerender_host.cc` (lines 421-439) - X-header mismatch skip

## Details
```cpp
// prerender_host.cc:1052-1057
// Relaxes checks for initiator, transition type, and headers. This logic is
// intended to be used for WebView, as WebView is intended to host
// embedder-trusted contests.
bool allow_partial_mismatch =
    web_contents_->GetDelegate()->ShouldAllowPartialParamMismatchOfPrerender2(
        navigation_request);
```

```cpp
// prerender_host.cc:1111-1113
if (!allow_partial_mismatch && (potential_activation.initiator_frame_token !=
                                begin_params_->initiator_frame_token)) {
  return ActivationNavigationParamsMatch::kInitiatorFrameToken;
}
```

```cpp
// prerender_host.cc:1245-1248
if (!allow_partial_mismatch && (potential_activation.initiator_origin !=
                                common_params_->initiator_origin)) {
  return ActivationNavigationParamsMatch::kInitiatorOrigin;
}
```

```cpp
// prerender_host.cc:421-439 - X-header stripping
if (allow_x_header_mismatch) {
  absl::flat_hash_set<std::string> headers_to_be_removed;
  for (net::HttpRequestHeaders::Iterator it(prerender_headers); it.GetNext();) {
    if (it.name().starts_with("X-") || it.name().starts_with("x-")) {
      headers_to_be_removed.insert(it.name());
    }
  }
  ...
}
```

When all these checks are skipped simultaneously:
- A prerender initiated by origin A can be activated by a navigation initiated by origin B
- The prerendered page's content was fetched in the context of origin A (with A's referrer, headers, etc.)
- But after activation, the navigation context switches to origin B's navigation
- Custom `X-` headers that may carry authentication tokens or session identifiers are not compared

## Attack Scenario
1. In an Android WebView app, the embedder uses prerendering for performance
2. The embedder navigates to `https://app-backend.com/dashboard` which prerenders `https://app-backend.com/settings`
3. The prerender request includes `X-Auth-Token: user_abc_token` from the embedder
4. Later, a different in-app navigation (from a different initiator origin or with different `X-Auth-Token`) navigates to `https://app-backend.com/settings`
5. Because `allow_partial_mismatch` is true, the activation proceeds despite the initiator origin and X-header differences
6. The user sees content fetched with user_abc's auth token, even though the activation navigation may have been for a different user or context
7. The X-header mismatch means security-relevant headers like `X-CSRF-Token` or `X-Auth-Token` are not validated

## Impact
Low-Medium - Limited to Android WebView which is described as hosting "embedder-trusted" content. However, the simultaneous relaxation of initiator origin, transition type, and custom authentication headers creates a risk of content mismatch if the WebView hosts multi-tenant or context-switching scenarios.

## VRP Value
Low
