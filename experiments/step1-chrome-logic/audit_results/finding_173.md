# Finding 173: Prefetch Cookie-Level Validation (kPrefetchCookieIndices) Disabled by Default Allows Stale Content Serving

## Summary
The `kPrefetchCookieIndices` feature (DISABLED_BY_DEFAULT) would, when enabled, validate that the cookies at serving time match the cookies that were present at prefetch time. When disabled (the default), prefetched responses are served without any cookie-value-level validation. The only check is whether the `PrefetchCookieListener` detected any cookie changes since the prefetch was made. However, the cookie listener only monitors the default network context's cookies using `AddCookieChangeListener`, which has known gaps: (1) it only monitors host/domain cookies for the specific URL (not broader domain cookies that would affect the request), (2) it can miss changes during the pause window (see finding 166), and (3) it uses the default cookie manager which may not reflect partitioned cookie changes (see finding 165). With `kPrefetchCookieIndices` disabled, there is no positive validation that the cookies are still correct at serving time.

## Affected Files
- `content/common/features.cc` (line 556) - `kPrefetchCookieIndices` DISABLED_BY_DEFAULT
- `content/browser/preloading/prefetch/prefetch_serving_handle.cc` (lines 291-314) - Feature-gated validation
- `content/browser/preloading/prefetch/prefetch_serving_handle.cc` (lines 421-463) - Cookie validation flow

## Details
```cpp
// features.cc:556
BASE_FEATURE(kPrefetchCookieIndices, base::FEATURE_DISABLED_BY_DEFAULT);
```

```cpp
// prefetch_serving_handle.cc:291-314
if (base::FeatureList::IsEnabled(features::kPrefetchCookieIndices)) {
  if (!state->cookies_matched.has_value()) {
    // ... fetch cookies and validate
  }
  CHECK(state->cookies_matched.has_value());
  if (!state->cookies_matched.value()) {
    // Cookies did not match, but needed to. We're done here.
    std::move(state->callback).Run({});
    return;
  }
}
// When disabled: NO cookie validation happens here
```

Without `kPrefetchCookieIndices`:
1. The only protection is the `PrefetchCookieListener` which sets a boolean `have_cookies_changed_` flag
2. If the listener misses a change (due to pause, CHIPS gap, or URL-level vs domain-level mismatch), the stale prefetch is served
3. There is no positive confirmation that the cookie state matches before serving

With `kPrefetchCookieIndices` enabled:
1. At serving time, the current cookies for the URL are fetched from the default cookie manager
2. The cookie names and values are compared against the "cookie indices" stored during the prefetch
3. If there is a mismatch, the prefetch is not served

The gap when disabled means:
- User logs in to a site (sets session cookie) -> prefetch was made before login -> stale logged-out content served
- Server rotates CSRF token cookie -> prefetch has old token -> form submissions may fail
- Partitioned cookies change but listener doesn't see them -> stale content served

## Attack Scenario
1. User visits `https://referring.com` which prefetches `https://target.com/dashboard`
2. At prefetch time, user has no session cookie for `target.com`
3. The prefetch returns the logged-out dashboard page
4. User then opens a new tab and logs into `target.com` (setting a session cookie)
5. The `PrefetchCookieListener` detects the cookie change and marks the prefetch as having changed cookies
6. This part works correctly. But consider the alternative:
7. User's session cookie for `target.com` is a **partitioned cookie** (CHIPS), set with `Partitioned` attribute
8. The `PrefetchCookieListener` registers with `AddCookieChangeListener(url)` on the default cookie manager
9. Partitioned cookie changes may not trigger the listener (since they use partition keys)
10. Without `kPrefetchCookieIndices`, there is no backup validation
11. The stale, logged-out prefetch is served to the user even though they are now logged in

## Impact
Low-Medium - The existing cookie listener provides some protection, but the disabled cookie indices feature represents a more robust defense that is currently not active. The gap primarily affects edge cases involving CHIPS partitioned cookies and the pause-window race condition.

## VRP Value
Low
