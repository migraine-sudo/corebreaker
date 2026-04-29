# Finding 166: Cookie Listener Pause During Isolated Copy Creates Race Window for Missed Cookie Changes

## Summary
When a prefetch is being served and its isolated cookies are being copied to the default network context, `PrefetchCookieListener` is paused via `PauseListening()` to avoid treating the cookie copy as a real cookie change. However, the pause mechanism silently drops cookie change events that arrive during the pause window. If a real external cookie change (e.g., from another tab, a service worker, or an XHR response) occurs during this window, it is permanently lost. The listener resumes after the copy completes, but the missed change is never re-detected. This means a prefetch could be served to the user with stale content that does not match the current cookie state.

## Affected Files
- `content/browser/preloading/prefetch/prefetch_cookie_listener.cc` (lines 39-57) - Pause/resume and OnCookieChange
- `content/browser/preloading/prefetch/prefetch_single_redirect_hop.cc` (lines 138-160) - Pause on copy start
- `content/browser/preloading/prefetch/prefetch_single_redirect_hop.cc` (lines 234-253) - Resume on copy complete

## Details
```cpp
// prefetch_cookie_listener.cc:39-57
void PrefetchCookieListener::PauseListening() {
  should_pause_listening_ = true;
}

void PrefetchCookieListener::ResumeListening() {
  should_pause_listening_ = false;
}

void PrefetchCookieListener::OnCookieChange(
    const net::CookieChangeInfo& change) {
  if (!should_pause_listening_) {
    DCHECK(url_.DomainIs(change.cookie.DomainWithoutDot()));
    have_cookies_changed_ = true;

    // Once we record one change to the cookies associated with |url_|, we don't
    // care about any subsequent changes.
    TerminateListening();
  }
  // When paused: the change event is SILENTLY DROPPED
}
```

```cpp
// prefetch_single_redirect_hop.cc:138-160
void PrefetchSingleRedirectHop::OnIsolatedCookieCopyStart() {
  // We should temporarily ignore the cookie monitoring by
  // `PrefetchCookieListener` during the isolated cookie is written to the
  // default network context.
  prefetch_container_->PauseAllCookieListeners();
  cookie_copy_status_ = CookieCopyStatus::kInProgress;
  ...
}
```

The window between `PauseAllCookieListeners()` and `ResumeAllCookieListeners()` includes:
1. Reading all cookies from the isolated network context (async IPC to CookieManager)
2. Writing each cookie to the default network context (N async IPCs, one per cookie)
3. Waiting for all write callbacks via BarrierClosure

During this potentially non-trivial window, any real cookie changes from:
- Another tab making requests to the same domain
- A service worker processing events
- JavaScript from other origins setting cookies via subresource responses
...will be dropped and never flagged, causing the prefetch to be served as if cookies hadn't changed.

## Attack Scenario
1. User has tab A open at `https://target-site.com` and tab B at `https://referring-site.com`
2. Tab B prefetches `https://target-site.com/page` while user has no cookies for target-site
3. The prefetch completes and is stored in the isolated network context
4. User clicks a link in tab B to navigate to `target-site.com/page`
5. The serving flow starts: cookie copy from isolated context begins, pausing the listener
6. Concurrently, tab A's JavaScript sets a cookie for `target-site.com` (e.g., user logs in)
7. The cookie change event arrives at the paused listener and is silently dropped
8. Cookie copy completes, listener resumes, but the login cookie change was missed
9. The prefetch is served with the logged-out version of the page, even though the user just logged in
10. The user sees stale/incorrect content, and the prefetch's cookie state is now inconsistent with reality

## Impact
Low-Medium - This is primarily a correctness issue that could lead to serving stale prefetched content after a concurrent cookie change. The timing window is relatively short but non-zero and increases with the number of cookies being copied. The security impact is limited since the served content was legitimately fetched earlier, but it violates the invariant that prefetch serving should respect current cookie state.

## VRP Value
Low
