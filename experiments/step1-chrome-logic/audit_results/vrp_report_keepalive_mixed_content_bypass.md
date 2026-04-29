# VRP Report: KeepAlive/fetchLater Mixed Content and CSP Bypass

## Title
Mixed content and CSP checks bypassed for keepalive/fetchLater redirect responses when initiator frame is gone

## Severity
High

## Component
Blink > Loader > KeepAlive

## Summary

Chrome's KeepAlive URL loader (used by `fetchLater()` and `fetch({keepalive: true})`) skips mixed content checks when processing redirect responses after the initiating frame has navigated away or closed. This is because the mixed content check in `keep_alive_url_loader.cc` line 1225 depends on `GetInitiator()` returning a valid RenderFrameHost, but keepalive requests are specifically designed to outlive their initiating frames.

Additionally, isolated world CSP (e.g., from extension content scripts) is not enforced for keepalive redirect targets (acknowledged TODO at line 199).

## Steps to Reproduce

### Mixed Content Bypass
1. Visit an HTTPS page with the following code:
```html
<script>
// Make a keepalive fetch that will redirect
fetch('https://example.com/redirect-to-http', { keepalive: true });
// Immediately navigate away
window.location = 'https://other-site.com';
</script>
```

2. Server at `https://example.com/redirect-to-http` responds with:
```
HTTP/1.1 302 Found
Location: http://insecure-target.com/receive-data
```

3. After navigation, the initiator frame is gone, `GetInitiator()` returns null
4. The mixed content check at line 1225 is skipped (the `rfh &&` guard is false)
5. The redirect to `http://insecure-target.com` proceeds

### fetchLater Amplification
```javascript
// fetchLater always fires after page unload — frame will ALWAYS be gone
fetchLater('https://example.com/redirect-to-http', { activateAfter: 0 });
```

## Root Cause

`content/browser/loader/keep_alive_url_loader.cc` lines 1222-1230:
```cpp
// TODO(crbug.com/40941240): Figure out how to check without a frame.
if (auto* rfh = GetInitiator();
    rfh && MixedContentChecker::ShouldBlockFetchKeepAlive(
               rfh, redirect_info.new_url, /*for_redirect=*/true)) {
    return net::ERR_FAILED;
}
```

The security check is conditioned on `rfh` being non-null, but for keepalive requests, the frame is frequently gone when redirects are processed.

## Impact

- HTTPS page can silently redirect keepalive requests to HTTP endpoints
- fetchLater() can always bypass mixed content since the frame is always gone when it fires
- Combined with local network mixed content bypass (separate bug), can reach internal services
- Extension content script CSP not enforced for keepalive redirects

## Affected Versions
Latest Chrome stable (tested against current chromium-src HEAD)
