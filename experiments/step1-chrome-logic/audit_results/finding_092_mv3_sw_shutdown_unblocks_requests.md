# Finding 092: MV3 Service Worker Shutdown Silently Unblocks All Pending Requests

## Summary

When a MV3 extension's service worker is shut down (e.g., hits the 5-minute hard lifetime timeout), ALL requests it was blocking via webRequest are automatically unblocked with no response. This silently breaks the blocking guarantee of security/filtering extensions.

## Affected Files

- `extensions/browser/api/web_request/extension_web_request_event_router.cc:2185-2195` — Unblock on deactivation

## Details

```cpp
// extension_web_request_event_router.cc:2185-2195
  // Unblock any request that this event listener may have been blocking.
  // Note that we do this even for deactivations, since if the service worker
  // is shut down (which would happen if it reached the hard lifetime timeout),
  // it won't be able to respond to the request.
  // TODO(crbug.com/40107353): This likely won't be sufficient, since it
  // means requests can leak through.
  for (uint64_t blocked_request_id : listener.blocked_requests) {
    DecrementBlockCount(..., blocked_request_id, nullptr, 0);
  }
```

## Attack Scenario

1. Security extension (parental controls, content filter) blocks malicious requests
2. Attacker's page makes many long-running requests to keep the SW busy
3. Extension's service worker hits the 5-minute hard lifetime timeout
4. ALL pending blocked requests are silently allowed through
5. Malicious content loads despite the extension's intent to block it

## Impact

- **No compromised renderer required**: Standard web page behavior
- **Filtering bypass**: Content filtering and security extensions become unreliable
- **Known issue**: crbug.com/40107353
- **MV3 design limitation**: Fundamental conflict between SW lifecycle and request blocking

## VRP Value

**Medium** — Breaks the security guarantee of blocking extensions. Users relying on ad-blockers or parental controls are vulnerable.
