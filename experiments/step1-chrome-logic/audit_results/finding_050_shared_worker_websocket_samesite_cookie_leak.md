# Finding 050: SharedWorker WebSocket Sends SameSite Cookies in Cross-Site Context (kRestrictSharedWorkerWebSocketCrossSiteCookies Disabled)

## Summary

When a SharedWorker is created in a third-party context (e.g., via the Storage Access API), WebSocket connections from that worker incorrectly attach `SameSite=Strict` and `SameSite=Lax` cookies to the handshake. The fix is gated behind `kRestrictSharedWorkerWebSocketCrossSiteCookies`, which is `FEATURE_DISABLED_BY_DEFAULT`. This allows cross-site cookie exfiltration via SharedWorker WebSockets.

## Affected Files

- `content/browser/worker_host/shared_worker_host.cc:710-724` — Cookie restriction disabled
- `content/common/features.cc` — kRestrictSharedWorkerWebSocketCrossSiteCookies DISABLED

## Details

### The disabled restriction

```cpp
// shared_worker_host.cc:710-724
if (instance_.DoesRequireCrossSiteRequestForCookies()) {
  if (base::FeatureList::IsEnabled(
          features::kRestrictSharedWorkerWebSocketCrossSiteCookies)) {
    // If the worker requires cross-site cookie semantics, we must
    // ensure that the SiteForCookies is null. This prevents the network
    // service from incorrectly attaching SameSite=Strict/Lax cookies.
    isolation_info = net::IsolationInfo::Create(
        isolation_info.request_type(), *isolation_info.top_frame_origin(),
        *isolation_info.frame_origin(), net::SiteForCookies(),
        isolation_info.nonce());
  }
}
```

When disabled (default), `SiteForCookies` is not nullified for cross-site SharedWorker WebSockets. The network service sees a valid `SiteForCookies` and attaches SameSite cookies.

## Attack Scenario

### SameSite cookie exfiltration via SharedWorker WebSocket

1. `evil.example` creates a SharedWorker in a third-party context (e.g., embedded as iframe on `target.example`)
2. The SharedWorker opens a WebSocket connection to `target.example`
3. **Expected**: SameSite=Strict/Lax cookies should NOT be sent (cross-site context)
4. **Actual**: SameSite cookies ARE sent because `SiteForCookies` is not nullified
5. `evil.example`'s WebSocket server at `target.example` (or via DNS rebinding to `target.example`) receives the SameSite cookies
6. This can include session tokens, CSRF tokens, and other sensitive cookies

### Storage Access API amplification

1. Site gets storage access via the Storage Access API
2. Creates SharedWorker in the third-party context
3. SharedWorker WebSocket bypasses SameSite cookie restrictions
4. Full cookie jar (including SameSite=Strict) available to the cross-site WebSocket

## Impact

- **No compromised renderer required**: Standard JavaScript APIs
- **Cookie policy bypass**: SameSite=Strict/Lax cookies sent cross-site
- **Session hijacking potential**: If session cookies are SameSite=Lax (default), they leak
- **CSRF amplification**: SameSite CSRF protection bypassed

## VRP Value

**Medium-High** — No renderer compromise needed. Exploitable via standard APIs. Bypasses SameSite cookie protections which are a fundamental web security mechanism. The UMA metric logging shows Chrome is aware of the issue.
