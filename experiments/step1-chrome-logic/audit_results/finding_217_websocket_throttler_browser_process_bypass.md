# Finding 217: WebSocket Throttler Completely Bypassed for Browser-Process-Originated Connections

## Summary

The `WebSocketThrottler` completely bypasses all throttling for connections where `process_id.is_browser()` returns true. This means:
1. `HasTooManyPendingConnections` returns false (no connection limit)
2. `CalculateDelay` returns zero (no delay)
3. `IssuePendingConnectionTracker` returns `std::nullopt` (no tracking)

Browser-process-originated WebSocket connections include those from extensions with `chrome.webRequest` or similar APIs, internal Chrome features, and potentially any code path that creates WebSocket connections from the browser process. These connections have no throttling at all -- no connection count limit and no delay-based rate limiting.

## Affected Files

- `services/network/websocket_throttler.cc` lines 81-98:
  ```cpp
  bool WebSocketThrottler::HasTooManyPendingConnections(
      const network::OriginatingProcessId& process_id) const {
    if (process_id.is_browser()) {
      return false;  // No limit for browser process
    }
    // ...
  }

  base::TimeDelta WebSocketThrottler::CalculateDelay(
      const network::OriginatingProcessId& process_id) const {
    if (process_id.is_browser()) {
      return base::TimeDelta();  // No delay for browser process
    }
    // ...
  }
  ```
- `services/network/websocket_throttler.cc` lines 107-114:
  ```cpp
  std::optional<WebSocketThrottler::PendingConnection>
  WebSocketThrottler::IssuePendingConnectionTracker(
      const network::OriginatingProcessId& process_id) {
    if (process_id.is_browser()) {
      return std::nullopt;  // No tracking for browser process
    }
    // ...
  }
  ```

## Code Snippet

```cpp
// websocket_throttler.cc:81-86
bool WebSocketThrottler::HasTooManyPendingConnections(
    const network::OriginatingProcessId& process_id) const {
  if (process_id.is_browser()) {
    return false;  // ALWAYS returns false - no limit
  }
  auto it = per_process_throttlers_.find(process_id.renderer_process_id());
  // ...
}
```

## Attack Scenario

1. A Chrome extension (or internal feature) opens WebSocket connections from the browser process
2. These connections bypass all throttling checks
3. A malicious extension could open thousands of WebSocket connections simultaneously without any rate limiting
4. This could be used for:
   - Port scanning of local network resources at high speed
   - DDoS amplification through many simultaneous WebSocket connections
   - Resource exhaustion on the network service

For extensions specifically:
1. Extensions with `webRequest` permission can intercept and modify WebSocket handshakes
2. The `ContentBrowserClient::CreateWebSocket` path creates WebSocket connections from the browser process context
3. These connections have zero throttling overhead

## Impact

- **Severity**: Low (requires extension or browser-process code path)
- **Requires compromised renderer**: No (extension API usage)
- **Security principle violated**: All network connections should have some form of rate limiting
- The browser process bypass is intentional for internal Chrome features, but extensions abuse this

## VRP Value Rating

Low - The browser-process bypass is a design decision, not a bug. However, extensions that create WebSocket connections inherit this bypass, which may not be intended. This is more of a hardening recommendation than a directly exploitable vulnerability.
