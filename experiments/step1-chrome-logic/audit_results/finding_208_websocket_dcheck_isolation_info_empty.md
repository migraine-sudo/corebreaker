# Finding 208: WebSocket IsolationInfo Emptiness Check is DCHECK-Only (Stripped in Release)

## Summary

In `WebSocketFactory::CreateWebSocket`, the check that `isolation_info` is not empty when `require_network_anonymization_key` is enabled is performed with `DCHECK` instead of `CHECK`. DCHECK is stripped from release builds, meaning a compromised or buggy renderer could provide an empty `IsolationInfo` in production Chrome without being detected. An empty `IsolationInfo` means network requests would lack proper partitioning, potentially enabling cross-site tracking or cache-based side channels.

## Affected Files

- `services/network/websocket_factory.cc` line 117:
  ```cpp
  if (context_->require_network_anonymization_key()) {
    DCHECK(!isolation_info.IsEmpty());
  }
  ```

## Code Snippet

```cpp
// services/network/websocket_factory.cc:115-118
  // If `require_network_anonymization_key` is set, `isolation_info` must not be
  // empty.
  if (context_->require_network_anonymization_key()) {
    DCHECK(!isolation_info.IsEmpty());  // STRIPPED IN RELEASE
  }
```

## Attack Scenario

1. A compromised renderer sends a `CreateWebSocket` mojo message with an empty `IsolationInfo`
2. In release builds, the DCHECK is stripped, so the empty `IsolationInfo` passes through
3. The WebSocket connection is created without proper network partitioning
4. This could allow cross-site tracking via WebSocket connections that share state (connection pooling, auth cache) across different origins
5. If `require_network_anonymization_key` is true (which it typically is in modern Chrome), this represents a real network partitioning bypass

The check should be:
```cpp
if (context_->require_network_anonymization_key() && isolation_info.IsEmpty()) {
  mojo::ReportBadMessage("WebSocket's IsolationInfo must not be empty when NAK is required");
  return;
}
```

## Impact

- **Severity**: Medium-High (network partitioning bypass)
- **Requires compromised renderer**: Yes
- **Security principle violated**: Security checks should not be debug-only
- Network partitioning (site isolation for network state) is a core privacy/security feature
- An empty IsolationInfo means the WebSocket operates in a "first-party" context regardless of actual embedding

## VRP Value Rating

Medium-High - Chrome VRP has paid for DCHECK-guarded security checks that should be CHECK or `mojo::ReportBadMessage`. Network partitioning bypass through WebSocket is a significant privacy concern that affects cross-site tracking protection.
