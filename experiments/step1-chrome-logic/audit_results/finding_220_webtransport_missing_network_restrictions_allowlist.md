# Finding 220: WebTransport Missing Connection Allowlist (network_restrictions_id) Enforcement

## Summary

WebSocket connections enforce Connection Allowlist restrictions via the `network_restrictions_id` parameter, which limits which URLs can be connected to from restricted contexts (e.g., fenced frames with `disableUntrustedNetwork`). WebTransport has NO equivalent enforcement -- the `CreateWebTransport` mojom interface does not accept a `network_restrictions_id` parameter, and the network context implementation does not check it.

This means that in a context where WebSocket connections are restricted by an allowlist (fenced frames), WebTransport connections bypass those restrictions entirely. A web page in a fenced frame that has its untrusted network disabled can still create WebTransport connections to arbitrary servers.

## Affected Files

- `services/network/public/mojom/network_context.mojom` lines 1493-1503:
  - `CreateWebTransport` has NO `network_restrictions_id` parameter
  - Compare with `CreateWebSocket` (line 1484) which has `network_restrictions_id`
- `services/network/network_context.cc` lines 2094-2119:
  - `CreateWebTransport` only checks nonce-based revocation, NOT allowlist restrictions
- `services/network/websocket_factory.cc` lines 143-153:
  - WebSocket DOES check allowlist:
  ```cpp
  if (network_restrictions_id.has_value() &&
      !context_->IsNetworkForNonceAndUrlAllowed(
          *network_restrictions_id, net::ChangeWebSocketSchemeToHttpScheme(url),
          isolation_info.network_anonymization_key())) {
    // ... fails connection
  }
  ```
- `content/browser/webtransport/web_transport_connector_impl.cc`:
  - No `network_restrictions_id` handling in the connector

## Code Snippet

```cpp
// WebSocket (websocket_factory.cc:143-153) - HAS restriction check:
if (network_restrictions_id.has_value() &&
    !context_->IsNetworkForNonceAndUrlAllowed(
        *network_restrictions_id, net::ChangeWebSocketSchemeToHttpScheme(url),
        isolation_info.network_anonymization_key())) {
  handshake_client_remote->OnFailure("Network access revoked",
                                     net::ERR_NETWORK_ACCESS_REVOKED, -1);
  return;
}

// WebTransport (network_context.cc:2094-2119) - MISSING restriction check:
void NetworkContext::CreateWebTransport(
    const GURL& url, ...) {
  // Only checks nonce-based revocation, NOT allowlist restrictions
  if (!IsNetworkForNonceAndUrlAllowed(
          key.GetNonce().value_or(base::UnguessableToken::Null()), url, key)) {
    // ...
  }
  // No network_restrictions_id check at all!
  web_transports_.insert(std::make_unique<WebTransport>(...));
}
```

## Attack Scenario

1. A page creates a fenced frame with `disableUntrustedNetwork` API enabled
2. The fenced frame has network restrictions enforced via `network_restrictions_id`
3. WebSocket connections from the fenced frame are properly blocked if the URL is not on the allowlist
4. However, the fenced frame creates a WebTransport connection to an arbitrary HTTPS server
5. The WebTransport connection bypasses the allowlist because `CreateWebTransport` has no `network_restrictions_id` parameter
6. Data can be exfiltrated from the fenced frame via WebTransport despite the network restrictions

This undermines the privacy guarantees of fenced frames, which are designed to prevent data exfiltration from restricted advertising contexts.

## Impact

- **Severity**: High (privacy/security bypass for fenced frame network restrictions)
- **Requires compromised renderer**: No -- standard web API usage from within a fenced frame
- **Security principle violated**: Consistent enforcement of network restrictions across protocols
- Undermines the `disableUntrustedNetwork` API privacy guarantees
- Fenced frames are a key component of the Privacy Sandbox initiative
- WebTransport over QUIC makes the exfiltration fast and bidirectional

## VRP Value Rating

High - This is a bypass of a security/privacy feature (fenced frame network restrictions) that does NOT require a compromised renderer. A restricted context that is supposed to have its network access limited can use WebTransport to bypass those restrictions. This is a gap in the security model rather than a renderer trust boundary issue, making it reportable under standard Chrome VRP criteria.
