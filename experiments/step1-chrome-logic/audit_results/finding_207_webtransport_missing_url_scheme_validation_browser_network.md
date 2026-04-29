# Finding 207: WebTransport Missing URL Scheme Validation at Browser/Network Service Boundary

## Summary

WebTransport URL scheme validation ("https" only) is performed exclusively in the Blink renderer via `url_.ProtocolIs("https")`. Neither the browser-process `WebTransportConnectorImpl::Connect` nor the network-service `NetworkContext::CreateWebTransport` validate the URL scheme before creating a WebTransport session. By contrast, the WebSocket path validates `url.SchemeIsWSOrWSS()` at the network service boundary in `WebSocketFactory::CreateWebSocket` (line 104) and calls `mojo::ReportBadMessage("Invalid scheme.")` if it fails.

This means the defense-in-depth principle is violated: a compromised renderer could bypass the Blink-side check and send arbitrary URL schemes to the network service for WebTransport connections. While `net::CreateWebTransportClient` at the lowest layer does reject non-HTTPS schemes with `ERR_UNKNOWN_URL_SCHEME`, this defense is at the wrong layer -- it should be at the mojo boundary with `mojo::ReportBadMessage()` to kill the compromised renderer.

## Affected Files

- `content/browser/webtransport/web_transport_connector_impl.cc` lines 177-215 (`Connect` method)
  - No URL scheme validation at all
- `services/network/network_context.cc` lines 2094-2119 (`CreateWebTransport` method)
  - No URL scheme validation, no `mojo::ReportBadMessage()`
- Contrast with `services/network/websocket_factory.cc` lines 104-106:
  ```cpp
  if (!url.SchemeIsWSOrWSS()) {
    mojo::ReportBadMessage("Invalid scheme.");
    return;
  }
  ```
- `net/quic/web_transport_client.cc` lines 89-99 (lowest-layer validation)

## Code Snippet

```cpp
// services/network/network_context.cc:2094
void NetworkContext::CreateWebTransport(
    const GURL& url,
    const url::Origin& origin,
    const net::NetworkAnonymizationKey& key,
    ...) {
  // NOTE: No scheme validation here, unlike WebSocket
  if (!IsNetworkForNonceAndUrlAllowed(
          key.GetNonce().value_or(base::UnguessableToken::Null()), url, key)) {
    ...
    return;
  }
  web_transports_.insert(std::make_unique<WebTransport>(
      url, origin, key, fingerprints, ...));
}
```

## Attack Scenario

1. Attacker compromises a renderer process (e.g., via a separate renderer exploit)
2. Attacker directly calls `NetworkContext::CreateWebTransport` with a non-HTTPS URL (e.g., `http://internal-server:8080/`)
3. The browser process and network service accept the request without killing the compromised renderer
4. While the connection ultimately fails at the `net/` layer, the compromised renderer is not terminated, allowing it to continue operating and attempting other attacks
5. A proper `mojo::ReportBadMessage()` would terminate the compromised renderer process immediately

Without the `ReportBadMessage` call, the network service also wastes resources processing the invalid request before the failure at the net layer.

## Impact

- **Severity**: Medium (defense-in-depth violation)
- **Requires compromised renderer**: Yes, for direct exploitation
- **Without compromised renderer**: Not directly exploitable since Blink enforces HTTPS
- **Security principle violated**: Mojo interface security -- privileged services should validate inputs from less-privileged processes at the boundary
- The discrepancy with WebSocket's validation makes this an inconsistency in the security model

## VRP Value Rating

Medium - Defense-in-depth issue. Chrome VRP has historically paid for missing browser/network service input validation even when renderer-side checks exist, as these constitute a weakening of the security boundary. The comparable WebSocket validation makes the omission clearly unintentional.
