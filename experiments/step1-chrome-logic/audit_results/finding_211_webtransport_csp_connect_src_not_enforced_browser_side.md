# Finding 211: CSP connect-src Not Enforced Browser-Side for WebTransport/WebSocket Connections

## Summary

Content Security Policy (CSP) `connect-src` directive enforcement for both WebTransport and WebSocket happens exclusively in the Blink renderer, not in the browser process or network service. The browser-process `WebTransportConnectorImpl::Connect` and `WebSocketConnectorImpl::Connect` pass the URL directly through to the network service without any CSP check. The network service `CreateWebTransport` and `CreateWebSocket` also perform no CSP validation.

This means a compromised renderer can bypass CSP `connect-src` restrictions entirely for both WebTransport and WebSocket connections. While this is "by design" in the current architecture (CSP is a renderer-enforced policy), it represents a defense-in-depth gap that is especially significant given that WebTransport and WebSocket connections can be long-lived and bidirectional.

## Affected Files

- `content/browser/webtransport/web_transport_connector_impl.cc` lines 177-215:
  - `Connect()` has no CSP check
- `content/browser/websockets/websocket_connector_impl.cc` lines 78-134:
  - `Connect()` has no CSP check
- `services/network/network_context.cc` lines 2094-2119:
  - `CreateWebTransport` has no CSP check
- `services/network/websocket_factory.cc` lines 79-165:
  - `CreateWebSocket` has no CSP check

## Code Snippet

```cpp
// content/browser/webtransport/web_transport_connector_impl.cc:177
void WebTransportConnectorImpl::Connect(
    const GURL& url,
    ...) {
  DCHECK(BrowserThread::CurrentlyOn(BrowserThread::UI));
  RenderProcessHost* process = RenderProcessHost::FromID(process_id_);
  if (!process) { return; }
  // NO CSP CHECK - url passes through directly
  if (throttle_context_) {
    auto result = throttle_context_->PerformThrottle(...);
    ...
  }
}
```

## Attack Scenario

1. Website deploys CSP `connect-src 'self'` to restrict WebSocket/WebTransport destinations
2. Attacker compromises the renderer (e.g., via a renderer exploit)
3. Compromised renderer calls `WebTransportConnector::Connect` or `WebSocketConnector::Connect` with an arbitrary URL
4. Neither the browser process nor network service validates the URL against CSP
5. Connection is established to an arbitrary endpoint despite CSP restrictions
6. This enables data exfiltration via WebTransport/WebSocket to attacker-controlled servers

For WebTransport specifically, the connection is over QUIC/HTTP3, making it harder to detect with network monitoring tools that focus on TCP connections.

## Impact

- **Severity**: Medium (defense-in-depth, requires compromised renderer)
- **Requires compromised renderer**: Yes
- **Security principle violated**: Browser-side CSP enforcement should complement renderer-side for high-value network APIs
- Long-lived bidirectional connections make this especially useful for data exfiltration
- QUIC-based WebTransport is harder to detect than traditional HTTP connections

## VRP Value Rating

Low-Medium - CSP is traditionally renderer-enforced, so this is more of a design observation than a bug. However, Chrome has been moving toward browser-process enforcement for critical security policies. The fact that WebTransport/WebSocket are bidirectional, persistent connection types makes this gap more concerning than for simple fetch() calls.
