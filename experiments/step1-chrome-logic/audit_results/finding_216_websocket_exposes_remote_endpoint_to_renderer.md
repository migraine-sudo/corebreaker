# Finding 216: WebSocket Exposes Server IP Address (remote_endpoint) to Renderer Unlike WebTransport

## Summary

The WebSocket handshake response passes the full server `remote_endpoint` (IP address and port) to the renderer process in `WebSocketHandshakeResponse::remote_endpoint`. In contrast, WebTransport explicitly redacts this information, passing an empty/invalid `IPEndPoint` to the renderer with the comment "it is dangerous to pass the error details to the initiator renderer."

The WebSocket `OnAuthRequired` callback also passes the `remote_endpoint` to the renderer's `WebSocketAuthenticationHandler`.

This inconsistency means that WebSocket connections leak the resolved IP address of the server to the renderer process, while WebTransport does not. This could enable:
- DNS rebinding detection evasion (the renderer knows the resolved IP)
- Server IP address information leakage to web content
- Cross-origin IP address discovery through redirects

## Affected Files

- `services/network/websocket.cc` line 113:
  ```cpp
  response_to_pass->remote_endpoint = response->remote_endpoint;
  ```
- `services/network/public/mojom/websocket.mojom` lines 38, 54:
  ```
  IPEndPoint remote_endpoint;
  ```
- `services/network/websocket.cc` lines 479-490 (auth handler also receives remote_endpoint)

Contrast with WebTransport:
- `content/browser/webtransport/web_transport_connector_impl.cc` lines 113-114:
  ```cpp
  // Here we pass an invalid IPEndPoint instance because it is dangerous to
  // pass the error details to the initiator renderer.
  remote_->OnBeforeConnect(net::IPEndPoint());
  ```

## Code Snippet

```cpp
// services/network/websocket.cc:104-131
mojom::WebSocketHandshakeResponsePtr ToMojo(
    std::unique_ptr<net::WebSocketHandshakeResponseInfo> response,
    bool has_raw_headers_access) {
  mojom::WebSocketHandshakeResponsePtr response_to_pass(
      mojom::WebSocketHandshakeResponse::New());
  response_to_pass->url.Swap(&response->url);
  response_to_pass->status_code = response->headers->response_code();
  response_to_pass->status_text = response->headers->GetStatusText();
  response_to_pass->http_version = response->headers->GetHttpVersion();
  response_to_pass->remote_endpoint = response->remote_endpoint;  // IP LEAK
  // ...
```

## Attack Scenario

1. Web page opens a WebSocket connection to `wss://example.com/ws`
2. The DNS resolves `example.com` to a specific IP (e.g., behind a CDN or load balancer)
3. The resolved IP address is returned to the renderer in `remote_endpoint`
4. A compromised renderer (or JavaScript via DevTools protocol access) can read this IP
5. This leaks backend server infrastructure information

For DNS rebinding:
1. Attacker uses a DNS rebinding attack where `evil.com` first resolves to the attacker's IP, then to an internal IP
2. WebSocket `remote_endpoint` reveals the actual IP connected to
3. Attacker can verify which IP was used and adjust attack strategy

Note: The `remote_endpoint` is used by DevTools for display purposes, but it goes through the renderer mojo interface.

## Impact

- **Severity**: Low-Medium (information leak, inconsistency with WebTransport)
- **Requires compromised renderer**: Partially -- the information goes to the renderer, but accessing it from web content may require additional steps or DevTools access
- **Security principle violated**: Inconsistent information hiding between similar protocols
- The WebTransport team explicitly identified this as dangerous; the WebSocket code does not apply the same protection

## VRP Value Rating

Low-Medium - Information leak of resolved IP addresses to the renderer. The inconsistency with WebTransport's explicit redaction suggests this may be an oversight. Chrome VRP may consider this a low-priority information leak, but the explicit WebTransport comment calling this "dangerous" strengthens the case.
