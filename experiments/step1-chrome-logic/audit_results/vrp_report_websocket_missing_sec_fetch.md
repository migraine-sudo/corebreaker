# Chrome VRP Report: WebSocket Handshakes Missing All Sec-Fetch-* Metadata Headers

## Summary

Chrome's WebSocket handshake implementation completely bypasses the Fetch Metadata Request Headers mechanism. The WebSocket code path (`services/network/websocket.cc` → `net/websockets/websocket_stream.cc`) creates its `URLRequest` directly without calling `SetFetchMetadataHeaders()`, which is only invoked from the `URLLoader` path. As a result, WebSocket upgrade requests carry NO `Sec-Fetch-Dest`, `Sec-Fetch-Mode`, or `Sec-Fetch-Site` headers, preventing servers from using these security headers for WebSocket CSRF protection.

## Severity Assessment

- **Type**: Security feature bypass / Spec non-compliance with security impact
- **User Interaction**: None (any web page can initiate WebSocket connections)
- **Preconditions**: None
- **Chrome Version**: All versions (the WebSocket path was never integrated with fetch metadata)
- **Flags Required**: None (default configuration)
- **Compromised Renderer**: Not required
- **Platform**: All platforms

## Reproduction Steps

1. Set up a WebSocket server that logs all received headers:
```python
import asyncio
import websockets

async def echo(websocket):
    print("Headers received:")
    for header, value in websocket.request_headers.raw_items():
        print(f"  {header}: {value}")

asyncio.run(websockets.serve(echo, "localhost", 8765))
```

2. Open a cross-origin page that connects to the WebSocket server:
```html
<!-- served from https://attacker.example -->
<script>
const ws = new WebSocket('wss://victim-ws.example:8765');
ws.onopen = () => console.log('Connected');
</script>
```

3. Observe the headers received by the WebSocket server:
```
Headers received:
  Host: victim-ws.example:8765
  Connection: Upgrade
  Upgrade: websocket
  Origin: https://attacker.example
  Sec-WebSocket-Version: 13
  Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
  // NO Sec-Fetch-Dest header
  // NO Sec-Fetch-Mode header
  // NO Sec-Fetch-Site header
```

**Expected** (per Fetch spec):
```
  Sec-Fetch-Dest: websocket
  Sec-Fetch-Mode: websocket
  Sec-Fetch-Site: cross-site
```

**Actual**: All three Sec-Fetch-* headers are completely absent.

## Technical Root Cause

### 1. WebSocket bypasses URLLoader entirely

The WebSocket connection is established via `services/network/websocket.cc` → `net::WebSocketChannel` → `net::WebSocketStream`. This code path creates its own `net::URLRequest` at `net/websockets/websocket_stream.cc:118-160` without going through the `URLLoader` pipeline.

### 2. SetFetchMetadataHeaders only called from URLLoader

`SetFetchMetadataHeaders()` (defined at `services/network/sec_header_helpers.cc:277`) is only called from:
- `services/network/url_loader.cc:806` (initial request)
- `services/network/url_loader_util.cc:553` (redirect handling)

Neither `websocket.cc` nor any file in `net/websockets/` references `SetFetchMetadataHeaders`, `sec_header_helpers`, or any Sec-Fetch header constant.

### 3. No WebSocket destination in RequestDestination enum

`services/network/public/mojom/fetch_api.mojom`'s `RequestDestination` enum has no `kWebSocket` value, and `RequestMode` has no websocket mode. The Fetch Metadata infrastructure was never extended to support WebSocket connections.

## Impact

### 1. Server-Side CSRF Protection Bypassed

Servers that implement Sec-Fetch-based CSRF protection (as recommended by OWASP and web.dev) cannot distinguish legitimate same-origin WebSocket connections from cross-site-initiated ones using Sec-Fetch headers:

```python
# Server-side middleware that FAILS for WebSocket:
def check_sec_fetch(request):
    site = request.headers.get('Sec-Fetch-Site')
    if site is None:
        # WebSocket requests always fall here!
        # Server must fall back to Origin header check
        pass
    elif site in ('cross-site', 'same-site'):
        return reject()
```

### 2. Defense-in-Depth Gap

While the `Origin` header is present on WebSocket handshakes and can be used for CSRF protection, Sec-Fetch headers are designed to be:
- **Cannot be set by JavaScript** (prefixed with `Sec-`)
- **Automatically set by the browser** (unforgeable signal)
- **More granular** than Origin (distinguishes same-site from same-origin)

Their absence on WebSocket removes one layer of server-side protection.

### 3. Inconsistency with Fetch/XHR

A regular `fetch()` request to the same URL would include all Sec-Fetch-* headers. The WebSocket handshake to the same URL does not. This inconsistency can lead to security gaps in server configurations that treat the absence of Sec-Fetch headers as implying an older browser rather than a WebSocket connection.

### 4. Also Affects WebTransport

The WebTransport connection path (`services/network/web_transport.cc`) has the same issue — no Sec-Fetch headers are attached to the CONNECT request.

## Spec References

The Fetch specification (https://fetch.spec.whatwg.org/#append-a-request-sec-metadata-header) requires:
- All requests should have Sec-Fetch-Dest set
- WebSocket requests should have `Sec-Fetch-Dest: websocket` and `Sec-Fetch-Mode: websocket`
- `Sec-Fetch-Site` should reflect the relationship between the initiator and the target

## Suggested Fix

Add `SetFetchMetadataHeaders()` call (or equivalent) in the WebSocket connection path. This requires:

1. Adding `kWebSocket` to the `RequestDestination` enum (or handling it specially)
2. Adding `kWebSocket` to the `RequestMode` enum
3. In `services/network/websocket.cc`, after the URLRequest is created, calling the Sec-Fetch header logic with the appropriate mode/destination/site values
4. Computing `Sec-Fetch-Site` from the origin/isolation info already available in the WebSocket code path

## References

- `services/network/websocket.cc` (entire file — no sec-fetch reference)
- `net/websockets/websocket_stream.cc:118-160` (URLRequest creation)
- `services/network/sec_header_helpers.cc:277` (SetFetchMetadataHeaders definition)
- `services/network/url_loader.cc:806` (only call site in request path)
- `services/network/url_loader_util.cc:553` (only call site in redirect path)
- Fetch Metadata spec: https://w3c.github.io/webappsec-fetch-metadata/
