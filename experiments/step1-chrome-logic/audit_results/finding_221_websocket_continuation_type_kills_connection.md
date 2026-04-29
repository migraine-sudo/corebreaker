# Finding 221: WebSocket SendMessage with CONTINUATION Type Silently Kills Connection Without Error

## Summary

When a renderer sends a `SendMessage` with type `CONTINUATION`, the WebSocket implementation calls `Reset()` which destroys the entire connection silently. The code comment says "This is guaranteed by mojo" but there is no mojo validation that prevents sending CONTINUATION type -- the mojom enum definition explicitly includes CONTINUATION as a valid value. A compromised renderer can cause any WebSocket connection in its process to be silently torn down by sending a CONTINUATION-type message, without any error or bad message report.

## Affected Files

- `services/network/websocket.cc` lines 596-599:
  ```cpp
  // This is guaranteed by mojo.
  if (type == mojom::WebSocketMessageType::CONTINUATION) {
    Reset();  // Silently kills the connection
    return;
  }
  ```
- `services/network/public/mojom/websocket.mojom` lines 13-18:
  ```
  enum WebSocketMessageType {
    CONTINUATION,
    TEXT,
    BINARY,
    LAST = BINARY,
  };
  ```

## Code Snippet

```cpp
// websocket.cc:587-612
void WebSocket::SendMessage(mojom::WebSocketMessageType type,
                            uint64_t data_length) {
  DCHECK(channel_) << "WebSocket::SendMessage is called but there is "
                      "no active channel.";
  DCHECK(handshake_succeeded_);

  // This is guaranteed by mojo.
  if (type == mojom::WebSocketMessageType::CONTINUATION) {
    Reset();  // Kills the entire WebSocket connection
    return;
  }
  DCHECK(IsKnownEnumValue(type));  // Also stripped in release
  // ...
}
```

The comment "This is guaranteed by mojo" is misleading. Mojo will ensure the enum value is valid (i.e., it's one of the defined values), but `CONTINUATION` IS a valid enum value. The correct approach would be:
```cpp
if (type == mojom::WebSocketMessageType::CONTINUATION) {
  mojo::ReportBadMessage("WebSocket::SendMessage received CONTINUATION type");
  return;
}
```

## Attack Scenario

1. A compromised renderer sends `WebSocket::SendMessage(CONTINUATION, 0)` via mojo
2. The network service receives this and calls `Reset()`, which destroys the WebSocket channel
3. The connection is terminated without any error being reported to the legitimate page
4. This can be used to disrupt WebSocket connections of any page in the same renderer process
5. The `Reset()` call deletes `this` via `factory_->Remove(this)`, so no further processing occurs

Without a compromised renderer:
- This is not exploitable, as the Blink side only sends TEXT or BINARY types

The issue is that `Reset()` is called instead of `mojo::ReportBadMessage()`, so:
- The compromised renderer is NOT killed
- The renderer can repeat this attack on any other WebSocket connection it has access to
- No error logging occurs in release builds

## Impact

- **Severity**: Low-Medium (requires compromised renderer, enables connection disruption)
- **Requires compromised renderer**: Yes
- **Security principle violated**: Invalid mojo inputs should be reported via ReportBadMessage, not silently handled
- A compromised renderer can disrupt WebSocket connections without being detected/terminated

## VRP Value Rating

Low - Requires compromised renderer. The missing `mojo::ReportBadMessage()` is a defense-in-depth issue. The silent `Reset()` means the compromised renderer survives and can continue attacks, whereas `ReportBadMessage()` would terminate it.
