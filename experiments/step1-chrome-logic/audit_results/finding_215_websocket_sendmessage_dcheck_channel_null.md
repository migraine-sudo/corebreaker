# Finding 215: WebSocket SendMessage/StartClosingHandshake DCHECK for Channel Validity (Null Deref in Release)

## Summary

`WebSocket::SendMessage()` and `WebSocket::StartClosingHandshake()` guard their preconditions (`channel_` not null, `handshake_succeeded_` is true) with DCHECK, which is stripped in release builds. If a compromised renderer sends a `SendMessage` or `StartClosingHandshake` mojo message before the handshake completes or after the channel has been destroyed, the DCHECK will not fire in release builds, leading to a null pointer dereference on `channel_->SendFrame()` or `channel_->StartClosingHandshake()`.

`StartReceiving()` similarly DCHECKs `pending_data_frames_.empty()` at line 615, meaning a malformed renderer could call it at wrong times.

## Affected Files

- `services/network/websocket.cc` lines 592-594:
  ```cpp
  DCHECK(channel_) << "WebSocket::SendMessage is called but there is "
                      "no active channel.";
  DCHECK(handshake_succeeded_);
  ```
- `services/network/websocket.cc` lines 624-626:
  ```cpp
  DCHECK(channel_) << "WebSocket::StartClosingHandshake is called but there is "
                      "no active channel.";
  DCHECK(handshake_succeeded_);
  ```
- `services/network/websocket.cc` line 615:
  ```cpp
  DCHECK(pending_data_frames_.empty());
  ```

## Code Snippet

```cpp
// services/network/websocket.cc:587-612
void WebSocket::SendMessage(mojom::WebSocketMessageType type,
                            uint64_t data_length) {
  DCHECK(channel_) << "WebSocket::SendMessage is called but there is "
                      "no active channel.";   // STRIPPED IN RELEASE
  DCHECK(handshake_succeeded_);               // STRIPPED IN RELEASE

  if (type == mojom::WebSocketMessageType::CONTINUATION) {
    Reset();
    return;
  }
  DCHECK(IsKnownEnumValue(type));  // STRIPPED IN RELEASE

  const bool do_not_fragment = data_length <= kSmallMessageThreshold;
  pending_send_data_frames_.emplace(type, data_length, do_not_fragment);

  if (!blocked_on_websocket_channel_) {
    ReadAndSendFromDataPipe(InterruptionReason::kNone);
    // ReadAndSendFromDataPipe calls channel_->SendFrame() which will
    // crash on null channel_ in release
  }
}
```

## Attack Scenario

1. A compromised renderer obtains the `WebSocket` mojo interface
2. Renderer sends `SendMessage(TEXT, 100)` before the handshake has completed (i.e., `OnConnectionEstablished` hasn't been called yet)
3. In release builds, `handshake_succeeded_` is false but unchecked
4. `channel_` may be null if `AddChannel` hasn't been called yet or the channel was reset
5. `pending_send_data_frames_.emplace()` succeeds, then `ReadAndSendFromDataPipe` is called
6. Inside `ReadAndSendFrameFromDataPipe`, `channel_->SendFrame()` causes a null pointer dereference in the network service process
7. This crashes the network service, disrupting all network operations for the browser

Note: Mojo ordering may partially mitigate this for the `SendMessage` case since the mojo interface is only provided after `OnConnectionEstablished`. However, race conditions or reordering in the mojo pipe could still trigger this. The `StartClosingHandshake` path is more concerning since the `WebSocket` mojo interface is established at connection time.

## Impact

- **Severity**: Medium (network service crash / DoS)
- **Requires compromised renderer**: Yes (for direct mojo manipulation)
- **Security principle violated**: Precondition checks should use CHECK, not DCHECK, for untrusted inputs
- Network service crash affects all browser network operations
- The DCHECK on `IsKnownEnumValue(type)` at line 601 is also debug-only

## VRP Value Rating

Medium - A null pointer dereference in the network service process caused by a compromised renderer is a reportable finding. The network service runs in a separate sandboxed process, so this is a DoS rather than a memory corruption exploit. Chrome VRP typically rates network service crashes from compromised renderers as medium severity.
