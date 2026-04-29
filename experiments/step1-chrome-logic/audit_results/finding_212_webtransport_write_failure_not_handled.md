# Finding 212: WebTransport Stream Write Failure Silently Ignored - Potential Data Loss

## Summary

In `WebTransport::Stream::Send()`, when `outgoing_->Write()` fails, the error is silently ignored with a TODO comment. The data that was read from the Mojo pipe is acknowledged via `EndReadData(0)` (consuming 0 bytes), but the write failure is not propagated to the client or to the stream state. This could lead to data loss where the application believes data was sent but it was actually dropped, or to inconsistent stream state.

Additionally, in `OnIncomingBidirectionalStreamAvailable` and `OnIncomingUnidirectionalStreamAvailable`, when `mojo::CreateDataPipe` fails, the stream is reset but the entire connection is NOT errored (TODO comments acknowledge this gap). This means partial failures can leave the session in an inconsistent state.

## Affected Files

- `services/network/web_transport.cc` lines 282-288 (write failure):
  ```cpp
  bool send_result = outgoing_->Write(base::as_string_view(data));
  if (!send_result) {
    // TODO(yhirano): Handle this failure.
    readable_->EndReadData(0);
    return;
  }
  ```
- `services/network/web_transport.cc` lines 798-800 (data pipe failure):
  ```cpp
  stream->ResetDueToInternalError();
  // TODO(yhirano): Error the entire connection.
  return;
  ```
- `services/network/web_transport.cc` lines 804-806 (same pattern)
- `services/network/web_transport.cc` lines 844-846 (same pattern)
- `services/network/web_transport.cc` lines 867-871 (unimplemented stream creation notifications)

## Code Snippet

```cpp
// services/network/web_transport.cc:266-289
void Send() {
  MaySendFin();
  while (readable_ && outgoing_ && outgoing_->CanWrite()) {
    base::span<const uint8_t> data;
    MojoResult result =
        readable_->BeginReadData(MOJO_BEGIN_READ_DATA_FLAG_NONE, data);
    // ...
    bool send_result = outgoing_->Write(base::as_string_view(data));
    if (!send_result) {
      // TODO(yhirano): Handle this failure.
      readable_->EndReadData(0);  // Data is lost here!
      return;
    }
    readable_->EndReadData(data.size());
  }
}
```

## Attack Scenario

1. A malicious WebTransport server could trigger write failures on the QUIC layer
2. The client application sends data, which is read from the Mojo pipe but silently dropped
3. The application receives no error indication for the lost data
4. For applications using WebTransport for critical data (financial transactions, command/control), this silent data loss could have security consequences

For the data pipe creation failure:
1. Under memory pressure, `mojo::CreateDataPipe` can fail
2. Individual streams are reset but the session continues operating
3. The renderer is not informed that the session is in a degraded state
4. Subsequent stream operations may produce unexpected behavior

## Impact

- **Severity**: Low-Medium (data integrity / reliability)
- **Requires compromised renderer**: No (server-side trigger possible)
- **Security principle violated**: Fail-safe error handling; silent data loss
- Multiple TODO comments (lines 284, 799, 805, 845, 867, 871) indicate known unhandled error conditions
- The combination of unhandled errors could lead to session state confusion

## VRP Value Rating

Low - These are primarily reliability/correctness bugs rather than direct security vulnerabilities. However, the silent data loss pattern is concerning for security-sensitive applications, and the multiple unfixed TODOs indicate technical debt that could be leveraged in more complex attack chains. Chrome VRP may consider these as quality issues rather than security bugs.
