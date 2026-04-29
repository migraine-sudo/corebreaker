# Finding 219: WebTransport InterceptingHandshakeClient Uses MakeSelfOwnedReceiver - Resource Leak

## Summary

The `WebTransportConnectorImpl::OnThrottleDone` method creates an `InterceptingHandshakeClient` using `mojo::MakeSelfOwnedReceiver`. The TODO comment at line 240 explicitly notes the problem: "the WebTransport implementation in the network service won't notice that the WebTransportHandshakeClient is going away."

When the browser-side `InterceptingHandshakeClient` is destroyed (e.g., page navigation or renderer crash), the network service's `WebTransport` object is not notified because the `MakeSelfOwnedReceiver` creates a separate pipe. The network service continues holding the handshake open, consuming QUIC resources (connections, streams) until the QUIC idle timeout fires.

This creates a resource leak that could be exploited for DoS by rapidly navigating pages that initiate WebTransport handshakes.

## Affected Files

- `content/browser/webtransport/web_transport_connector_impl.cc` lines 240-246:
  ```cpp
  // TODO(yhirano): Stop using MakeSelfOwnedReceiver here, because the
  // WebTransport implementation in the network service won't notice that
  // the WebTransportHandshakeClient is going away.
  mojo::MakeSelfOwnedReceiver(
      std::make_unique<InterceptingHandshakeClient>(
          frame_, url, std::move(handshake_client), std::move(tracker)),
      std::move(client_receiver));
  ```

## Code Snippet

The issue:
```
Renderer -> [WebTransportConnector] -> Browser -> [InterceptingHandshakeClient (self-owned)]
                                                          |
                                                          v (separate pipe)
                                                   NetworkService -> [WebTransport]

When the renderer or browser page is destroyed:
- InterceptingHandshakeClient is destroyed (mojo pipe closed)
- But NetworkService WebTransport does NOT detect this
- The QUIC connection continues until idle timeout
```

## Attack Scenario

1. Malicious page rapidly creates WebTransport connections to a server
2. Before each handshake completes, the page navigates away (or the iframe is removed)
3. The browser-side `InterceptingHandshakeClient` is destroyed, but the network service continues the QUIC handshake
4. Each orphaned QUIC connection consumes network service resources until timeout
5. By repeating this rapidly across many pages/iframes, an attacker can exhaust network service QUIC connection limits
6. This prevents legitimate WebTransport connections from being established

The browser-side throttle (64 per page) mitigates this partially, but:
- The throttle is per-page, and destroyed pages release their throttle context
- ServiceWorker/SharedWorker contexts have per-profile throttling (weaker)
- The network service side has NO throttling at all

## Impact

- **Severity**: Low-Medium (resource leak / DoS)
- **Requires compromised renderer**: No -- standard navigation patterns
- **Security principle violated**: Resource lifecycle management; the TODO confirms this is a known issue
- The orphaned QUIC connections consume network service memory and connection slots

## VRP Value Rating

Low - Known issue (the TODO comment explicitly describes it). The practical impact depends on QUIC idle timeout settings and connection limits. This is more of a robustness issue than a high-severity vulnerability, but it could contribute to a DoS attack chain.
