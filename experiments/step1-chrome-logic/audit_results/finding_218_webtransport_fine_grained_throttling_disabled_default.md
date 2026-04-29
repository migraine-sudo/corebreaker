# Finding 218: WebTransport Fine-Grained Throttling Disabled by Default - Fixed 5-Minute Penalty

## Summary

The `kWebTransportFineGrainedThrottling` feature flag is disabled by default (`FEATURE_DISABLED_BY_DEFAULT`). When disabled, ALL failed WebTransport handshakes receive a fixed 5-minute penalty, regardless of whether the failure is to the same IP, the same subnet, or a completely unrelated server. This is excessively punitive and creates a denial-of-service vector: a malicious WebTransport server that deliberately fails handshakes can block the victim page from making ANY WebTransport connections for 5 minutes.

When fine-grained throttling IS enabled, penalties are proportional:
- First failure to a new IP: 100ms
- Repeated failure to same IP: 5 minutes
- Repeated failure to same /24 subnet: 2 minutes
- Unknown server (cancelled before DNS): 50ms

The disabled-by-default state means the much more punitive blanket 5-minute penalty is the current production behavior.

## Affected Files

- `net/base/features.cc` lines 338-339:
  ```cpp
  BASE_FEATURE(kWebTransportFineGrainedThrottling,
               base::FEATURE_DISABLED_BY_DEFAULT);
  ```
- `content/browser/webtransport/web_transport_throttle_context.cc` lines 310-319:
  ```cpp
  void WebTransportThrottleContext::MaybeQueueHandshakeFailurePenalty(
      const std::optional<net::IPAddress>& server_address) {
    if (should_queue_handshake_failure_penalty_) {
      auto penalty = base::Minutes(5);  // DEFAULT: always 5 min!
      if (IsFineGrainedThrottlingEnabled()) {
        penalty = penalty_mgr_.ComputeHandshakePenalty(server_address);
      }
      penalty_mgr_.QueuePending(penalty);
      return;
    }
    // ...
  }
  ```

## Code Snippet

```cpp
// web_transport_throttle_context.cc:310-322
void WebTransportThrottleContext::MaybeQueueHandshakeFailurePenalty(
    const std::optional<net::IPAddress>& server_address) {
  if (should_queue_handshake_failure_penalty_) {
    auto penalty = base::Minutes(5);  // Always 5 minutes unless fine-grained enabled
    if (IsFineGrainedThrottlingEnabled()) {
      // Fine-grained: 50ms to 5min depending on IP/subnet/history
      penalty = penalty_mgr_.ComputeHandshakePenalty(server_address);
    }
    penalty_mgr_.QueuePending(penalty);
    return;
  }
  // Developer mode path: no penalty at all
}
```

## Attack Scenario

1. Malicious website A has a WebTransport server at `https://evil.com:443/`
2. User visits website B that legitimately uses WebTransport to `https://app.com:443/`
3. Evil.com's server deliberately fails the WebTransport handshake
4. Browser applies a 5-minute penalty to the page's throttle context
5. Website B's WebTransport connection to `https://app.com:443/` is delayed by up to 5 minutes
6. This is because the penalty is per-page, not per-server -- a single failure to any server penalizes all subsequent connections from that page

This is especially impactful for ServiceWorker contexts where the throttle is per-PROFILE:
1. ServiceWorker on origin A fails a WebTransport handshake
2. 5-minute penalty is applied to the per-profile throttle context
3. ALL ServiceWorkers in the same profile now face 5-minute delays for WebTransport

## Impact

- **Severity**: Medium (DoS via throttle poisoning, no compromised renderer needed)
- **Requires compromised renderer**: No -- standard web API usage
- **Security principle violated**: Overly broad penalty scope creates cross-origin DoS
- The per-page/per-profile throttle context means one bad server poisons ALL connections
- The fixed 5-minute penalty without fine-grained throttling is disproportionate for first-time failures

## VRP Value Rating

Medium - This is a cross-origin DoS that can be triggered from standard web content. A malicious iframe or third-party script that deliberately fails a WebTransport handshake can block the host page's WebTransport connections for 5 minutes. The fine-grained throttling being disabled by default makes this worse than intended.
