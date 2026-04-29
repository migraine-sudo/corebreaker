# Finding 210: WebTransport Local Network Access Check is Feature-Gated and Can Be Bypassed

## Summary

Both WebTransport and WebSocket Local Network Access (LNA) checks are gated behind feature flags (`kLocalNetworkAccessChecksWebTransport` and `kLocalNetworkAccessChecksWebSockets`). When these features are disabled, the LNA check returns `net::OK` immediately, allowing connections to local network resources (RFC 1918, loopback) without any check. While currently enabled by default, the feature flag gating means these checks could be disabled via Finch experiments or enterprise policy, creating a window where WebTransport/WebSocket connections bypass LNA protection.

More critically, the `LocalNetworkAccessChecker::CheckAddressSpace` returns `kAllowedMissingClientSecurityState` when `client_security_state_` is null, which is an automatic pass. If any code path creates a WebTransport/WebSocket with a null `ClientSecurityState`, LNA is bypassed entirely.

## Affected Files

- `services/network/web_transport.cc` lines 613-617:
  ```cpp
  if (!base::FeatureList::IsEnabled(
          features::kLocalNetworkAccessChecksWebTransport)) {
    std::move(callback).Run(net::OK);  // LNA bypassed entirely
    return;
  }
  ```
- `services/network/websocket.cc` lines 224-226:
  ```cpp
  if (!base::FeatureList::IsEnabled(
          features::kLocalNetworkAccessChecksWebSockets)) {
    return net::OK;  // LNA bypassed entirely
  }
  ```
- `services/network/local_network_access_checker.cc` lines 121-123:
  ```cpp
  if (!client_security_state_) {
    return Result::kAllowedMissingClientSecurityState;  // Auto-pass
  }
  ```
- `services/network/public/cpp/features.cc` lines 273-282

## Code Snippet

```cpp
// services/network/web_transport.cc:610-618
void WebTransport::OnLocalNetworkAccessCheck(
    const net::IPEndPoint& server_address,
    const net::NetLogWithSource& net_log,
    net::CompletionOnceCallback callback) {
  if (!base::FeatureList::IsEnabled(
          features::kLocalNetworkAccessChecksWebTransport)) {
    std::move(callback).Run(net::OK);  // Complete bypass
    return;
  }
  // ...
  LocalNetworkAccessChecker checker(
      url_, origin_,
      /*required_ip_address_space=*/network::mojom::IPAddressSpace::kUnknown,
      client_security_state_.get(), /*url_load_options=*/0);
  // If client_security_state_ is null/empty, checker auto-allows
```

## Attack Scenario

### Scenario 1: Feature Flag Rollback
1. Chrome disables `kLocalNetworkAccessChecksWebTransport` via Finch (e.g., due to a bug in the feature)
2. Malicious website creates a WebTransport connection to `https://192.168.1.1:443/`
3. LNA check returns `net::OK` without any verification
4. Attacker can probe and interact with local network services via QUIC/HTTP3

### Scenario 2: Missing ClientSecurityState
1. A code path creates a WebTransport connection where `client_security_state_` is null or the mojom deserialization produces an empty state
2. The `LocalNetworkAccessChecker` returns `kAllowedMissingClientSecurityState`
3. Connection to local network proceeds without LNA protection

### Scenario 3: Inconsistency between protocols
- WebTransport passes `url_load_options=0` always (line 628), meaning `kURLLoadOptionBlockLocalRequest` is never set
- WebSocket passes `impl_->options_` which CAN include `kURLLoadOptionBlockLocalRequest`
- This means WebTransport never triggers `kBlockedByLoadOption` even if the browser intended to block local requests

## Impact

- **Severity**: Medium-High (local network access bypass)
- **Requires compromised renderer**: No for Scenario 1; potentially No for Scenario 2 if code paths exist
- **Security principle violated**: Feature-gated security checks should fail-closed, not fail-open
- Local network access bypass allows scanning/attacking internal network services

## VRP Value Rating

Medium-High - LNA bypass is a significant finding. The feature-flag gating itself is standard Chromium practice for gradual rollout, but the fail-open behavior and the missing `url_load_options` for WebTransport create a real gap compared to WebSocket and fetch.
