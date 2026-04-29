# Finding 113: Local Network Access Permission for WebRTC Disabled by Default

## Severity: MEDIUM

## Location
- `third_party/blink/renderer/modules/peerconnection/peer_connection_dependency_factory.cc`, lines 251-274
- `LocalNetworkAccessPermission::ShouldRequestPermission()`

## Description

The `LocalNetworkAccessPermission` class is designed to enforce permission checks when WebRTC ICE candidates attempt to reach local/loopback network addresses from public origins. However, the feature is gated behind `RuntimeEnabledFeatures::LocalNetworkAccessWebRTCEnabled()`, and the implementation has a further narrowing gate:

```cpp
bool ShouldRequestPermission(const webrtc::SocketAddress& candidate_address) override {
    // ...histogram recording...

    if (!RuntimeEnabledFeatures::LocalNetworkAccessWebRTCEnabled()) {
        return false;  // Permission check completely skipped
    }

    const bool is_less_public = network::IsLessPublicAddressSpace(
        target_address_space, originator_address_space_);

    if (network::features::kLocalNetworkAccessChecksWebRTCLoopbackOnly.Get()) {
        return candidate_address.IsLoopbackIP() && is_less_public;
    }

    return is_less_public;
}
```

When `LocalNetworkAccessWebRTCEnabled` is false (which appears to be the default based on the RuntimeEnabledFeatures pattern), no permission is requested for WebRTC connections to local network addresses. This means:

1. A public website can use WebRTC ICE candidates to probe local network hosts (192.168.x.x, 10.x.x.x, 127.0.0.1)
2. Even when the feature is enabled, the `kLocalNetworkAccessChecksWebRTCLoopbackOnly` parameter further restricts checks to only loopback addresses, meaning local network probing (192.168.x.x) remains ungated

The histogram recording at the top of `ShouldRequestPermission()` still fires regardless of the feature flag, confirming this code path is actively reached.

## Impact

- Public websites can probe local network services via WebRTC ICE candidates without user permission
- Port scanning of local network hosts is possible through WebRTC candidate gathering
- Local services not expecting public internet connections may be discoverable
- This undermines the broader Local Network Access spec's goal of protecting local resources

## Exploitability

MEDIUM -- This is exploitable from any web page without requiring a compromised renderer. The attack surface is limited to what can be discovered/reached through STUN/ICE probing rather than direct connections. The IP handling policy (Finding 112) may mitigate some scenarios, but when `enable_multiple_routes` is true, local candidate gathering proceeds. The feature is being rolled out gradually, which is a reasonable mitigation strategy.
