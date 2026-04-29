# VRP Report: Fenced Frame WebRTC P2P Bypass — Privacy Sandbox Isolation Failure

## Title

Fenced frames allow unrestricted WebRTC RTCPeerConnection, enabling local IP leak and covert communication channel that bypasses Privacy Sandbox isolation

## Severity

Medium-High (Privacy Sandbox isolation bypass)

## Component

Blink > FencedFrames, Blink > WebRTC

## Chrome Version

Tested against Chromium source at HEAD (April 2026). Affects all current Chrome versions with fenced frame support.

## Summary

Chrome's fenced frames allow unrestricted creation of `RTCPeerConnection` because the WebRTC P2P blocking code is gated behind the `kFencedFramesLocalUnpartitionedDataAccess` feature flag, which is `FEATURE_DISABLED_BY_DEFAULT`. In production Chrome, fenced frames can:

1. **Leak local IP addresses** via ICE candidate gathering
2. **Establish direct P2P DataChannels** with the embedding page, completely bypassing the fenced frame communication boundary

This undermines the core privacy guarantee of fenced frames in the Protected Audience (FLEDGE) API.

## Steps to Reproduce

### 1. Create a test page with a fenced frame

```html
<!DOCTYPE html>
<html>
<head><title>Fenced Frame WebRTC Test</title></head>
<body>
<h1>Embedding Page</h1>
<script>
// Create a fenced frame
const ff = document.createElement('fencedframe');
ff.config = new FencedFrameConfig('https://ad.example/ad.html');
ff.width = 300;
ff.height = 250;
document.body.appendChild(ff);
</script>
</body>
</html>
```

### 2. Inside the fenced frame (ad.html)

```html
<!DOCTYPE html>
<html>
<body>
<h2>Ad Content (Fenced Frame)</h2>
<pre id="output"></pre>
<script>
const output = document.getElementById('output');

// Create RTCPeerConnection — should be blocked in fenced frames
try {
  const pc = new RTCPeerConnection({iceServers: []});
  output.textContent += 'RTCPeerConnection created successfully!\n';
  
  // Create data channel to trigger ICE gathering
  pc.createDataChannel('test');
  
  pc.createOffer().then(offer => {
    pc.setLocalDescription(offer);
    output.textContent += 'SDP offer created\n';
  });
  
  pc.onicecandidate = (event) => {
    if (event.candidate) {
      output.textContent += 'ICE candidate: ' + event.candidate.candidate + '\n';
      // This leaks local IP addresses!
    } else {
      output.textContent += 'ICE gathering complete\n';
    }
  };
} catch (e) {
  output.textContent += 'RTCPeerConnection blocked: ' + e.message + '\n';
}
</script>
</body>
</html>
```

### Expected Result (if working correctly)

The fenced frame should throw a `DOMException` when `new RTCPeerConnection()` is called, with a message like "RTCPeerConnection is not allowed in fenced frames."

### Actual Result (vulnerable)

`RTCPeerConnection` is created successfully. ICE candidate gathering proceeds and reveals local IP addresses to the fenced frame's origin.

## Root Cause

The WebRTC P2P blocking for fenced frames is gated behind a feature flag that is disabled by default:

```cpp
// third_party/blink/common/features.cc:780-781
BASE_FEATURE(kFencedFramesLocalUnpartitionedDataAccess,
             base::FEATURE_DISABLED_BY_DEFAULT);
```

This means:
- Browser process: `P2PSocketManager` Mojo interface is always bound for fenced frames (browser_interface_binders.cc:879-885)
- Renderer process: `RTCPeerConnection` constructor never throws for fenced frames (rtc_peer_connection.cc:649-654)

Both the browser-side and renderer-side checks use:
```cpp
if (base::FeatureList::IsEnabled(kFencedFramesLocalUnpartitionedDataAccess) &&
    IsNestedWithinFencedFrame()) { /* block */ }
```

Since the feature is disabled, the blocking never activates.

## Security/Privacy Impact

### 1. Local IP Address Leak

ICE candidate gathering reveals the user's local/private IP addresses (e.g., `192.168.1.100`, `10.0.0.5`) to the fenced frame's origin. This is a direct fingerprinting vector that the fenced frame privacy model is designed to prevent.

### 2. Covert Communication Channel

A fenced frame (FLEDGE ad) and its embedder can establish a WebRTC DataChannel via a shared signaling server:

1. Fenced frame: `pc.createOffer()` → sends SDP to signaling server
2. Embedder: receives SDP → `pc.createAnswer()` → sends answer to signaling server
3. Both exchange ICE candidates via signaling server
4. Direct P2P DataChannel established — **high bandwidth, low latency, no server involvement after setup**

This completely breaks the fenced frame communication boundary, allowing the ad to send arbitrary data to the embedding page (including user tracking data, auction outcomes, etc.).

### 3. Privacy Sandbox Violation

The Protected Audience API (FLEDGE) uses fenced frames specifically to prevent cross-site tracking. If an ad in a fenced frame can communicate with the embedding page via WebRTC, the entire privacy guarantee is nullified.

## Suggested Fix

Either:

1. **Enable the feature flag by default**: Change `FEATURE_DISABLED_BY_DEFAULT` to `FEATURE_ENABLED_BY_DEFAULT` for `kFencedFramesLocalUnpartitionedDataAccess`
2. **Invert the logic**: Block P2P unconditionally for fenced frames, and only allow it when the feature flag enables "local unpartitioned data access"
3. **Remove the feature flag dependency**: Always block P2P in fenced frames, similar to how Battery and ComputePressure are unconditionally blocked

## PoC

Included inline above. Can also be found at `poc/fenced_frame_webrtc_poc.html`.
