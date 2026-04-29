# Finding 180: WebRTC Local Network Access Checks Disabled by Default

## Summary

`kLocalNetworkAccessChecksWebRTC` is DISABLED by default, meaning WebRTC connections from public websites to local/private network addresses are not subject to Local Network Access (LNA) permission checks. Combined with Finding 120 (CSP connect-src doesn't block RTCPeerConnection), this creates an unchecked pathway for web pages to probe and communicate with local network devices via WebRTC.

## Affected Files

- `services/network/public/cpp/features.cc:251-252` — Feature DISABLED_BY_DEFAULT
- `services/network/web_transport.cc:615` — WebTransport LNA check reference (enabled)

## Details

```cpp
// features.cc:248-252
// Enables Local Network Access checks for WebRTC.
// Blocks local network requests without user permission to prevent exploitation
// of vulnerable local devices.
BASE_FEATURE(kLocalNetworkAccessChecksWebRTC,
             base::FEATURE_DISABLED_BY_DEFAULT);
```

Comparison with other protocols:
- **Fetch/XHR**: LNA checks ENABLED (`kLocalNetworkAccessChecks` enabled)
- **WebSockets**: LNA checks ENABLED (`kLocalNetworkAccessChecksWebSockets` enabled)
- **WebTransport**: LNA checks ENABLED (`kLocalNetworkAccessChecksWebTransport` enabled)
- **WebRTC**: LNA checks **DISABLED** ← security gap

## Attack Scenario

### Local network device scanning via WebRTC
1. Public website `https://attacker.com` creates RTCPeerConnection objects
2. The page generates ICE candidates targeting local network addresses (192.168.x.x, 10.x.x, 172.16.x.x)
3. No LNA check blocks these connections — the feature is disabled
4. CSP connect-src also doesn't block WebRTC (Finding 120)
5. The attacker can:
   - Enumerate live hosts on the local network via ICE candidate responses
   - Detect internal network topology
   - Fingerprint users by their local network configuration

### TURN server-based local network relay
1. Attacker runs a TURN server on the public internet
2. Web page establishes WebRTC connection through attacker's TURN server
3. TURN relay can be configured to relay to local network addresses
4. The attacker proxies connections to the victim's local network devices

## Impact

- **No compromised renderer required**: Standard WebRTC API
- **Local network scanning**: Enumerate hosts on local/private networks
- **No user permission needed**: LNA checks disabled for WebRTC
- **CSP bypass**: connect-src doesn't restrict RTCPeerConnection
- **Inconsistent enforcement**: WebSocket and WebTransport have LNA checks; WebRTC doesn't

## VRP Value

**Medium-High** — WebRTC is the only remaining protocol without LNA checks. When Fetch, WebSocket, and WebTransport all enforce LNA, WebRTC becomes the obvious bypass route. Combined with CSP not applying to WebRTC (Finding 120), this is a complete unchecked pathway to local networks from any web page.
