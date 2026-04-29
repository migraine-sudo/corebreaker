# Finding 110: SDP Modification Allows Non-Fingerprint Changes Without Rejection

## Severity: MEDIUM

## Location
- `third_party/blink/renderer/modules/peerconnection/rtc_peer_connection.cc`, lines 851-910
- Function: `RTCPeerConnection::checkSdpForStateErrors()`

## Description

The `checkSdpForStateErrors()` function checks if the SDP passed to `setLocalDescription()` has been modified from the SDP originally produced by `createOffer()` / `createAnswer()`. The function correctly blocks DTLS fingerprint modifications (preventing MITM downgrade attacks on the DTLS-SRTP channel), but **allows all other SDP modifications** with only a UseCounter metric being recorded.

The key code path:

```cpp
if (parsed_sdp.sdp() != last_offer_) {
    if (FingerprintMismatch(last_offer_, parsed_sdp.sdp())) {
        return MakeGarbageCollected<DOMException>(...);  // BLOCKED
    } else {
        UseCounter::Count(context, WebFeature::kRTCLocalSdpModification);
        // ... more counters ...
        return nullptr;  // ALLOWED
        // TODO(https://crbug.com/823036): Return failure for all modification.
    }
}
```

This means an attacker who controls JavaScript (e.g., via XSS) can modify the SDP to:
1. Change ICE ufrag/pwd (counted but not blocked) -- potentially redirecting media traffic
2. Insert legacy simulcast parameters via `a=ssrc-group:SIM` (counted but not blocked)
3. Modify codec parameters (e.g., add Opus stereo) -- counted but not blocked
4. Alter media directions, bandwidth limits, or other SDP attributes
5. Add/modify candidate attributes

The `FingerprintMismatch()` function itself only checks the **first** `a=fingerprint:` line in the SDP. Multiple media sections could have different fingerprints, and only the first is compared.

## TODO Indicating Known Issue

```
// TODO(https://crbug.com/823036): Return failure for all modification.
```

This TODO appears twice (lines 881 and 905), confirming this is a known gap that the team intends to fix but has not yet addressed.

## Impact

A web attacker with script execution context (e.g., XSS in a WebRTC application) can modify SDP parameters to:
- Redirect ICE connectivity checks by changing ufrag/pwd
- Force specific codec configurations that may have known vulnerabilities
- Modify media descriptions to alter the negotiated session properties

The fingerprint check prevents the most dangerous DTLS MITM attack, but other SDP munging remains possible.

## Exploitability

Requires JavaScript execution in the page context (e.g., XSS). The modifications are applied in the renderer process before being sent to the WebRTC stack. This is MEDIUM because:
- It requires XSS or similar script injection first
- The fingerprint protection prevents the most critical DTLS downgrade
- ICE ufrag/pwd changes could redirect traffic but require STUN/TURN server cooperation
