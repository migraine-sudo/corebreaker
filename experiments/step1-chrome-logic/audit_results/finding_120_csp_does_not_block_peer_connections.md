# Finding 120: Content Security Policy Does Not Block WebRTC Peer Connections

## Severity: MEDIUM

## Location
- `third_party/blink/renderer/modules/peerconnection/rtc_peer_connection.cc`, lines 571-587

## Description

The `RTCPeerConnection::Create()` method checks whether CSP (Content Security Policy) is active and would block the connection, but only records UseCounter metrics rather than actually blocking the connection:

```cpp
// Count number of PeerConnections that could potentially be impacted by CSP
auto* content_security_policy = context->GetContentSecurityPolicy();
if (content_security_policy &&
    content_security_policy->IsActiveForConnections()) {
    UseCounter::Count(context, WebFeature::kRTCPeerConnectionWithActiveCsp);
    // Count number of PeerConnections that would be blocked by CSP connect-src
    // or one of the directive it inherits from.
    // This is intended for evaluating whether introducing a "webrtc-src"
    // on-off switch that inherits from connect-csp would be harmful or not.
    // TODO(crbug.com/1225968): Remove code when decision is made.
    if (!content_security_policy->AllowConnectToSource(
            KURL("https://example.org"), KURL("https://example.org"),
            RedirectStatus::kNoRedirect,
            ReportingDisposition::kSuppressReporting)) {
        UseCounter::Count(context, WebFeature::kRTCPeerConnectionWithBlockingCsp);
    }
}
```

Key observations:

1. **No actual blocking**: Even when CSP `connect-src` would block regular fetch/XHR/WebSocket connections, RTCPeerConnection creation proceeds without restriction.

2. **Data collection phase**: The TODO (crbug.com/1225968) reveals this is still in an "evaluation" phase -- they are counting how many sites would be affected before deciding whether to enforce CSP on WebRTC.

3. **Test URL**: The CSP check uses a hardcoded `https://example.org` test URL rather than the actual STUN/TURN server URLs that will be contacted, meaning the metric doesn't even accurately reflect whether the specific ICE servers would be blocked.

4. **No `webrtc-src` directive**: There is no CSP directive specifically for WebRTC. The `connect-src` directive does not apply to WebRTC connections.

## Impact

A website that carefully restricts outbound connections via CSP `connect-src` to only its own origin would expect all network connections (including WebRTC) to be limited. However:

- XSS payloads can establish WebRTC peer connections to any STUN/TURN server, bypassing CSP `connect-src` restrictions
- Data exfiltration is possible through WebRTC data channels to an attacker-controlled TURN server, even on a site with strict CSP
- The ICE candidate gathering process can contact arbitrary STUN servers, leaking the user's IP address regardless of CSP

## Exploitability

MEDIUM -- This is exploitable from any XSS context on a site that relies on CSP for data exfiltration prevention. The attacker can:
1. Create an RTCPeerConnection with their TURN server in the ICE configuration
2. Establish a data channel connection through the TURN relay
3. Exfiltrate data through the data channel

CSP was designed as a defense-in-depth mechanism, and this gap has been known and tracked. The lack of a `webrtc-src` CSP directive is a spec-level gap, not solely a Chromium implementation issue.
