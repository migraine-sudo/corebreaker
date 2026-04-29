# Finding 118: SDP Fingerprint Validation Only Checks First Occurrence

## Severity: MEDIUM

## Location
- `third_party/blink/renderer/modules/peerconnection/rtc_peer_connection.cc`, lines 449-478
- Function: `FingerprintMismatch()`

## Description

The `FingerprintMismatch()` function, which is the security check preventing DTLS fingerprint tampering in SDP, only validates the **first** `a=fingerprint:` line in the SDP:

```cpp
bool FingerprintMismatch(String old_sdp, String new_sdp) {
    // Check special case of externally generated SDP without fingerprints.
    const wtf_size_t new_fingerprint_pos = new_sdp.find("\na=fingerprint:");
    if (new_fingerprint_pos == kNotFound) {
        return false;  // No fingerprint in new SDP -- allowed
    }
    // Look for fingerprint having been added. Not allowed.
    const wtf_size_t old_fingerprint_pos = old_sdp.find("\na=fingerprint:");
    if (old_fingerprint_pos == kNotFound) {
        return true;  // Fingerprint added -- blocked
    }
    // Look for fingerprint being modified.
    // ... compares only the FIRST fingerprint occurrence ...
    return old_sdp.subview(old_fingerprint_pos, ...) !=
           new_sdp.subview(new_fingerprint_pos, ...);
}
```

In a multi-media-section SDP (common in WebRTC with both audio and video), each media section (`m=`) typically has its own `a=fingerprint:` line. The `String::find()` method returns the position of the **first** match only.

This means:
1. The first `a=fingerprint:` line is protected against modification
2. Subsequent `a=fingerprint:` lines in other media sections can be freely modified
3. An attacker could change the fingerprint for video while the audio fingerprint remains intact (or vice versa)

### Example Attack

Original SDP:
```
m=audio 9 UDP/TLS/RTP/SAVPF 111
a=fingerprint:sha-256 AA:BB:CC:...  <-- This one is checked
...
m=video 9 UDP/TLS/RTP/SAVPF 96
a=fingerprint:sha-256 DD:EE:FF:...  <-- This one is NOT checked
```

Modified SDP (would pass the check):
```
m=audio 9 UDP/TLS/RTP/SAVPF 111
a=fingerprint:sha-256 AA:BB:CC:...  <-- Same as original, passes check
...
m=video 9 UDP/TLS/RTP/SAVPF 96
a=fingerprint:sha-256 XX:YY:ZZ:...  <-- MODIFIED, not detected
```

## Mitigation Factors

In practice, modern WebRTC implementations using BUNDLE (which is the default `maxBundle` policy) negotiate a single DTLS session for all media. When bundled, all media sections share the same fingerprint. However:
- `maxCompat` bundle policy results in separate DTLS sessions per media section
- Older or non-standard implementations may not use BUNDLE
- The spec allows `a=fingerprint` at both session and media level

Additionally, the WebRTC stack itself performs fingerprint verification during the DTLS handshake, providing a lower-level protection. However, if the SDP is modified before being processed by the WebRTC stack, the stack would verify against the **modified** fingerprint, not the original.

## Impact

A MITM attacker who can inject JavaScript (XSS) could modify the SDP to change the DTLS fingerprint for one media section, enabling selective MITM of that media stream. This would allow interception of video while audio remains intact, for example.

## Exploitability

MEDIUM -- Requires:
1. XSS or script injection in the WebRTC application
2. The application using `maxCompat` bundle policy or no BUNDLE
3. Multi-media-section SDP with per-section fingerprints
4. A MITM position to exploit the modified fingerprint
