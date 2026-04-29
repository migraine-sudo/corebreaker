# Finding 119: addIceCandidate() Silently Succeeds on Empty Candidate String

## Severity: LOW

## Location
- `third_party/blink/renderer/modules/peerconnection/rtc_peer_connection.cc`, lines 1510-1516 and 1564-1569

## Description

The `addIceCandidate()` implementation has a "temporary mitigation" that silently resolves the promise when an empty candidate string is provided, rather than passing it to the WebRTC stack:

```cpp
// First overload (promise-based):
if (candidate->hasCandidate() && candidate->candidate().empty()) {
    // Temporary mitigation to avoid throwing an exception when candidate is
    // empty or nothing was passed.
    // TODO(crbug.com/978582): Remove this mitigation when the WebRTC layer
    // handles the empty candidate field or the null candidate correctly.
    return ToResolvedUndefinedPromise(script_state);
}

// Second overload (callback-based):
if (platform_candidate->Candidate().empty())
    return ToResolvedUndefinedPromise(script_state);
```

The TODO at crbug.com/978582 indicates this is a known workaround that has persisted for years.

## Security Implications

1. **Silent success on invalid input**: The API resolves successfully even though no candidate was actually processed. This can mask application bugs or injection attempts where an attacker injects empty candidates to disrupt ICE negotiation.

2. **Inconsistent behavior**: The first overload checks `hasCandidate() && candidate().empty()`, while the second checks `Candidate().empty()` on the already-converted platform candidate. These are subtly different code paths with different conditions.

3. **End-of-candidates signal confusion**: An empty candidate is the signal for "end of candidates" in the ICE trickle specification. By silently succeeding without forwarding this signal to the WebRTC stack, the ICE agent may not know that candidate gathering is complete, potentially keeping the connection in a gathering state longer than necessary.

4. **Defense-in-depth gap**: If JavaScript code is constructing candidates from untrusted data and the candidate string is empty due to a parsing error, the empty check prevents the error from surfacing, potentially masking an injection or data corruption issue.

## Impact

The direct security impact is low. The primary concern is that the silent success behavior can mask bugs in WebRTC applications that handle ICE candidates from untrusted sources. An attacker who can inject empty candidates into the signaling channel could cause subtle negotiation issues without triggering any errors.

## Exploitability

LOW -- Requires control over the signaling channel or script injection. The impact is limited to disrupting ICE negotiation timing rather than enabling direct exploitation.
