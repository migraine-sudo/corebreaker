# Finding 222: Systematic Security Enforcement Asymmetry Between WebSocket and WebTransport

## Summary

There is a systematic pattern of security enforcement gaps where WebSocket has protections that WebTransport lacks. This appears to stem from WebTransport being a newer protocol that was not subjected to the same security hardening iterations as WebSocket. The gaps create a situation where an attacker can use WebTransport to bypass security measures that would block equivalent WebSocket connections.

## Comprehensive Comparison

| Security Feature | WebSocket | WebTransport | Gap |
|---|---|---|---|
| URL Scheme Validation (network service) | CHECK + `ReportBadMessage` | None | YES |
| Connection Allowlist (`network_restrictions_id`) | Enforced | Missing entirely | YES - Critical |
| Per-Process Throttling (network service) | 255/process, exponential backoff | None at network service | YES |
| Local Network Access (LNA) | `url_load_options` supported | `url_load_options=0` always | YES |
| Server IP redaction | Exposed to renderer | Redacted | WebTransport is BETTER |
| CSP connect-src browser-side | None | None | Both missing |
| Nonce-based revocation | `isolation_info.nonce()` | `key.GetNonce()` | Both present, different APIs |
| IsolationInfo validation | `DCHECK(!IsEmpty())` | Not checked | Both weak |
| Response headers to renderer | Filtered (cookies) | Stripped entirely | WebTransport is BETTER |
| Process ID handling | Type-safe `GlobalRenderFrameHostId` | Raw `int` + `FromUnsafeValue` | YES |
| Error reporting | `ReportBadMessage` for invalid inputs | Silent failure | YES |

## Affected Files

Key comparison points:
- `services/network/websocket_factory.cc` (WebSocket validation)
- `services/network/network_context.cc:2094-2119` (WebTransport creation, missing validation)
- `content/browser/websockets/websocket_connector_impl.cc:14890` (passes `GetNetworkRestrictionsID()`)
- `content/browser/webtransport/web_transport_connector_impl.cc:14897-14900` (no restrictions ID)
- `services/network/websocket_throttler.h` (WebSocket per-process throttling)
- No equivalent file for WebTransport network-service throttling

## Attack Scenarios

### 1. Connection Allowlist Bypass (Most Critical)
A fenced frame with `disableUntrustedNetwork` can use WebTransport to exfiltrate data to arbitrary servers, bypassing the Connection Allowlist that would block WebSocket connections.

### 2. Local Network Probing
WebTransport connections always pass `url_load_options=0`, meaning `kURLLoadOptionBlockLocalRequest` is never set. If a browser integration sets this option for WebSocket, the same protection does not apply to WebTransport.

### 3. Resource Exhaustion
Without per-process throttling at the network service, a single renderer can create many more WebTransport connections than WebSocket connections without being throttled.

### 4. Silent Error Handling
WebTransport errors at the network service boundary are handled silently (connection fails, no `ReportBadMessage`), allowing a compromised renderer to probe the network service's behavior without being killed.

## Impact

- **Severity**: High (aggregate of multiple gaps)
- **Requires compromised renderer**: Varies -- Connection Allowlist bypass does NOT require compromised renderer
- **Security principle violated**: Consistent security enforcement across similar protocols
- The most critical gap is the Connection Allowlist bypass (Finding 220), which undermines Privacy Sandbox guarantees

## VRP Value Rating

High (aggregate) - While individual gaps may be low/medium severity, the systematic pattern demonstrates that WebTransport was not subjected to the same security review as WebSocket. The Connection Allowlist bypass alone is high-severity since it affects the Privacy Sandbox without requiring a compromised renderer.
