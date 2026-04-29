# Finding 045: WebRTC Local Network Access Checks Completely Disabled

## Summary

Local Network Access (LNA) checks for WebRTC are gated behind `kLocalNetworkAccessChecksWebRTC`, which is `FEATURE_DISABLED_BY_DEFAULT`. While regular HTTP/fetch LNA checks are enabled, WebRTC provides an unrestricted pathway for any web page to reach local/private network hosts without preflight or permission checks.

## Affected Files

- `services/network/public/cpp/features.cc:251-252` — kLocalNetworkAccessChecksWebRTC DISABLED_BY_DEFAULT
- `services/network/local_network_access_checker.cc:157-169` — local→loopback not blocked comment

## Details

### Disabled WebRTC LNA enforcement

```cpp
// features.cc:251-252
BASE_FEATURE(kLocalNetworkAccessChecksWebRTC,
             base::FEATURE_DISABLED_BY_DEFAULT);
```

### Contrast with other protocols

| Protocol | LNA Enforcement | Feature Flag |
|----------|----------------|--------------|
| HTTP/fetch | **Enabled** | kLocalNetworkAccessChecks (ENABLED) |
| WebSockets | **Enabled** | kLocalNetworkAccessChecksWebSockets (ENABLED) |
| WebTransport | **Enabled** | kLocalNetworkAccessChecksWebTransport (ENABLED) |
| **WebRTC** | **DISABLED** | kLocalNetworkAccessChecksWebRTC (DISABLED) |

### Additional gap: local→loopback not blocked

```cpp
// local_network_access_checker.cc:157-169
// Currently for LNA we are only blocking public -> local/private/loopback
// requests. Requests from local -> loopback (or private -> local in PNA
// terminology) are not blocked at present.
```

## Attack Scenario

### IoT/router exploitation via WebRTC

1. User visits `evil.example`
2. Page uses WebRTC to establish peer connections to local network addresses (192.168.x.x, 10.x.x.x)
3. No LNA preflight or permission prompt is shown (feature disabled)
4. WebRTC data channels can send arbitrary data to local network services
5. Attacker can:
   - Scan the local network for live hosts
   - Interact with IoT devices, routers, NAS appliances
   - Exploit vulnerabilities in local network services
   - Exfiltrate data from internal services

### Bypassing HTTP-based LNA enforcement

1. A page is blocked from making fetch() requests to `192.168.1.1` (router) due to LNA
2. The same page establishes a WebRTC connection to the same IP — no LNA check
3. Using WebRTC data channels, the attacker sends HTTP-like payloads to the router
4. LNA enforcement is completely circumvented via protocol switching

## Impact

- **No compromised renderer required**: Standard WebRTC JavaScript APIs
- **Local network attack vector**: Any web page can reach local/private network services via WebRTC
- **LNA bypass**: Renders HTTP-level LNA enforcement ineffective since WebRTC provides an unrestricted channel
- **Privacy**: WebRTC ICE candidate gathering already reveals local IP addresses; combined with no LNA, this enables full local network interaction

## VRP Value

**Medium-High** — No renderer compromise required. WebRTC provides a complete bypass of the LNA enforcement that is enabled for all other protocols. The inconsistency between protocols (HTTP/WS/WT enforced, WebRTC not) is the core issue.
