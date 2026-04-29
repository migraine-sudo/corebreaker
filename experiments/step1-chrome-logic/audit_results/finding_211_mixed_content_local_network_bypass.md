# Finding 211: Mixed Content Checker Allows Local/Loopback HTTP Requests Without Checking Initiator

## Summary

The mixed content checker explicitly allows HTTP requests to local network (kLocal) and loopback (kLoopback) IP addresses from HTTPS pages, without checking the IP address space of the initiator. This means a public HTTPS webpage can make mixed-content HTTP requests to `http://192.168.x.x/`, `http://10.x.x/`, or `http://localhost/` and they will NOT be blocked by the mixed content checker. Combined with the WebRTC LNA bypass (Finding 180), this creates multiple unchecked pathways to local networks.

## Affected Files

- `content/browser/renderer_host/mixed_content_checker.cc:351-359` — Local/loopback bypass

## Details

```cpp
// mixed_content_checker.cc:345-359
// that the ip address space is definitively in the local or loopback
// address spaces.
//
// Loopback addresses shouldn't need to be checked as they are considered
// secure and not mixed content, but it can't hurt.
//
// TODO(crbug.com/395895368): check the IP address space for initiator, only
// skip when the initiator is more public.
std::optional<network::mojom::IPAddressSpace> ip_address_space =
    network::GetAddressSpaceFromUrl(url);
if (ip_address_space &&
    (ip_address_space == network::mojom::IPAddressSpace::kLocal ||
     ip_address_space == network::mojom::IPAddressSpace::kLoopback)) {
    allowed = true;  // ALWAYS allows HTTP to local/loopback!
}
```

The TODO explicitly says the fix should check that the initiator is "more public" (i.e., an initiator from the public internet should NOT be allowed to make HTTP requests to local addresses). Currently, no such check exists.

## Attack Scenario

### Local service discovery and attack
1. User visits `https://attacker.com` on their home/corporate network
2. The HTTPS page makes `fetch('http://192.168.1.1/')` (router admin page)
3. Mixed content checker ALLOWS this because 192.168.1.1 resolves to kLocal address space
4. The request reaches the router's HTTP admin interface
5. If the router has no authentication (common for many IoT devices), the attacker can:
   - Read router configuration
   - Change DNS settings
   - Enable remote management
   - Access connected device lists

### Localhost service exploitation
1. User has developer tools running on localhost (e.g., `http://localhost:8080/api/`)
2. `https://attacker.com` makes `fetch('http://localhost:8080/api/exec?cmd=whoami')`
3. Mixed content checker allows this (loopback address)
4. The request reaches the local development server
5. If the server has no CORS restrictions or has permissive CORS, the attacker can:
   - Read sensitive data from development databases
   - Execute commands if the service supports it
   - Access internal tooling

### Combined with DNS rebinding
1. Attacker sets up a domain that initially resolves to their public IP
2. After the page loads, DNS rebinding switches to resolve to 192.168.1.1
3. The mixed content checker sees the IP as kLocal and allows the HTTP request
4. This bypasses both mixed content and potentially CORS (since origin matches)

## Impact

- **No compromised renderer required**: Standard fetch/XHR from HTTPS pages
- **Local network access**: HTTP requests to LAN devices allowed without mixed content blocking
- **Router/IoT attacks**: Many local devices run HTTP-only admin interfaces
- **Localhost attacks**: Development servers, databases, local services exposed
- **Missing initiator check**: The code acknowledges the fix is needed but hasn't implemented it

## VRP Value

**Medium-High** — Mixed content bypass for local network access from HTTPS pages. While Local Network Access (LNA) checks separately cover this for regular (non-mixed-content) requests, the mixed content exemption for local addresses means that even if a request would be blocked as mixed content, local targets get through. The TODO explicitly acknowledges the missing initiator check.
