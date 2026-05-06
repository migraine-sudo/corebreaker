# Finding 236: Source Map URL Triggers Authenticated No-CORS Fetch When DevTools Opens

## Summary

A web page can set `//# sourceMappingURL=https://internal-server/sensitive-endpoint` in its JavaScript. When a developer opens DevTools on that page, Chrome's browser process automatically fetches the URL in `kNoCors` mode with ORB disabled, using the inspected frame's cookies. This is an SSRF primitive that allows a malicious page to trigger authenticated requests to arbitrary URLs when DevTools is opened.

## Severity: Medium (SSRF Triggered by Developer Action)

## Affected Component

- DevTools source map fetching
- CDP `Network.loadNetworkResource`

## Root Cause

`content/browser/devtools/protocol/devtools_network_resource_loader.cc:57`:
- Source map fetch uses `kNoCors` request mode

`content/browser/devtools/protocol/network_handler.cc:4588-4591`:
```cpp
// Let DevTools fetch resources without CORS and ORB. Source maps are valid
// JSON and would otherwise require a CORS fetch + correct response headers.
params->is_orb_enabled = false;
```

## Attack Scenario

1. Attacker hosts a page with JavaScript containing:
   ```javascript
   //# sourceMappingURL=https://internal-corp-server.example/api/admin/delete-all
   ```
2. Developer visits the page (e.g., investigating a reported bug)
3. Developer opens DevTools (standard workflow)
4. Chrome's browser process fetches `https://internal-corp-server.example/api/admin/delete-all` with:
   - `kNoCors` mode (no CORS preflight)
   - ORB disabled (response not blocked)
   - Page's cookies attached (authenticated request)
   - No user consent or warning

## Limitations

- Response body goes only to DevTools, not back to the attacker's page
- Requires DevTools to be opened (developer must actively inspect the page)
- CSP `connect-src` IS checked for frame targets (but NOT for worker targets — see TODO at line 4714)
- The request uses the frame's `NetworkIsolationKey`, so it's partitioned

## Impact

- **Internal network scanning**: Attacker learns if internal URLs exist (via timing or error responses visible in DevTools)
- **State-changing GETs**: If internal services perform mutations on GET requests, the SSRF can cause damage
- **Token leakage**: If the fetched URL returns sensitive data in response headers (e.g., `Set-Cookie`, auth tokens), these may be processed by the network stack
- **Cookie exfiltration to attacker-controlled redirect**: If the source map URL redirects to attacker's server, the initial authenticated request to the internal target is made, and on redirect, cookies for the initial domain may be sent (depending on cookie policy)

## Preconditions

- Developer must open DevTools on the attacker's page
- The sourceMappingURL must point to a URL the browser can reach
- Cookies are only sent if they match the target URL's SameSite/domain requirements

## Files

- `content/browser/devtools/protocol/devtools_network_resource_loader.cc:57` (kNoCors mode)
- `content/browser/devtools/protocol/network_handler.cc:4588-4591` (ORB disabled)
- `content/browser/devtools/protocol/network_handler.cc:4714` (TODO: CSP not checked for non-frame targets)
