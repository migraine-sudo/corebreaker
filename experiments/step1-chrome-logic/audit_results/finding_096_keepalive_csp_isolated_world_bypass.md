# Finding 096: KeepAlive CSP Check Ignores Isolated World (Extension Content Script) CSP

## Summary

When a keepalive fetch is initiated by an extension content script (isolated world), the redirect CSP check only uses the main world's CSP. The isolated world's own CSP is not consulted, meaning the content script's stricter CSP can be bypassed.

## Affected Files

- `content/browser/loader/keep_alive_url_loader.cc:199,1215-1219` — TODO: Isolated world CSP not handled

## Details

```cpp
// keep_alive_url_loader.cc:199
// TODO(crbug.com/40263403): Isolated world's CSP is not handled.
bool IsRedirectAllowedByCSP(
    const std::vector<network::mojom::ContentSecurityPolicyPtr>& policies, ...)
```

The CSP check only uses `policy_container_host_` which holds the main world's CSP.

## Attack Scenario

1. Extension content script has strict CSP (e.g., `connect-src 'self'`)
2. Content script issues `fetch(url, {keepalive: true})`
3. Redirect happens after renderer dies
4. CSP check uses the page's CSP (which may be more permissive) instead of the content script's CSP
5. Redirect to a domain blocked by the extension's CSP succeeds

## Impact

- **No compromised renderer required**: Standard extension content script behavior
- **CSP bypass for extensions**: Extension's own CSP not enforced on keepalive redirects
- **Known issue**: crbug.com/40263403

## VRP Value

**Medium** — Extension CSP bypass on keepalive redirects. Requires specific extension + server redirect setup.
