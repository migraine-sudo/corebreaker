# Finding 064: Keep-Alive Fetch CSP Check Ignores Isolated World CSP

## Summary

The `IsRedirectAllowedByCSP()` function in `keep_alive_url_loader.cc` checks Content-Security-Policy for redirect targets during keepalive requests (e.g., `fetch()` with `keepalive: true` that outlives the page). However, it has an explicit TODO (crbug.com/40263403) stating that the isolated world's CSP is not handled. This means extension content scripts' CSP restrictions are not enforced during keepalive request redirects.

## Affected Files

- `content/browser/loader/keep_alive_url_loader.cc:199` — Missing isolated world CSP handling

## Details

```cpp
// keep_alive_url_loader.cc:199
// TODO(crbug.com/40263403): Isolated world's CSP is not handled.
```

Isolated worlds are used by Chrome extensions' content scripts. Each isolated world can have its own CSP. When a keepalive request (sent from an extension's content script) follows a redirect after the page is gone, the CSP check only considers the main world's CSP, not the isolated world's.

## Attack Scenario

### CSP bypass for extension keepalive requests

1. An extension content script sets a strict CSP: `connect-src 'self'`
2. The script sends `fetch('https://allowed.example', {keepalive: true})`
3. The user navigates away — the keepalive request continues in the browser
4. The server redirects to `https://tracking.example/pixel?data=...`
5. The browser checks the main world's CSP (which may be more permissive or absent)
6. The redirect is allowed — the extension's CSP restriction is bypassed

## Impact

- **No compromised renderer required**: Exploitable from normal extension behavior
- **CSP bypass**: Extension's isolated world CSP not enforced for keepalive redirects
- **Data exfiltration**: Can redirect keepalive requests to unauthorized origins

## VRP Value

**Low-Medium** — Requires specific extension + server-side redirect combination. The impact is CSP bypass for a niche scenario (keepalive requests from isolated worlds).
