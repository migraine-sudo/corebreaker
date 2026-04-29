# Finding 217: KeepAlive URL Loader Skips Mixed Content Check When Initiator Frame Is Gone

## Summary

The KeepAlive URL loader (used by `fetchLater()` and `fetch()` with `keepalive: true`) checks mixed content for redirects by looking up the initiator RenderFrameHost. However, keepalive requests are specifically designed to outlive their initiating page. When the initiator frame navigates away or closes, `GetInitiator()` returns null, and the mixed content check is completely skipped. This allows a keepalive request to be redirected to an insecure HTTP URL without any mixed content blocking.

## Affected Files

- `content/browser/loader/keep_alive_url_loader.cc:1222-1230` — Mixed content check skipped when no frame
- `content/browser/loader/keep_alive_url_loader.cc:199` — Isolated world CSP not handled

## Details

```cpp
// keep_alive_url_loader.cc:1222-1230
// Checks if redirecting to `redirect_info.new_url` is allowed by
// MixedContent checker.
// TODO(crbug.com/40941240): Figure out how to check without a frame.
if (auto* rfh = GetInitiator();
    rfh && MixedContentChecker::ShouldBlockFetchKeepAlive(
               rfh, redirect_info.new_url,
               /*for_redirect=*/true)) {
    return net::ERR_FAILED;
}
// If rfh is null (frame gone), the entire check is skipped!
```

Additionally:
```cpp
// keep_alive_url_loader.cc:196-199
// Violation will not be reported back to renderer, as this function must be
// called after renderer is gone.
// TODO(crbug.com/40263403): Isolated world's CSP is not handled.
bool IsRedirectAllowedByCSP(...) {
```

## Attack Scenario

### Mixed content downgrade via keepalive redirect
1. User visits `https://attacker.com` which makes a keepalive fetch:
   ```javascript
   fetch('https://attacker.com/redirect', { keepalive: true });
   ```
2. User navigates away from attacker.com (the keepalive request continues)
3. The initiator frame is now gone, `GetInitiator()` returns null
4. `https://attacker.com/redirect` responds with a 302 redirect to `http://victim-internal.corp/api/sensitive-data`
5. Mixed content check is SKIPPED because there's no initiator frame
6. The request follows the redirect to the insecure HTTP URL
7. Combined with Finding 211 (local network bypass), this could reach internal services

### CSP bypass via keepalive + isolated world
1. Extension content script uses `fetch()` with keepalive to load a resource
2. The content script has its own CSP in its isolated world
3. After redirect, the isolated world's CSP is not checked (TODO at line 199)
4. The redirect can go to a URL that the content script's CSP would block

### fetchLater() exploitation
1. `fetchLater()` is designed to fire after page unload — the frame will always be gone
2. Set up a fetchLater that will redirect to a mixed-content HTTP URL
3. When the page unloads and fetchLater fires, the redirect happens without mixed content blocking
4. Data is sent to/received from the insecure HTTP endpoint

## Impact

- **No compromised renderer required**: Standard fetch keepalive + redirect
- **Mixed content bypass**: HTTPS→HTTP redirect not blocked after frame closes
- **By design**: keepalive requests are meant to outlive frames, but security checks depend on frames
- **CSP bypass**: Isolated world CSP not enforced for redirects
- **fetchLater amplification**: fetchLater always fires without a frame

## VRP Value

**High** — This is a fundamental design gap in the keepalive loader's security model. Security checks (mixed content, CSP) depend on the initiator frame, but keepalive requests are specifically designed to outlive their frames. The TODO explicitly acknowledges they don't know how to check without a frame. fetchLater() makes this even more exploitable since it always fires after the page is gone.
