# Finding 224: WebSocket Blocks All Cookies Including Partitioned When Third-Party Cookies Blocked

## Summary

When third-party cookies are blocked, URL loader requests correctly preserve partitioned cookies (via `ExcludeAllCookiesExceptPartitioned`), but WebSocket requests incorrectly block ALL cookies including partitioned ones (via `ExcludeAllCookies`). This is acknowledged by a TODO comment at line 265 of `network_service_network_delegate.cc`: "TODO(crbug/324211435): Fix partitioned cookies for web sockets."

Partitioned cookies (CHIPS - Cookies Having Independent Partitioned State) are designed to work even when third-party cookies are blocked. By using WebSocket instead of fetch/XHR, a third-party service loses access to its partitioned cookies that it should have access to.

## Affected Files

- `services/network/network_service_network_delegate.cc` lines 240-271:
  ```cpp
  URLLoader* url_loader = URLLoader::ForRequest(request);
  if (url_loader) {
    allowed = url_loader->AllowFullCookies(...);
    if (!allowed) {
      if (url_loader->CookiesDisabled()) {
        ExcludeAllCookies(...);  // Block ALL when cookies fully disabled
      } else {
        ExcludeAllCookiesExceptPartitioned(...);  // Preserve partitioned for 3PC block
      }
    }
  } else {
    WebSocket* web_socket = WebSocket::ForRequest(request);
    if (web_socket) {
      allowed = web_socket->AllowCookies(request.url());
      // TODO(crbug/324211435): Fix partitioned cookies for web sockets.
      if (!allowed) {
        ExcludeAllCookies(...);  // BUG: Blocks ALL including partitioned!
      }
    }
  }
  ```

## Code Snippet

The URLLoader path correctly distinguishes between "all cookies disabled" and "just 3PC blocked":
```cpp
// URLLoader path (CORRECT):
if (url_loader->CookiesDisabled()) {
  ExcludeAllCookies(EXCLUDE_USER_PREFERENCES, ...);
} else {
  ExcludeAllCookiesExceptPartitioned(EXCLUDE_USER_PREFERENCES, ...);
}

// WebSocket path (INCORRECT):
if (!allowed) {
  ExcludeAllCookies(EXCLUDE_USER_PREFERENCES, ...);  // No partitioned exception
}
```

## Attack Scenario

This is not an attack per se, but a consistency bug that breaks CHIPS (Cookies Having Independent Partitioned State) for WebSocket:

1. Third-party service `https://analytics.com` embeds in `https://site.com`
2. `analytics.com` sets a partitioned cookie: `Set-Cookie: __Host-id=123; Secure; Path=/; SameSite=None; Partitioned`
3. User has third-party cookies blocked
4. When `analytics.com` makes fetch requests, the partitioned cookie is correctly included (ExcludeAllCookiesExceptPartitioned preserves it)
5. When `analytics.com` opens a WebSocket connection to `wss://analytics.com/ws`, the partitioned cookie is INCORRECTLY excluded (ExcludeAllCookies blocks it)
6. The WebSocket connection loses authentication/state that should be available via partitioned cookies

This creates an inconsistency between fetch and WebSocket, potentially breaking real-world services that use WebSocket with partitioned cookies for state management.

## Impact

- **Severity**: Low-Medium (functional bug with privacy implications, no compromised renderer needed)
- **Requires compromised renderer**: No -- standard web API behavior difference
- **Security principle violated**: Consistent enforcement of cookie policies across connection types
- The TODO comment confirms this is a known issue (crbug/324211435)
- CHIPS is designed to provide a privacy-preserving alternative to third-party cookies
- Breaking CHIPS for WebSocket may push developers toward less privacy-preserving workarounds

## VRP Value Rating

Low - This is a known bug (tracked at crbug/324211435) that causes a functional inconsistency rather than a security bypass. However, the inconsistency breaks a privacy-preserving feature (CHIPS) for a specific protocol, which could have privacy implications if services work around it by requesting broader cookie access.
