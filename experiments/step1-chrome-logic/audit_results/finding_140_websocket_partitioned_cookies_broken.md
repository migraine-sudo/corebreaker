# Finding 140: WebSocket Partitioned Cookie Enforcement Missing

**Severity: MEDIUM**

**Component:** `services/network/network_service_network_delegate.cc`

## Summary

The `OnCanGetCookies()` function in `NetworkServiceNetworkDelegate` has a known bug (crbug/324211435) where partitioned cookies are not correctly handled for WebSocket connections. When cookies are blocked for WebSockets, ALL cookies are excluded (`ExcludeAllCookies`), rather than using the partitioned-aware exclusion (`ExcludeAllCookiesExceptPartitioned`) that is used for regular URL loaders.

## Vulnerable Code

```cpp
// services/network/network_service_network_delegate.cc:240-272
bool NetworkServiceNetworkDelegate::OnCanGetCookies(
    const net::URLRequest& request, ...) {
  URLLoader* url_loader = URLLoader::ForRequest(request);
  if (url_loader) {
    allowed = url_loader->AllowCookie(request.url(), request.site_for_cookies());
    if (!allowed) {
      if (url_loader->ShouldNotAllowPartitionedCookies()) {
        ExcludeAllCookies(...);
      } else {
        ExcludeAllCookiesExceptPartitioned(...);  // Partitioned cookies still allowed
      }
    }
#if BUILDFLAG(ENABLE_WEBSOCKETS)
  } else {
    WebSocket* web_socket = WebSocket::ForRequest(request);
    if (web_socket) {
      allowed = web_socket->AllowCookies(request.url());
      // TODO(crbug/324211435): Fix partitioned cookies for web sockets.
      if (!allowed) {
        ExcludeAllCookies(...);  // ALL cookies excluded, including partitioned
      }
    }
#endif
  }
```

## Security Concern

1. **Inconsistent behavior**: For regular HTTP requests, when cookies are blocked, partitioned cookies (CHIPS) are still allowed through `ExcludeAllCookiesExceptPartitioned`. WebSocket connections do not get this treatment -- all cookies are blocked. This is a denial of service for legitimate partitioned cookie use over WebSockets, but more importantly it reveals an inconsistency in the security model.

2. **Missing ShouldNotAllowPartitionedCookies check**: The WebSocket path does not call `ShouldNotAllowPartitionedCookies()` at all, meaning there's no nuanced cookie policy enforcement for WebSockets.

3. **Potential for future regression**: As partitioned cookies become more important (CHIPS is the replacement for third-party cookies), this gap means WebSockets will be a second-class citizen with potentially unexpected behavior that developers may try to work around.

## Rating Justification

MEDIUM: This is primarily a correctness/consistency issue rather than a direct security bypass. The TODO indicates it is known. The main security concern is the inconsistent enforcement model between HTTP and WebSocket cookie handling, which could lead to unexpected behavior in security-sensitive applications that use WebSockets.

## Related Code

- `services/network/network_service_network_delegate.cc:278-303` - `OnCanSetCookie` has similar WebSocket path but no TODO
- `net/cookies/cookie_setting_override.h` - Partitioned cookie overrides
