# Finding 102: VerifyNavigationHeaders Always Returns True — Arbitrary Header Injection

## Summary

The browser-side `VerifyNavigationHeaders()` function validates HTTP headers in renderer-initiated navigations, but **always returns true** even when non-allowlisted headers are detected. A compromised renderer can inject arbitrary HTTP headers (Cookie, Authorization, etc.) into navigation requests.

## Affected Files

- `content/browser/renderer_host/ipc_utils.cc:466-494` — VerifyNavigationHeaders always returns true
- `content/browser/renderer_host/render_frame_host_impl.cc:10061` — extra_headers from OpenURL
- `content/browser/renderer_host/render_frame_host_impl.cc:11656` — extra_headers from BeginNavigation

## Details

```cpp
// ipc_utils.cc:466-494
bool VerifyNavigationHeaders(RenderProcessHost* process,
                             const std::string& headers) {
  for (net::HttpRequestHeaders::Iterator header(parsed_headers);
       header.GetNext();) {
    if (header.name() != net::HttpRequestHeaders::kUpgradeInsecureRequests &&
        header.name() != net::HttpRequestHeaders::kOrigin &&
        header.name() != net::HttpRequestHeaders::kContentType &&
        header.name() != net::HttpRequestHeaders::kUserAgent &&
        header.name() != net::HttpRequestHeaders::kSecPurpose &&
        header.name() != net::HttpRequestHeaders::kDNT) {
      // TODO(https://crbug.com/40093290): Once we have enough data, this should
      // be a `bad_message::ReceivedBadMessage` and return `false`.
      if (base::FeatureList::IsEnabled(features::kDumpOnInvalidNavigationHeaders)) {
        base::debug::DumpWithoutCrashing();
      }
    }
  }
  return true;  // ALWAYS returns true regardless
}
```

The allowlist only includes: Upgrade-Insecure-Requests, Origin, Content-Type, User-Agent, Sec-Purpose, DNT. Any other header (Cookie, Authorization, X-Custom-*) is detected but NOT blocked.

## Attack Scenario

1. Compromised renderer calls `OpenURL` or `BeginNavigation` with `extra_headers` containing `Cookie: admin=1` or `Authorization: Bearer <stolen_token>`
2. Browser calls `VerifyNavigationHeaders()` which detects the non-allowlisted headers
3. Function only does `DumpWithoutCrashing` (if feature even enabled) and returns `true`
4. Navigation proceeds with injected headers sent to the target server
5. Server-side authorization based on Cookie/Authorization headers is bypassed

## Impact

- **Requires compromised renderer**: Yes, but this is a severe sandbox escape vector
- **CSRF bypass**: Inject Cookie headers to forge authenticated requests
- **Authorization bypass**: Inject Authorization headers for server-side auth
- **Header injection**: Any HTTP header can be injected into navigation requests
- **Known issue**: crbug.com/40093290

## VRP Value

**High** — While requiring compromised renderer, this is a direct vector for CSRF and authorization bypass. The TODO explicitly acknowledges this should be a `bad_message::ReceivedBadMessage` but currently allows all headers through.
