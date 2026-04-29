# Chrome VRP Report: VerifyNavigationHeaders Always Returns True — Renderer Can Inject Arbitrary HTTP Headers

## Summary

The browser-side `VerifyNavigationHeaders()` function in `content/browser/renderer_host/ipc_utils.cc` validates HTTP headers in renderer-initiated navigations against a small allowlist, but **always returns true** regardless of the result. A compromised renderer can inject arbitrary HTTP headers (including `Cookie`, `Authorization`, `X-Forwarded-For`, etc.) into navigation requests.

## Vulnerability Details

**Component:** `content/browser/renderer_host/ipc_utils.cc`
**Lines:** 466-494

```cpp
bool VerifyNavigationHeaders(RenderProcessHost* process,
                             const std::string& headers) {
  // ...parse headers...
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
  return true;  // ALWAYS returns true
}
```

The function detects non-allowlisted headers but:
1. Only calls `DumpWithoutCrashing()` (if the dump feature is enabled)
2. Does NOT call `bad_message::ReceivedBadMessage()`
3. Always returns `true`, allowing the navigation to proceed with arbitrary headers

The `extra_headers` parameter flows from the renderer via:
- `OpenURL` (render_frame_host_impl.cc:10061)
- `BeginNavigation` (render_frame_host_impl.cc:11656)

## Steps to Reproduce

### Setup

This requires a compromised renderer. The proof of concept demonstrates the header injection path:

1. A compromised renderer sends an `OpenURL` or `BeginNavigation` Mojo IPC with `extra_headers` containing non-allowlisted headers
2. The browser calls `VerifyNavigationHeaders()` which detects the violation
3. The function returns `true` and the navigation proceeds
4. The injected headers are sent to the target server

### Injected Headers

A compromised renderer can inject:
- `Cookie: session=stolen_token` — forge authentication cookies
- `Authorization: Bearer <token>` — bypass server-side auth
- `X-Forwarded-For: 127.0.0.1` — bypass IP-based access controls
- `Host: internal-service.local` — virtual host confusion
- Any custom header the target server trusts

### Expected Behavior

`VerifyNavigationHeaders()` should call `bad_message::ReceivedBadMessage()` and return `false` when non-allowlisted headers are detected.

### Actual Behavior

The function always returns `true`, allowing navigation with arbitrary injected headers.

## Impact

1. **CSRF Bypass**: A compromised renderer can inject Cookie headers to forge authenticated requests to cross-origin servers, bypassing same-origin cookie protections.

2. **Authorization Header Injection**: Inject `Authorization` headers to authenticate as a different user to server-side services that trust this header.

3. **Server-Side Request Forgery Aid**: Combined with navigation to internal services, injected headers can bypass IP-based access controls and authentication.

4. **Header Smuggling**: Custom headers can exploit server-side logic that trusts specific HTTP headers for routing, authorization, or feature flags.

## Affected Versions

All Chrome versions with the `VerifyNavigationHeaders` function (current codebase).

## Severity Assessment

**High** — While this requires a compromised renderer, the ability to inject arbitrary HTTP headers into cross-origin navigation requests is a significant privilege escalation within the browser's security model. The browser's sandbox should prevent a compromised renderer from influencing HTTP headers beyond the allowlisted set.

## Known Issue

The TODO at the relevant line references crbug.com/40093290, indicating the Chromium team is aware this should be a renderer kill but hasn't yet enforced it.

## Suggested Fix

```cpp
bool VerifyNavigationHeaders(RenderProcessHost* process,
                             const std::string& headers) {
  // ... parse headers ...
  for (net::HttpRequestHeaders::Iterator header(parsed_headers);
       header.GetNext();) {
    if (header.name() != net::HttpRequestHeaders::kUpgradeInsecureRequests &&
        header.name() != net::HttpRequestHeaders::kOrigin &&
        /* ... other allowlisted headers ... */) {
      bad_message::ReceivedBadMessage(
          process, bad_message::INVALID_NAVIGATION_HEADERS);
      return false;  // Block navigation with non-allowlisted headers
    }
  }
  return true;
}
```
