# Finding 142: Unsafe Redirect Schemes for Manual Mode Bypasses Redirect Safety Check

**Severity: MEDIUM**

**Component:** `services/network/url_loader_util.cc`, `net/url_request/url_request_http_job.cc`

## Summary

The `kAllowUnsafeRedirectSchemesForManualMode` feature flag (disabled by default) causes `IsSafeRedirect()` to always return `true` for `fetch()` requests with `redirect: "manual"`. This completely bypasses the scheme-based redirect safety check, potentially allowing redirects to dangerous schemes (like `file://`, `data://`, `javascript://`) that carry cookies from the original request context.

## Vulnerable Code

```cpp
// services/network/url_loader_util.cc:585-593
if (base::FeatureList::IsEnabled(
        features::kAllowUnsafeRedirectSchemesForManualMode)) {
  // Allow unsafe redirect schemes for fetch() with redirect: "manual".
  // We identify fetch() by checking for empty destination (per fetch spec).
  // Navigations also use kManual but have non-empty destinations.
  url_request.set_treat_all_redirects_as_safe(
      request.redirect_mode == mojom::RedirectMode::kManual &&
      request.destination == mojom::RequestDestination::kEmpty);
}
```

```cpp
// net/url_request/url_request_http_job.cc:1569-1576
bool URLRequestHttpJob::IsSafeRedirect(const GURL& location) {
  // When the caller has indicated all redirects should be treated as safe,
  // skip the scheme check.
  if (request_->treat_all_redirects_as_safe()) {
    return true;
  }
  // ...
}
```

## Security Concern

1. **Redirect to dangerous schemes**: With this flag enabled, a `fetch("https://evil.com", {redirect: "manual"})` could follow a redirect to `file://`, `data:`, or other normally-blocked schemes. While `redirect: "manual"` returns an opaque-redirect response (the response body is not directly readable), the redirect itself would be followed at the network level before being surfaced as an opaque response.

2. **Cookie leakage via redirect**: When a redirect is followed, cookies from the original request context may be sent to the redirect target. If the redirect goes to an unexpected scheme/domain, cookies could be leaked.

3. **fetch() identification heuristic**: The code identifies `fetch()` by checking for `RequestDestination::kEmpty`. This is an approximation -- other request types might also have empty destinations. The comment acknowledges navigations use `kManual` with non-empty destinations, but there could be edge cases.

4. **Comment says caller is responsible**: The comment at `IsSafeRedirect` says "The caller is responsible for filtering unsafe redirects (e.g., returning an opaque-redirect response instead of following the redirect)." This deferred-responsibility pattern is fragile -- if the caller changes, the safety guarantee may be lost.

## Rating Justification

MEDIUM: Currently disabled by default. When enabled, it creates a path where redirect safety checks are completely bypassed. The `redirect: "manual"` mode somewhat mitigates this (response is opaque), but the redirect itself still happens at the network level, potentially leaking cookies or triggering side effects at the redirect target.

## Related Code

- `services/network/public/cpp/features.cc:627-628` - Feature definition (DISABLED_BY_DEFAULT)
- Already documented as finding_098 but from a different angle. This finding focuses specifically on cookie implications of the unsafe redirect.
