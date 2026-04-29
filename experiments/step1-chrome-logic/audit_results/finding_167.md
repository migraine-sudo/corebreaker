# Finding 167: Isolated Cookie Copy Uses MakeAllInclusive Options Bypassing SameSite and HttpOnly Restrictions

## Summary
The isolated cookie copy flow in `PrefetchSingleRedirectHop::CopyIsolatedCookies()` reads cookies from the isolated network context and writes them to the default network context using `CookieOptions::MakeAllInclusive()`. This option bypasses all cookie access restrictions including SameSite, HttpOnly, and Secure attribute enforcement. While this is necessary for the cookie copy to work correctly (since it's a browser-internal operation, not a web request), the resulting `SetCanonicalCookie()` call on the default cookie manager also uses `MakeAllInclusive()`, which means cookies are written without checking whether they would normally be accessible from the navigation context. This effectively launders cookies through the isolated network context, writing them with full access regardless of their SameSite or other attributes.

## Affected Files
- `content/browser/preloading/prefetch/prefetch_single_redirect_hop.cc` (lines 191-231) - Cookie copy with inclusive options

## Details
```cpp
// prefetch_single_redirect_hop.cc:191-231
void PrefetchSingleRedirectHop::CopyIsolatedCookies() {
  ...
  net::CookieOptions options = net::CookieOptions::MakeAllInclusive();
  isolated_network_context->GetCookieManager()->GetCookieList(
      url_, options, net::CookiePartitionKeyCollection::Todo(),
      base::BindOnce(&PrefetchSingleRedirectHop::OnGotIsolatedCookiesForCopy,
                     weak_ptr_factory_.GetWeakPtr()));
}

void PrefetchSingleRedirectHop::OnGotIsolatedCookiesForCopy(
    const net::CookieAccessResultList& cookie_list,
    const net::CookieAccessResultList& excluded_cookies) {
  ...
  net::CookieOptions options = net::CookieOptions::MakeAllInclusive();
  for (const net::CookieWithAccessResult& cookie : cookie_list) {
    default_cookie_manager->SetCanonicalCookie(
        cookie.cookie, url_, options,
        base::BindOnce(...));
  }
}
```

`MakeAllInclusive()` configures `CookieOptions` with:
- `SameSiteCookieContext::MakeInclusive()` - treats the request as same-site even if it's cross-site
- `set_include_httponly()` - allows access to HttpOnly cookies
- All cookie access checks are bypassed

The problem is that the response from the prefetch (which was fetched cross-site via the isolated network context) may have set cookies with SameSite=Strict or SameSite=Lax that should not normally be accessible in a cross-site context. The isolated cookie copy writes these cookies to the default network context unconditionally.

## Attack Scenario
1. `https://evil.com` adds speculation rules to prefetch `https://bank.com/api/session`
2. The prefetch is fetched in the isolated network context (cross-site, without user cookies)
3. `https://bank.com/api/session` responds and sets `Set-Cookie: csrf_token=xyz; SameSite=Strict; Secure`
4. When the user clicks to navigate to `bank.com`, the cookie copy writes `csrf_token=xyz` to the default cookie jar using `MakeAllInclusive()`, bypassing the SameSite=Strict enforcement
5. This SameSite=Strict cookie was set in a cross-site context (the isolated prefetch), which normally would not be allowed
6. The `csrf_token` is now in the user's default cookie jar even though it was set by a cross-site prefetch

Note: The practical impact is limited because:
- The prefetch request itself does not include the user's existing cookies
- The cookie is set by the legitimate server's response
- The user would navigate to the same site anyway

However, this creates a path where a cross-site prefetch can inject cookies into the default cookie jar that would not normally be settable from a cross-site context.

## Impact
Low - The cookie copy bypasses SameSite enforcement as a necessary implementation detail, but this could allow cross-site cookie injection in edge cases. The server sets the cookies voluntarily, limiting the attack surface.

## VRP Value
Low
