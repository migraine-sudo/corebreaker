# Finding 223: RestrictedCookieManager Does Not Enforce site_for_cookies and top_frame_origin From Renderer

## Summary

The `RestrictedCookieManager::ValidateAccessToCookiesAt()` method computes whether the renderer-supplied `site_for_cookies` and `top_frame_origin` match the browser-authoritative values from `isolation_info_`, but only LOGS the mismatch without enforcing it. The validation was previously a `DCHECK` (stripped in release builds) and was then explicitly downgraded to `LOG(ERROR)` via TODO crbug.com/402207912. The renderer-supplied values are then used for SameSite cookie context computation in `MakeOptionsForGet()` and `MakeOptionsForSet()`, meaning a compromised renderer can manipulate SameSite cookie decisions.

## Affected Files

- `services/network/restricted_cookie_manager.cc` lines 1135-1183:
  ```cpp
  bool RestrictedCookieManager::ValidateAccessToCookiesAt(...) {
    // ...
    bool site_for_cookies_ok =
        BoundSiteForCookies().IsEquivalent(site_for_cookies);
    // TODO(crbug.com/402207912): Switch back to a DCEHCK once this condition
    // always holds again.
    if (!site_for_cookies_ok) {
      LOG(ERROR) << "site_for_cookies from renderer='"
                 << site_for_cookies.ToDebugString() << "' from browser='"
                 << BoundSiteForCookies().ToDebugString() << "';";
    }

    bool top_frame_origin_ok = (top_frame_origin == BoundTopFrameOrigin());
    // TODO(crbug.com/402207912): Switch back to a DCEHCK once this condition
    // always holds again.
    if (!top_frame_origin_ok) {
      LOG(ERROR) << "top_frame_origin from renderer='" << top_frame_origin
                 << "' from browser='" << BoundTopFrameOrigin() << "';";
    }
    // ... NO enforcement -- continues to line 1179 which only checks url origin
  ```
- `services/network/restricted_cookie_manager.cc` lines 550-551:
  ```cpp
  // Renderer-supplied site_for_cookies used directly:
  net::CookieOptions net_options = MakeOptionsForGet(
      role_, url, site_for_cookies, top_frame_origin, cookie_settings());
  ```
- `services/network/restricted_cookie_manager.cc` lines 76-97 (MakeOptionsForGet/Set):
  - These functions compute SameSite context using the renderer-supplied values
  - `ComputeSameSiteContextForScriptGet()` and `ComputeSameSiteContextForScriptSet()` use these values

## Code Snippet

```cpp
// restricted_cookie_manager.cc:1135-1183
bool RestrictedCookieManager::ValidateAccessToCookiesAt(
    const GURL& url,
    const net::SiteForCookies& site_for_cookies,
    const url::Origin& top_frame_origin,
    const net::CanonicalCookie* cookie_being_set) {
  if (origin_.opaque()) {
    receiver_.ReportBadMessage("Access is denied in this context");
    return false;
  }

  bool site_for_cookies_ok =
      BoundSiteForCookies().IsEquivalent(site_for_cookies);
  // TODO(crbug.com/402207912): Switch back to a DCEHCK once this condition
  // always holds again.
  if (!site_for_cookies_ok) {
    LOG(ERROR) << ...;  // LOG only, no enforcement!
  }

  bool top_frame_origin_ok = (top_frame_origin == BoundTopFrameOrigin());
  // TODO(crbug.com/402207912): Switch back to a DCEHCK once this condition
  // always holds again.
  if (!top_frame_origin_ok) {
    LOG(ERROR) << ...;  // LOG only, no enforcement!
  }

  // ... metrics recording ...

  if (origin_.IsSameOriginWith(url))
    return true;  // Returns true even if site_for_cookies/top_frame_origin wrong!

  receiver_.ReportBadMessage("Incorrect url origin");
  return false;
}
```

The browser has the correct values in `BoundSiteForCookies()` (from `isolation_info_.site_for_cookies()`) and `BoundTopFrameOrigin()` (from `isolation_info_.top_frame_origin()`), but uses the renderer-supplied values for actual cookie access decisions.

## Attack Scenario

1. A compromised renderer hosting `https://victim.com` sends a `GetAllForUrl` mojo call with:
   - `url = https://victim.com/` (passes origin check)
   - `site_for_cookies = SiteForCookies(https://victim.com/)` (lying -- actual page is cross-site iframe)
   - `top_frame_origin = https://victim.com/` (lying -- actual top frame is different)
2. The `ValidateAccessToCookiesAt` function logs the mismatch but does NOT reject the request
3. `MakeOptionsForGet()` uses the spoofed `site_for_cookies` to compute SameSite context as "same-site"
4. This causes `SameSite=Lax` and `SameSite=Strict` cookies to be included that should have been excluded (because the actual context is cross-site)
5. The compromised renderer gains access to SameSite-restricted cookies it should not have

This is especially impactful because SameSite cookies are a CSRF defense mechanism. By spoofing the site_for_cookies, a compromised renderer in a cross-site iframe can bypass SameSite restrictions on cookies it should not have access to.

## Impact

- **Severity**: Medium-High (SameSite cookie bypass, requires compromised renderer)
- **Requires compromised renderer**: Yes
- **Security principle violated**: Browser-authoritative values should be used for security decisions, not renderer-supplied values
- The TODO comment (crbug.com/402207912) explicitly acknowledges this was previously a DCHECK and was intentionally weakened
- SameSite cookies are a critical CSRF defense mechanism
- The browser already has the correct values but does not use them

## VRP Value Rating

Medium-High - While this requires a compromised renderer, it enables escalation beyond what the compromised renderer should be able to achieve. A compromised renderer in a cross-site iframe can access SameSite=Lax/Strict cookies of its origin that should be blocked due to the cross-site context. This is a defense-in-depth failure at the network service trust boundary.

### Additional Impact: Third-Party Cookie Blocking Bypass

The renderer-supplied `site_for_cookies` and `top_frame_origin` also flow into `CookieSettings::IsCookieAccessible()` via `SetCanonicalCookie()` (line 789-791), which determines whether third-party cookie blocking applies. By sending a `site_for_cookies` that makes the request appear same-site, a compromised renderer in a cross-site iframe can bypass third-party cookie blocking for its origin's cookies. The `GetCookieSettingWithMetadata()` function uses these values to determine the cookie access policy.

Multiple TODO comments acknowledge this: `// TODO(morlovich): Try to validate site_for_cookies as well.` (lines 548, 788) and `// TODO when crbug.com/40093296 "Don't trust |site_for_cookies| provided by the renderer" is fixed.` (url_loader.cc line 2246).
