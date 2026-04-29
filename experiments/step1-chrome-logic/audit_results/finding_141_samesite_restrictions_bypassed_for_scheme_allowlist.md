# Finding 141: SameSite Restrictions Bypassed for Scheme Allowlist (chrome://, Extensions) via ShouldIgnoreSameSiteRestrictions

**Severity: LOW**

**Component:** `services/network/cookie_settings.cc`

## Summary

`CookieSettings::ShouldIgnoreSameSiteRestrictions()` bypasses SameSite cookie restrictions for any request where the `top_level_origin`'s scheme is in the `secure_origin_cookies_allowed_schemes_` set (typically `chrome-extension`) or the origin itself is in `secure_origin_cookies_allowed_origins_`. This function is called from `RestrictedCookieManager` to compute the SameSite context for both GET and SET operations, setting `force_ignore_site_for_cookies = true` which makes the SameSite context fully inclusive (Strict + Lax cookies always sent).

## Vulnerable Code

```cpp
// services/network/cookie_settings.cc:179-192
bool CookieSettings::ShouldIgnoreSameSiteRestrictions(
    const GURL& url,
    const net::SiteForCookies& site_for_cookies,
    const url::Origin& top_level_origin) const {
  if (!url.SchemeIsCryptographic()) {
    return false;
  }
  if (secure_origin_cookies_allowed_schemes_.contains(
          top_level_origin.scheme()) &&
      !site_for_cookies.IsNull()) {
    return true;
  }
  return secure_origin_cookies_allowed_origins_.contains(top_level_origin);
}
```

The same pattern also appears in `ShouldAlwaysAllowCookies()`:

```cpp
// services/network/cookie_settings.cc:226-241
bool CookieSettings::ShouldAlwaysAllowCookies(
    const GURL& url, const GURL& first_party_url) const {
  if (url.SchemeIsCryptographic()) {
    if (secure_origin_cookies_allowed_schemes_.contains(
            first_party_url.scheme())) {
      return true;  // Bypasses third-party cookie blocking entirely
    }
    if (secure_origin_cookies_allowed_origins_.contains(
            url::Origin::Create(first_party_url))) {
      return true;
    }
  }
  return (matching_scheme_cookies_allowed_schemes_.contains(url.scheme()) &&
          url.SchemeIs(first_party_url.scheme()));
}
```

## Security Concern

1. **Broad SameSite bypass**: Any frame embedded under a `chrome-extension://` top-level origin (or other allowed scheme/origin) gets full SameSite bypass for requests to HTTPS URLs. This means a malicious extension page embedding a cross-origin iframe would cause that iframe's requests to carry SameSite=Strict cookies.

2. **Also bypasses third-party cookie blocking**: `ShouldAlwaysAllowCookies()` returns true for any HTTPS URL when the first-party URL has an allowed scheme. This completely bypasses third-party cookie blocking for extension contexts.

3. **Configurable via network context**: The `secure_origin_cookies_allowed_schemes_` is set via `set_secure_origin_cookies_allowed_schemes()` which is called from the browser process when configuring the NetworkContext. While normally only `chrome-extension` is added, the mechanism is generic enough to be misconfigured.

4. **site_for_cookies non-null check**: The `!site_for_cookies.IsNull()` check in `ShouldIgnoreSameSiteRestrictions` is the only guard beyond the scheme check. A null `site_for_cookies` would prevent the bypass, but most extension pages have a non-null site_for_cookies.

## Rating Justification

LOW: This is by design for Chrome Extensions which need to operate across origins. The restriction to cryptographic schemes provides some protection. However, it creates a significant attack surface for malicious extensions, as any extension that embeds web content can effectively bypass SameSite for that content. This is a known design tradeoff rather than a bug.

## Related Code

- `services/network/cookie_settings.h:58-61` - Where allowed schemes are configured
- `services/network/restricted_cookie_manager.cc:83-96` - Where the bypass is consumed
- `services/network/cookie_settings.h:224-226` - Storage for allowed schemes/origins
