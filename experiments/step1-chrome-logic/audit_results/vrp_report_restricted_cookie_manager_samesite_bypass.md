# VRP Report: RestrictedCookieManager SameSite/3PC Bypass via Unvalidated Renderer-Supplied Context

## Title
RestrictedCookieManager does not enforce browser-authoritative site_for_cookies and top_frame_origin, allowing SameSite and third-party cookie bypass

## Severity
Medium-High

## Component
Services > Network > Cookies

## Summary

`RestrictedCookieManager::ValidateAccessToCookiesAt()` in `services/network/restricted_cookie_manager.cc` checks whether renderer-supplied `site_for_cookies` and `top_frame_origin` match browser-side authoritative values, but the check is **not enforced** — mismatches are only logged via `LOG(ERROR)`. The renderer-supplied values then flow into `MakeOptionsForGet()/MakeOptionsForSet()` for SameSite cookie context computation and into `CookieSettings::IsCookieAccessible()` for third-party cookie blocking decisions.

This was explicitly downgraded from a DCHECK per crbug.com/402207912, and multiple TODOs at lines 548, 788, and url_loader.cc:2246 confirm this is a known but unresolved enforcement gap.

## Root Cause

```cpp
// restricted_cookie_manager.cc:1145-1161 (approximate)
// Validation checks renderer-supplied values against browser-authoritative values
// but only LOG(ERROR) on mismatch — does NOT reject the request or kill renderer
if (site_for_cookies != browser_site_for_cookies) {
    LOG(ERROR) << "site_for_cookies mismatch...";
    // No enforcement! Request continues with renderer-supplied value
}
```

## Steps to Reproduce

1. Compromised renderer sends a cookie access request via `RestrictedCookieManager` Mojo interface
2. The renderer supplies a forged `site_for_cookies` matching the target cookie's domain
3. The browser logs an error but uses the renderer-supplied value
4. SameSite cookie context is computed using the forged value → SameSite=Lax/Strict cookies are sent
5. Third-party cookie blocking decision uses the forged `top_frame_origin` → third-party cookies become accessible

## Impact

- **Requires compromised renderer**: Must forge Mojo messages to RestrictedCookieManager
- **SameSite bypass**: Compromised renderer can make any request appear same-site for cookie purposes
- **Third-party cookie blocking bypass**: Forged top_frame_origin defeats 3PC blocking
- **Known issue**: Multiple TODOs acknowledge the gap but no fix is in place
- **Wide scope**: Affects all cookie access through RestrictedCookieManager

## Affected Versions
Latest Chrome stable (tested against current chromium-src HEAD)
