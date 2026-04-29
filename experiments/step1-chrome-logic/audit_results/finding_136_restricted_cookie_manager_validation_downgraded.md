# Finding 136: RestrictedCookieManager site_for_cookies and top_frame_origin Validation Downgraded from DCHECK to LOG(ERROR)

**Severity: MEDIUM**

**Component:** `services/network/restricted_cookie_manager.cc`

## Summary

In `RestrictedCookieManager::ValidateAccessToCookiesAt()`, the checks that verify `site_for_cookies` and `top_frame_origin` match the browser-bound values have been downgraded from `DCHECK` (which would crash in debug builds and kill the renderer in release) to `LOG(ERROR)` with a TODO referencing crbug.com/402207912. This means a compromised renderer can supply arbitrary `site_for_cookies` and `top_frame_origin` values that do NOT match what the browser process expects, and the operation proceeds anyway.

## Vulnerable Code

```cpp
// services/network/restricted_cookie_manager.cc:1135-1183
bool RestrictedCookieManager::ValidateAccessToCookiesAt(
    const GURL& url, const net::SiteForCookies& site_for_cookies,
    const url::Origin& top_frame_origin, ...) {
  ...
  bool site_for_cookies_ok = BoundSiteForCookies().IsEquivalent(site_for_cookies);
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
  // ... continues to allow the operation even if both checks fail
```

## Impact

The `site_for_cookies` and `top_frame_origin` values supplied by the renderer directly influence:
1. **SameSite cookie context computation** - `MakeOptionsForGet()` and `MakeOptionsForSet()` in the same file use `site_for_cookies` and `top_frame_origin` passed from the renderer to call `ShouldIgnoreSameSiteRestrictions()` and `ComputeSameSiteContext*()`. A renderer that lies about `site_for_cookies` can cause SameSite=Lax/Strict cookies to be included in what should be cross-site requests.
2. **Third-party cookie blocking** - `IsCookieAccessible()` uses `site_for_cookies` and `top_frame_origin` for its decision. A mismatch could cause third-party cookie blocking to be bypassed.
3. **Cookie change listeners** - The `Listener` inner class stores these renderer-supplied values and uses them for filtering.

Additionally note the long-standing TODO at line 548:
```cpp
// TODO(morlovich): Try to validate site_for_cookies as well.
```

This means `site_for_cookies` has NEVER been validated against browser-side truth in `GetAllForUrl()` even when the DCHECK was active -- only the URL origin was validated. The downgraded check at `ValidateAccessToCookiesAt` was the only remaining defense.

## Attack Scenario

A compromised renderer could:
1. Obtain a `RestrictedCookieManager` interface bound to `victim.com`
2. Call `GetAllForUrl()` with the correct URL but a spoofed `site_for_cookies` matching `victim.com` (when the actual embedding context is `attacker.com`)
3. The spoofed `site_for_cookies` makes the request appear first-party, bypassing SameSite restrictions
4. SameSite=Lax/Strict cookies would be returned that should not be accessible in a cross-site context

## Rating Justification

MEDIUM: Requires a compromised renderer process. However, the entire point of the browser/renderer security boundary for cookies is to prevent a compromised renderer from escalating cookie access. This downgrade weakens that boundary. The presence of the TODO suggests this is a known temporary regression.

## Related Code

- `MakeOptionsForSet()` at line 76-100 uses renderer-supplied values
- `MakeOptionsForGet()` at line 102-128 uses renderer-supplied values
- `SetCanonicalCookie()` at line 788 uses renderer `site_for_cookies` for `IsCookieAccessible()`
