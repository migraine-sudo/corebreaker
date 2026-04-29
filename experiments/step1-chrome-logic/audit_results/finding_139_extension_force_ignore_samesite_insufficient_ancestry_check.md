# Finding 139: Extension-Based SameSite Bypass via force_ignore_site_for_cookies with Incomplete Ancestor Walk

**Severity: MEDIUM**

**Component:** `services/network/url_loader_util.cc`, `services/network/url_loader.cc`

## Summary

The `ShouldForceIgnoreSiteForCookies()` function bypasses ALL SameSite restrictions (Strict and Lax) when the request originates from or passes through a Chrome Extension that has CORS origin access list entries. The function explicitly acknowledges it cannot walk the full frame tree from the network service, and instead performs an incomplete check that only validates the direct initiator. This means an extension-embedded cross-site iframe chain could result in SameSite cookies being sent when they should not be.

## Vulnerable Code

```cpp
// services/network/url_loader_util.cc:223-279
bool ShouldForceIgnoreSiteForCookies(
    const GURL& url,
    const std::optional<url::Origin>& request_initiator,
    const net::SiteForCookies& site_for_cookies,
    const cors::OriginAccessList& origin_access_list) {
  // Ignore site for cookies in requests from an initiator covered by the
  // same-origin-policy exclusions in `origin_access_list_` (typically requests
  // initiated by Chrome Extensions).
  if (request_initiator.has_value() &&
      cors::OriginAccessList::AccessState::kAllowed ==
          origin_access_list.CheckAccessState(request_initiator.value(), url)) {
    return true;  // ALL SameSite restrictions bypassed
  }

  // ... second check path:
  // Ideally we would walk up the frame tree and check that each ancestor is
  // first-party to the main frame (treating the `origin_access_list_`
  // exceptions as "first-party").  But walking up the tree is not possible in
  // //services/network and so we make do with just checking the direct
  // initiator of the request.
```

When this returns `true`, the cookie context computation short-circuits to `MakeInclusive()`:

```cpp
// net/cookies/cookie_util.cc:933-934
if (force_ignore_site_for_cookies)
    return CookieOptions::SameSiteCookieContext::MakeInclusive();
```

This means ALL SameSite cookies (including Strict) are sent.

## Security Concern

1. **Incomplete frame tree check**: The code comments acknowledge this is an approximation. In a scenario like: `extension page -> cross-site iframe (attacker.com) -> subresource to victim.com`, the `site_for_cookies` would be the extension origin, the initiator would be `attacker.com`, and the URL would be `victim.com`. The second code path checks if the extension can access both the initiator and the target, AND if they are same-site. This `are_initiator_and_target_same_site` check prevents the worst case, but does NOT prevent the first code path from triggering when the initiator IS the extension.

2. **First code path is overly broad**: If an extension makes a request (as initiator) to any URL, and the extension's origin_access_list covers that URL (which is common for extensions with broad host permissions), then SameSite restrictions are completely bypassed. This means any extension with `<all_urls>` permission can force SameSite=Strict cookies to be sent on cross-site requests it initiates.

3. **Applied at the network level**: This bypass happens in `ConfigureUrlRequest()` which sets it on the `net::URLRequest` object. It affects all cookie decisions downstream.

4. **Identical code duplication**: The same logic exists in both `url_loader_util.cc` (line 223) and `url_loader.cc` (line 2583), increasing maintenance risk.

## Rating Justification

MEDIUM: Requires a malicious or compromised extension with appropriate host permissions. However, extensions with `<all_urls>` or broad host permissions are common. The bypass allows SameSite=Strict cookies to be sent in cross-site contexts initiated by the extension, which could be used for CSRF-like attacks against sites that rely on SameSite=Strict for protection. The code acknowledges this limitation but has not addressed it.

## Related Code

- `services/network/network_service_network_delegate.cc:306-310` - Network delegate hook
- `net/cookies/cookie_util.cc:933-934` - Context becomes fully inclusive
- `net/cookies/cookie_util.cc:962-964` - Script context also becomes inclusive
