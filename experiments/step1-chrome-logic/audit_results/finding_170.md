# Finding 170: Extended Preloading Bypasses Domain Allowlist for Prefetch Proxy by Default

## Summary
The `PrefetchAllowAllDomainsForExtendedPreloading` parameter defaults to `true`, meaning any user who has enabled "Enhanced preloading" (extended preloading) in Chrome settings will bypass the domain allowlist check for cross-site prefetches that require the private proxy. Normally, only domains in the prefetch allowlist can trigger proxy-backed prefetches. But with extended preloading enabled and this parameter at its default value, any domain can trigger a prefetch through the private proxy, including domains that serve tracking pixels, phishing pages, or other malicious content.

## Affected Files
- `content/browser/preloading/prefetch/prefetch_params.cc` (lines 53-57) - `allow_all_domains_for_extended_preloading` defaults to true
- `content/browser/preloading/prefetch/prefetch_service.cc` (lines 748-764) - Domain check bypassed

## Details
```cpp
// prefetch_params.cc:53-57
bool PrefetchAllowAllDomainsForExtendedPreloading() {
  return base::GetFieldTrialParamByFeatureAsDouble(
      features::kPrefetchUseContentRefactor,
      "allow_all_domains_for_extended_preloading", true);
}
```

```cpp
// prefetch_service.cc:748-764
if (prefetch_type.IsProxyRequiredWhenCrossOrigin()) {
  bool allow_all_domains =
      PrefetchAllowAllDomains() ||
      (PrefetchAllowAllDomainsForExtendedPreloading() &&
       delegate_->IsExtendedPreloadingEnabled());
  if (!allow_all_domains &&
      !delegate_->IsDomainInPrefetchAllowList(...)) {
    return;  // Not in allowlist, skip
  }
}
```

When `IsExtendedPreloadingEnabled()` returns true (user opted into Enhanced Preloading):
1. `allow_all_domains` is set to `true` regardless of the domain allowlist
2. The `IsDomainInPrefetchAllowList()` check is completely skipped
3. Any web page can trigger a prefetch through the private proxy for any cross-site URL

This means that with extended preloading:
- A malicious page can force the user's browser to prefetch arbitrary URLs through the prefetch proxy
- The proxy receives requests on behalf of the user that may not be part of Google's curated allowlist
- The prefetch proxy itself becomes an open proxy for the referring page's chosen targets
- A page can enumerate which sites the proxy can reach by observing prefetch success/failure

## Attack Scenario
1. User has "Enhanced preloading" enabled in Chrome settings
2. `https://evil.com` includes speculation rules to prefetch `https://internal-service.corp.net/status`
3. Normally this would be blocked because `evil.com` is not in the domain allowlist
4. But with extended preloading enabled, the allowlist check is bypassed
5. The browser sends the prefetch request through the private proxy to `internal-service.corp.net`
6. While the private proxy likely won't reach internal services, the request is still made on the user's behalf
7. For publicly reachable but unlisted domains, the prefetch goes through, creating an SSRF-like vector through the proxy
8. The referring page can observe timing differences to detect whether the prefetch succeeded

## Impact
Medium - Users who opt into Enhanced Preloading (a significant fraction of Chrome users) lose the domain allowlist protection for proxy-backed prefetches. This expands the attack surface of the prefetch proxy to arbitrary domains. While the proxy has its own server-side protections, the browser-side allowlist was a defense-in-depth measure that is completely bypassed.

## VRP Value
Medium
