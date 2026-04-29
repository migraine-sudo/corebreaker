# Finding 172: Default Search Engine Exempt from Contamination Delay Side-Channel Mitigation

## Summary
The contamination delay mitigation (`kPrefetchStateContaminationMitigation`) introduces a timing delay when serving cross-site prefetched content to obscure whether the prefetch was eligible or ineligible (based on cookie state). However, `ChromePrefetchServiceDelegate::IsContaminationExempt()` exempts the user's default search engine from this mitigation. When the referring page is the user's default search engine, no contamination delay is applied, and the timing side channel remains exploitable. An attacker who controls or becomes the user's default search engine (e.g., through browser hijacking, enterprise policy, or social engineering) can exploit this exemption to detect cookie state for cross-site targets.

## Affected Files
- `chrome/browser/preloading/prefetch/prefetch_service/chrome_prefetch_service_delegate.cc` (lines 114-123) - DSE exemption
- `content/browser/preloading/prefetch/prefetch_service.cc` (lines 1077-1089) - Exemption check

## Details
```cpp
// chrome_prefetch_service_delegate.cc:114-123
bool ChromePrefetchServiceDelegate::IsContaminationExempt(
    const url::Origin& referring_origin) {
  // The default search engine has been chosen by the user and its cross-site
  // navigations have a significant performance impact.
  TemplateURLService* template_url_service =
      TemplateURLServiceFactory::GetForProfile(profile_);
  return template_url_service &&
         template_url_service->GetDefaultSearchProviderOrigin() ==
             referring_origin;
}
```

```cpp
// prefetch_service.cc:1077-1089
if (base::FeatureList::IsEnabled(
        features::kPrefetchStateContaminationMitigation)) {
  const bool is_contamination_exempt =
      delegate_ && params.request().referring_origin().has_value() &&
      delegate_->IsContaminationExempt(
          params.request().referring_origin().value());
  if (!is_contamination_exempt) {
    params.MarkCrossSiteContaminated();
  }
}
```

When `IsContaminationExempt()` returns true:
1. `MarkCrossSiteContaminated()` is NOT called
2. The response's `is_prefetch_with_cross_site_contamination` flag remains false
3. `ContaminationDelayNavigationThrottle::WillProcessResponse()` sees no contamination and proceeds immediately
4. No timing obfuscation is applied

This means the default search engine can determine the cookie eligibility of any cross-site prefetch target by observing navigation timing:
- Prefetch eligible (no cookies): prefetch completes, navigation is instant
- Prefetch ineligible (has cookies): prefetch doesn't happen, navigation takes network time
- Contamination delay would normally obscure this difference, but the exemption removes it

## Attack Scenario
1. A browser hijacker changes the user's default search engine to `https://evil-search.com`
2. `evil-search.com` returns search results pages with speculation rules that prefetch cross-site URLs
3. For each search result, `evil-search.com` prefetches `https://social-network.com/`, `https://banking.com/`, etc.
4. Because `evil-search.com` is the DSE, the contamination delay exemption applies
5. When the user clicks a search result, the navigation timing reveals whether the prefetch was eligible
6. Eligible (instant navigation) = user has no cookies for the target site
7. Ineligible (network-time navigation) = user has cookies for the target site
8. `evil-search.com` builds a profile of which sites the user is logged into

Alternative scenario:
- Enterprise environments where the default search engine is set via policy
- The search engine operator can detect employee cookie state for internal and external sites

## Impact
Medium - The DSE exemption creates a privileged position where the default search engine can perform the exact cookie-state probing that the contamination delay was designed to prevent. While the DSE is "trusted" by the user's choice, browser hijacking is a common attack vector.

## VRP Value
Medium
