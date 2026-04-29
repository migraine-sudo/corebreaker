# Finding 157: Payment App Metadata Refresh Uses Origin Comparison Instead of Full Scope Match

## Summary
During the metadata refresh for already-installed payment apps, the crawler matches refetched metadata to installed apps using origin-level comparison (`IsSameOriginWith`) rather than exact scope matching. The code includes a comment acknowledging this weakness: "It is possible (unlikely) to have multiple apps with same origins." This means if two payment apps from the same origin are installed with different scopes, refetched metadata from one app's web manifest could be applied to the wrong app.

## Affected Files
- `components/payments/content/service_worker_payment_app_finder.cc:313-325` - Origin-based matching

## Details
```cpp
// service_worker_payment_app_finder.cc
void OnPaymentAppsCrawledForUpdatedMetadata(...) {
    for (auto& refetched_metadata : refetched_app_metadata) {
      GURL web_app_manifest_url = refetched_metadata.first;
      RefetchedMetadata* data = refetched_metadata.second.get();
      for (auto& app : installed_apps_) {
        // It is possible (unlikely) to have multiple apps with same origins.
        // The proper validation is to store web_app_manifest_url in
        // StoredPaymentApp and confirm that it is the same as the
        // web_app_manifest_url from which metadata is fetched.
        if (crawler_->IsSameOriginWith(GURL(app.second->scope),
                                       web_app_manifest_url)) {
          UpdatePaymentAppMetadata(app.second, data->icon, data->method_name,
                                   data->supported_delegations);
          break;  // Only updates the FIRST matching app!
        }
      }
    }
}
```

The `IsSameOriginWith` check compares only the origin (scheme + host + port), not the full scope path. If two payment apps are registered at:
- `https://pay.example.com/v1/` (scope for app v1)
- `https://pay.example.com/v2/` (scope for app v2)

Metadata fetched for v2's web manifest could be applied to v1's app (or vice versa), because the `break` exits after the first same-origin match.

## Attack Scenario
1. Legitimate payment provider has two payment apps registered at `https://pay.example.com/basic/` and `https://pay.example.com/premium/`
2. Basic app has a generic icon and limited delegations
3. Premium app has a trust-badge icon and full shipping/email delegations
4. During metadata refresh, the crawler fetches updated metadata for both
5. Due to same-origin matching with `break`, the premium metadata could be applied to the basic app (depending on iteration order)
6. The basic app now displays the premium trust-badge icon and claims full delegation support
7. This could mislead users about which app they are selecting, or cause the wrong app to handle payment data it was not designed for

## Impact
Payment app metadata cross-contamination between apps from the same origin. Could lead to user confusion about which payment handler they are selecting, or incorrect delegation support claims. The code comment acknowledges this is a known gap.

## VRP Value
Low
