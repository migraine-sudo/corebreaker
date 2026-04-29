# Finding 142: Prefetch Client Hints Cross-Site Behavior Configurable to Leak All Hints

## Summary
The `kPrefetchClientHintsCrossSiteBehavior` feature parameter controls which Client Hints headers are sent with cross-site prefetch requests. The default is `kLowEntropy` (only default hints), but it can be configured via field trial to `kAll`, which would send ALL client hints (including high-entropy ones like `Sec-CH-UA-Full-Version-List`, `Sec-CH-UA-Platform-Version`, etc.) to cross-site prefetch targets. This would create a fingerprinting vector where any site can trigger a cross-site prefetch and receive detailed device/browser information without user consent or awareness.

## Affected Files
- `content/browser/preloading/prefetch/prefetch_features.cc` (lines 23-35) - Feature definition and parameter
- `content/browser/preloading/prefetch/prefetch_features.h` (lines 38-55) - Enum and parameter declaration
- `content/browser/preloading/prefetch/prefetch_resource_request_utils.cc` (lines 330-349) - Client hints filtering logic

## Details
```cpp
// prefetch_features.cc:23-35
BASE_FEATURE(kPrefetchClientHints, base::FEATURE_ENABLED_BY_DEFAULT);

constexpr base::FeatureParam<PrefetchClientHintsCrossSiteBehavior>::Option
    kPrefetchClientHintsCrossSiteBehaviorOptions[] = {
        {PrefetchClientHintsCrossSiteBehavior::kNone, "none"},
        {PrefetchClientHintsCrossSiteBehavior::kLowEntropy, "low_entropy"},
        {PrefetchClientHintsCrossSiteBehavior::kAll, "all"},
};
const base::FeatureParam<PrefetchClientHintsCrossSiteBehavior>
    kPrefetchClientHintsCrossSiteBehavior{
        &kPrefetchClientHints, "cross_site_behavior",
        PrefetchClientHintsCrossSiteBehavior::kLowEntropy,
        &kPrefetchClientHintsCrossSiteBehaviorOptions};
```

```cpp
// prefetch_resource_request_utils.cc:330-349
const bool is_cross_site = prefetch_request.IsCrossSiteRequest(origin);
const auto cross_site_behavior =
    features::kPrefetchClientHintsCrossSiteBehavior.Get();
if (!is_cross_site ||
    cross_site_behavior ==
        features::PrefetchClientHintsCrossSiteBehavior::kAll) {
    request_headers.MergeFrom(client_hints_headers);
} else if (cross_site_behavior ==
           features::PrefetchClientHintsCrossSiteBehavior::kLowEntropy) {
    for (const auto& [ch, header] : network::GetClientHintToNameMap()) {
        if (blink::IsClientHintSentByDefault(ch)) {
            // Only add low-entropy hints
        }
    }
}
```

The `kAll` mode sends the full set of Client Hints to any cross-site prefetch target. Since speculation rules can be injected by any page (including attacker-controlled pages), setting this parameter to `kAll` via a field trial could enable passive fingerprinting of users through prefetch.

## Attack Scenario
1. If a field trial or enterprise policy sets `cross_site_behavior=all`
2. `https://evil.com` includes speculation rules to prefetch `https://fingerprint-tracker.com/collect`
3. The prefetch request to `fingerprint-tracker.com` includes ALL client hints: full UA string, platform version, device model, screen dimensions, etc.
4. `fingerprint-tracker.com` receives a detailed device fingerprint without the user ever visiting the site
5. No user consent dialogs or permission prompts are shown

Even in the default `kLowEntropy` mode, the low-entropy hints still provide some fingerprinting surface (browser brand, major version, mobile/desktop, platform).

## Impact
Medium - In default configuration, only low-entropy hints are sent cross-site. However, the `kAll` option exists as a field trial parameter and could be inadvertently enabled. The comment in the code (TODO crbug.com/41497015) acknowledges this is a temporary control.

## VRP Value
Low
