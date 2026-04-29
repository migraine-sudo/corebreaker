# Finding 144: Decoy Request Probability Controlled by Field Trial Enables Cookie Presence Detection

## Summary
The prefetch service sends "decoy" requests for ineligible prefetches (where the user has cookies or service workers for the target) to prevent the referring site from distinguishing between eligible and ineligible prefetches via network timing. However, the decoy probability is controlled by field trial parameters (`ineligible_decoy_request_probability`), defaults to 1.0, and can be set to 0.0. When decoy probability is reduced or disabled, a referring page can detect whether the user has cookies for a cross-site target by observing whether a prefetch request was actually sent to the network.

## Affected Files
- `content/browser/preloading/prefetch/prefetch_params.cc` (lines 59-88) - `PrefetchServiceSendDecoyRequestForIneligblePrefetch()`
- `content/browser/preloading/prefetch/prefetch_service.cc` (lines 108-138) - `ShouldConsiderDecoyRequestForStatus()`

## Details
```cpp
// prefetch_params.cc:59-88
bool PrefetchServiceSendDecoyRequestForIneligblePrefetch(
    bool disabled_based_on_user_settings) {
  if (base::CommandLine::ForCurrentProcess()->HasSwitch(
          "prefetch-proxy-never-send-decoy-requests-for-testing")) {
    return false;
  }
  if (base::CommandLine::ForCurrentProcess()->HasSwitch(
          "prefetch-proxy-always-send-decoy-requests-for-testing")) {
    return true;
  }

  if (base::GetFieldTrialParamByFeatureAsBool(
          features::kPrefetchUseContentRefactor,
          "disable_decoys_based_on_user_settings", true) &&
      disabled_based_on_user_settings) {
    return false;
  }

  double probability = base::GetFieldTrialParamByFeatureAsDouble(
      features::kPrefetchUseContentRefactor,
      "ineligible_decoy_request_probability", 1.0);

  // Clamp to [0.0, 1.0].
  probability = std::max(0.0, probability);
  probability = std::min(1.0, probability);

  return base::RandDouble() < probability;
}
```

Key issues:
1. `disable_decoys_based_on_user_settings` (default: true) can disable decoys entirely based on user preloading settings
2. `ineligible_decoy_request_probability` can be set to 0 via field trial, completely disabling decoys
3. `--prefetch-proxy-never-send-decoy-requests-for-testing` command-line switch works in production builds
4. When decoys are disabled and the referencing site triggers a cross-site prefetch, the site can observe (via Resource Timing or other side channels) whether the prefetch resulted in network activity or was silently dropped, revealing the user's cookie state for the target site

## Attack Scenario
1. Field trial or user settings result in decoy requests being disabled
2. `https://evil.com` includes speculation rules to prefetch `https://social-network.com/profile`
3. If the user has cookies for `social-network.com`: prefetch is ineligible, no decoy is sent, no network request occurs
4. If the user has no cookies: prefetch proceeds normally with a network request
5. `evil.com` can detect whether the prefetch caused network activity (e.g., via shared connection pool timing, server-side logging if colluding with social-network.com, or navigation timing when the user clicks the link)
6. This reveals whether the user is logged into `social-network.com`

## Impact
Medium - When decoys are disabled (which is a supported configuration), cross-site cookie presence detection becomes straightforward. The default configuration (probability=1.0) mitigates this, but the multiple paths to disable decoys create risk.

## VRP Value
Medium
