# Finding 143: Prerender Activation Parameter Mismatch Check Can Be Disabled via Kill Switch

## Summary
The `kPrerenderActivationCheckForCommitNavigationParams` feature flag is a "kill switch" that, when disabled, completely skips the comparison of `CommitNavigationParams` between the prerender and activation navigation. Furthermore, even when enabled, the check for `is_overriding_user_agent` is skipped for speculation-rule-triggered prerenders. This means a prerender fetched with one User-Agent string can be activated by a navigation expecting a different User-Agent, potentially causing the server to serve content mismatched with the client's actual UA.

## Affected Files
- `content/browser/preloading/prerender/prerender_host.cc` (lines 1346-1369) - Kill switch and partial mismatch

## Details
```cpp
// prerender_host.cc:1346-1348
// Kill switch.
BASE_FEATURE(kPrerenderActivationCheckForCommitNavigationParams,
             base::FEATURE_ENABLED_BY_DEFAULT);

// prerender_host.cc:1350-1369
PrerenderHost::ActivationNavigationParamsMatch
PrerenderHost::AreCommitNavigationParamsCompatibleWithNavigation(
    const blink::mojom::CommitNavigationParams& potential_activation) {
  if (!base::FeatureList::IsEnabled(
          kPrerenderActivationCheckForCommitNavigationParams)) {
    return ActivationNavigationParamsMatch::kOk;
  }

  // A mitigation for DCHECK failures happening on Android Desktop. Tentatively
  // allowing parameter discrepancies at this point for prerender triggered by
  // speculation rules to narrow the mitigation scope. See crbug.com/40252581
  // and crbug.com/461578988 for details.
  if (!IsSpeculationRuleType(trigger_type()) &&
      (potential_activation.is_overriding_user_agent !=
       commit_params_is_overriding_user_agent_)) {
    return ActivationNavigationParamsMatch::kIsOverridingUserAgent;
  }

  return ActivationNavigationParamsMatch::kOk;
}
```

Key issues:
1. **Kill switch**: If `kPrerenderActivationCheckForCommitNavigationParams` is disabled, ALL commit navigation parameter checks are bypassed
2. **Speculation rules exemption**: For speculation-rule-triggered prerenders (the most common case), the `is_overriding_user_agent` check is always skipped, meaning a prerender fetched with a custom UA can be activated by a navigation expecting the default UA
3. **WebView header mismatch**: `ShouldAllowPartialParamMismatchOfPrerender2` (line 1055-1057) relaxes checks for WebView, allowing initiator, transition type, and X-header mismatches

## Attack Scenario
1. A page triggers a prerender of `https://target.com/adaptive-page` which serves different content based on User-Agent
2. The prerender is fetched with User-Agent "Chrome Desktop" (based on the referring page's UA override setting)
3. The user navigates to the same URL, but the actual navigation would use a different UA (e.g., because UA override was toggled between prerender and navigation)
4. The prerender activates with content served for the wrong User-Agent
5. While mostly a functionality issue, this could have security implications if the server makes security decisions based on UA (e.g., serving different authentication flows for mobile vs desktop)

## Impact
Low - Primarily a content mismatch issue rather than a direct security vulnerability. The kill switch is currently enabled.

## VRP Value
Low
