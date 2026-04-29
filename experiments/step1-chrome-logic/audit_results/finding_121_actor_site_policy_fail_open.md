# Finding 121: Actor Site Policy Fails Open When Optimization Guide Is Unavailable

## Severity: HIGH

## Summary

The Actor's site policy check in `MayActOnUrlInternal()` explicitly "fails open" -- if the Optimization Guide component is not loaded or the service is unavailable, ALL URLs are ACCEPTED. This means on fresh installs, during component update delays, or if optimization guide is disabled, the Actor has NO URL-level safety checks beyond scheme and IP address validation.

## Affected Files

- `chrome/browser/actor/site_policy.cc:269-291` -- Fail-open logic
- `chrome/browser/actor/site_policy.cc:362-389` -- Sensitive URL check also fails open

## Details

```cpp
// site_policy.cc:269-291
// Check that the optimization guide component has loaded. It could be
// missing, for example, if the user has very recently installed chrome and
// the component updater has not yet run. We don't want to reject every URL,
// so we check for this and fail open.
const bool optimization_guide_component_loaded =
    optimization_guide::OptimizationHintsComponentUpdateListener::
        GetInstance()
            ->hints_component_info()
            .has_value();

if (auto* optimization_guide_decider =
        OptimizationGuideKeyedServiceFactory::GetForProfile(profile);
    optimization_guide_decider && optimization_guide_component_loaded &&
    base::FeatureList::IsEnabled(kGlicActionUseOptimizationGuide)) {
  optimization_guide_decider->CanApplyOptimization(
      url, optimization_guide::proto::GLIC_ACTION_PAGE_BLOCK,
      base::BindOnce(&OnOptimizationGuideDecision,
                     std::move(decision_wrapper)));
  return;
}

// Fail open.
decision_wrapper->Accept();
```

Similarly, `MaybeCheckOptimizationGuideForSensitiveUrl()` at line 362-389 returns `base::unexpected(callback)` if the component is not loaded, which results in `not_sensitive=true` being passed to the caller.

Three distinct fail-open conditions:
1. Optimization guide component not yet downloaded (fresh install)
2. `OptimizationGuideKeyedService` not available for the profile
3. `kGlicActionUseOptimizationGuide` feature disabled

## Attack Scenario

1. User freshly installs Chrome and immediately uses the Actor feature
2. The optimization guide component has not yet been downloaded
3. Actor has zero URL-level safety checks (beyond https/IP)
4. Attacker's page uses prompt injection to navigate Actor to known-bad phishing domains
5. The optimization guide blocklist that would normally catch these is not yet available
6. Actor freely navigates to and interacts with the malicious site

Alternative: An attacker could attempt to interfere with the component updater to delay or prevent optimization guide data delivery.

## Impact

- Complete loss of URL-level safety on fresh Chrome installs
- The Actor feature could be available before its safety infrastructure is ready
- Time window between Chrome install and component update is unpredictable
- Also applies if optimization guide service encounters any error

## Remediation

The Actor feature should verify that the optimization guide component is loaded before allowing any actions. If the safety infrastructure is not ready, the Actor should refuse to act rather than operating without safety checks. A "fail closed" approach would be more appropriate for a feature that can interact with web pages on behalf of the user.
