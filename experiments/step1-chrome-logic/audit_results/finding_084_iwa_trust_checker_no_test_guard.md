# Finding 084: IWA Trust Checker Testing Bypass Has No CHECK_IS_TEST Guard

## Summary

The `IsolatedWebAppTrustChecker` has `SetTrustedWebBundleIdsForTesting()` and `AddTrustedWebBundleIdForTesting()` functions that are NOT guarded by `CHECK_IS_TEST()`. These functions exist in release binaries and bypass ALL trust checks including the blocklist.

## Affected Files

- `chrome/browser/web_applications/isolated_web_apps/isolated_web_app_trust_checker.cc:185-187` — Testing trust bypass in production code
- `chrome/browser/web_applications/isolated_web_apps/isolated_web_app_trust_checker.cc:248-264` — Setter functions without CHECK_IS_TEST

## Details

```cpp
// isolated_web_app_trust_checker.cc:185-187
if (GetTrustedWebBundleIdsForTesting().contains(web_bundle_id)) {
    return base::ok();  // Bypasses ALL checks: allowlist, blocklist, policy
}

// isolated_web_app_trust_checker.cc:248-264
// IN-TEST — but no CHECK_IS_TEST() guard!
void SetTrustedWebBundleIdsForTesting(...) {
    GetTrustedWebBundleIdsForTesting() = ...;
}
void AddTrustedWebBundleIdForTesting(...) {
    GetTrustedWebBundleIdsForTesting().insert(...);
}
```

The testing set is a `NoDestructor<base::flat_set>` — it persists for the process lifetime.

Additionally used in production code at `iwa_permissions_policy_cache.cc:569`:
```cpp
!IsolatedWebAppTrustChecker::IsTrustedForTesting(origin.web_bundle_id())
// ^ Used to skip entitlement filtering
```

## Attack Scenario

1. If any code path in release Chrome can reach `AddTrustedWebBundleIdForTesting`, it would bypass all trust verification
2. The bypass skips even blocklist checks — blocklisted IWAs would be allowed
3. The function is not dead code; `IsTrustedForTesting()` is called from production permission policy cache code
4. Any future refactoring that accidentally calls the setter creates a full trust bypass

## Impact

- **Architectural risk**: Testing bypass in release binary with no runtime guard
- **Complete trust bypass**: Skips allowlist, blocklist, and policy verification
- **Production code dependency**: `IsTrustedForTesting()` is used in production permission filtering

## VRP Value

**Medium** — No known production call path to the setter, but the lack of CHECK_IS_TEST() in a trust-critical code path is a defense-in-depth failure.
