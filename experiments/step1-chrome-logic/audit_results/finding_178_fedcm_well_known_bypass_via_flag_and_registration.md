# Finding 178: FedCM Well-Known Enforcement Can Be Bypassed via Feature Flag and IdP Registration

## Summary
The well-known file enforcement -- a critical anti-tracking mechanism in FedCM -- can be bypassed in multiple ways: (1) via the `kFedCmWithoutWellKnownEnforcement` feature flag, (2) via the `force_skip_well_known_enforcement` parameter that is set when IdP registration is enabled, and (3) when both `getUserInfo()` and `disconnect()` use the `IsIdPRegistrationEnabled()` flag to skip well-known checks. These bypasses allow an IdP to serve arbitrary config URLs without being constrained by the well-known file, undermining the privacy protections the well-known file provides.

## Affected Files
- `content/browser/webid/config_fetcher.cc:383-389` -- `ShouldSkipWellKnownEnforcementForIdp()` with two bypass paths
- `content/browser/webid/config_fetcher.cc:69-70` -- `force_skip_well_known_enforcement` set from request
- `content/browser/webid/user_info_request.cc:166-172` -- Well-known skip when IdP registration enabled
- `content/browser/webid/disconnect_request.cc:114-119` -- Well-known skip when IdP registration enabled

## Details
In `config_fetcher.cc`:
```cpp
bool ConfigFetcher::ShouldSkipWellKnownEnforcementForIdp(
    const FetchResult& fetch_result) {
  if (IsWithoutWellKnownEnforcementEnabled()) {
    return true;
  }
  if (fetch_result.force_skip_well_known_enforcement) {
    return true;
  }
  // ...
}
```

In `user_info_request.cc` and `disconnect_request.cc`:
```cpp
// TODO(crbug.com/390626180): It seems ok to ignore the well-known checks in
// all cases here. However, keeping this unchanged for now when the IDP
// registration API is not enabled since we only really need this for that
// case.
config_fetcher_->Start(
    {{idp_config_url, webid::IsIdPRegistrationEnabled()}},
    // ...
```

The second argument to the FetchRequest is `force_skip_well_known_enforcement`. When `kFedCmIdPRegistration` is enabled, well-known checks are entirely skipped for both `getUserInfo()` and `disconnect()`.

## Attack Scenario
1. A malicious IdP registers itself via the IdP Registration API (when `kFedCmIdPRegistration` flag is enabled).
2. The registered IdP serves a config URL pointing to a malicious config file.
3. When the RP calls `getUserInfo()` or `disconnect()`, the browser fetches the config but skips well-known validation.
4. The IdP can claim any `accounts_endpoint` or `disconnect_endpoint` without the well-known file constraints.
5. This enables the IdP to redirect account/disconnect requests to arbitrary same-origin endpoints, potentially exfiltrating data.
6. The well-known file was designed to limit what endpoints an IdP can declare, and this bypass removes that limit entirely.

## Impact
- The well-known file privacy protection is completely bypassed when IdP registration is enabled.
- A registered IdP can change its endpoints without updating its well-known file.
- The TODO comments suggest the developers believe skipping well-known checks is acceptable, but this weakens a fundamental privacy invariant of the FedCM specification.
- When `kFedCmWithoutWellKnownEnforcement` is enabled, ALL well-known checks are skipped globally.

## VRP Value
**Medium** -- Both `kFedCmIdPRegistration` and `kFedCmWithoutWellKnownEnforcement` are behind `FEATURE_DISABLED_BY_DEFAULT` flags. However, the pattern of skipping well-known enforcement in multiple code paths suggests a systemic weakening of a security boundary, and the IdP registration path is actively being developed for production use.
