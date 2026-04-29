# Finding 176: FedCM Active Mode and Conditional Mediation Bypass API Permission/Embargo Checks

## Summary
The `CanBypassPermissionStatusCheck()` function allows FedCM requests in active mode (`RpMode::kActive`) and conditional mediation mode to completely skip the FedCM API permission status check. This means that even when a user has disabled FedCM in settings or is under embargo (due to repeated dismissals), an active-mode FedCM request will still proceed to contact the IdP and show UI. This effectively makes the user's preference to disable FedCM unenforceable in active mode.

## Affected Files
- `content/browser/webid/request_service.cc:137-146` -- `CanBypassPermissionStatusCheck()` returns true for active mode
- `content/browser/webid/request_service.cc:458-467` -- Permission check skipped in `RequestToken()`
- `content/browser/webid/request_service.cc:1039-1045` -- Permission check skipped in `MaybeShowAccountsDialog()`
- `content/browser/webid/request_service.cc:1543-1548` -- Permission check skipped in `OnAccountSelected()`

## Details
```cpp
bool CanBypassPermissionStatusCheck(
    const blink::mojom::RpMode& rp_mode,
    const MediationRequirement& mediation_requirement) {
  // Embargo or browser settings should not affect active mode. Since
  // conditional flow isn't intrusive which was the main reason we added such
  // controls, we can bypass the check for it as well.
  return rp_mode == RpMode::kActive ||
         (IsAutofillEnabled() &&
          mediation_requirement == MediationRequirement::kConditional);
}
```

This is used as:
```cpp
if (!CanBypassPermissionStatusCheck(rp_mode_, mediation_requirement_)) {
    if (permission_status != FederatedApiPermissionStatus::GRANTED) {
        // ... error handling ...
    }
}
```

The `rp_mode` is controlled by the renderer via the mojom `IdentityProviderGetParameters::mode` field. A compromised or malicious website can specify `RpMode::kActive` to bypass all permission checks.

## Attack Scenario
1. User visits website.com and dismisses the FedCM prompt multiple times, triggering embargo.
2. User may also explicitly disable FedCM in settings (BLOCKED_SETTINGS).
3. Website.com changes its FedCM request to use active mode (`mode: "active"`), which requires a user gesture.
4. On the next visit, the user clicks anything on the page (providing transient user activation).
5. The active-mode FedCM request bypasses the embargo/settings check entirely.
6. The FedCM dialog is shown despite the user having previously indicated they do not want FedCM on this site.
7. Credentialed requests are sent to the IdP's accounts endpoint, enabling tracking.

## Impact
- User preference to disable FedCM (via settings or embargo) is unenforceable for active-mode requests.
- IdPs receive credentialed requests (with cookies) to their accounts endpoint even when the user has explicitly blocked FedCM, enabling tracking.
- The embargo mechanism (designed to prevent harassment after repeated dismissals) is completely ineffective in active mode.
- This is a design-level issue, not an implementation bug, but the security implications are significant.

## VRP Value
**Medium** -- While active mode was intentionally designed to bypass embargo (per the comment), the bypass extends to `BLOCKED_SETTINGS` which represents an explicit user choice. The credentialed fetch to the IdP's accounts endpoint reveals the user's identity to the IdP regardless of the user's preference. This does not require a compromised renderer -- any website can use active mode.
