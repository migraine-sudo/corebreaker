# Finding 088: IWA Enterprise-Installed Apps Bypass Entitlement Filtering

## Summary

Enterprise-managed and dev-mode Isolated Web Apps skip entitlement filtering entirely. Their `policy.filtered` equals `policy.unfiltered`, meaning they get ALL claimed permissions policy features (including `direct-sockets`, `all-screens-capture`) without entitlement verification.

## Affected Files

- `chrome/browser/web_applications/isolated_web_apps/iwa_permissions_policy_cache.cc:291-299,566-581` — Entitlement bypass for managed/dev apps

## Details

```cpp
// iwa_permissions_policy_cache.cc:566-581
if (registrar.AppMatches(app_id,
    WebAppFilter::IsIsolatedWebAppWithOnlyUserManagement() &
    !WebAppFilter::IsDevModeIsolatedApp()) &&
    !IsolatedWebAppTrustChecker::IsTrustedForTesting(origin.web_bundle_id())) {
  policy.app_version_for_filtering = iwa->isolation_data()->version();
}

if (policy.app_version_for_filtering) {
  policy.filtered = ApplyEntitlements(policy.unfiltered, ...);
} else {
  policy.filtered = policy.unfiltered;  // NO FILTERING for managed/dev apps
}
```

## Attack Scenario

1. Compromised MDM/enterprise policy server pushes malicious IWA via `IsolatedWebAppInstallForceList`
2. IWA claims `direct-sockets`, `all-screens-capture`, `usb`, etc. in manifest
3. Since it's policy-installed, no entitlement check applies
4. IWA gets full access to all claimed powerful APIs

## Impact

- **No compromised renderer required**: Enterprise policy deployment
- **Privilege escalation**: Full API access without entitlement verification
- **Broad trust delegation**: All managed IWAs implicitly trusted

## VRP Value

**Low-Medium** — By design for enterprise trust model, but creates a wide attack surface via compromised MDM.
