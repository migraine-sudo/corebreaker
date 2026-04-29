# Finding 083: IWA Managed Allowlist Fail-Open Design

## Summary

The Isolated Web App managed allowlist feature (`kIsolatedWebAppManagedAllowlist`) has a fail-open design: when the feature flag is disabled, both `IsManagedInstallPermitted()` and `IsManagedUpdatePermitted()` unconditionally return `true`, allowing ANY IWA to be enterprise-installed regardless of the allowlist.

## Affected Files

- `chrome/browser/web_applications/isolated_web_apps/key_distribution/iwa_key_distribution_info_provider.cc:155-171` — Fail-open logic
- `chrome/browser/web_applications/isolated_web_apps/key_distribution/features.cc:9` — Feature flag (ENABLED_BY_DEFAULT)

## Details

```cpp
// iwa_key_distribution_info_provider.cc:155-171
bool IwaKeyDistributionInfoProvider::IsManagedInstallPermitted(
    std::string_view web_bundle_id) const {
  bool is_permitted =
      component_ && component_->data.managed_allowlist.contains(web_bundle_id);
  return IsIsolatedWebAppManagedAllowlistEnabled() ? is_permitted : true;
  //                                                                ^^^^
  // FAIL-OPEN: returns true when feature disabled
}
```

The same pattern applies to `IsManagedUpdatePermitted()`.

## Attack Scenario

1. Attacker modifies Chrome launch flags: `--disable-features=IsolatedWebAppManagedAllowlist`
2. Combined with enterprise policy `IsolatedWebAppInstallForceList`, this allows installation of ANY IWA
3. The IWA can claim powerful permissions (direct-sockets, all-screens-capture) 
4. On enterprise-managed devices, a compromised MDM server could push this configuration

## Impact

- **No compromised renderer required**: Configuration-level bypass
- **Privilege escalation**: Bypasses the only mechanism controlling which IWAs can be enterprise-installed
- **Fail-open antipattern**: Disabled feature should deny, not allow
- **Currently ENABLED by default**: The flag is enabled, but disabling it grants more access

## VRP Value

**Medium** — Requires ability to modify Chrome flags or enterprise policy. The fail-open design is a clear antipattern for a security gate.
