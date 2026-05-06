# Finding 239: DIP Grants SharedArrayBuffer Access Without Process Isolation on Low-Memory Android

## Summary

Document-Isolation-Policy (DIP) grants `crossOriginIsolated` capability (and thus SharedArrayBuffer access) with `kConcrete` mode even on platforms where site isolation is disabled (low-memory Android devices). The feature flag `kDocumentIsolationPolicyWithoutSiteIsolation` (ENABLED by default) explicitly allows DIP content to run in unpartitioned ("AllowsAnySite") processes, undermining the core security assumption of DIP: that cross-origin content is guaranteed to be out-of-process.

## Severity: Medium (Spectre-class side-channel amplification on specific platforms)

## Affected Component

- Document-Isolation-Policy process isolation guarantees
- SharedArrayBuffer access control
- `content/browser/process_lock.cc:166-177`
- `content/common/features.cc:198-199`
- `content/browser/renderer_host/navigation_request.cc:11358-11438`

## Root Cause

Three features interact to create this gap:

### 1. DIP is ENABLED by default
`services/network/public/cpp/features.cc:355`:
```cpp
BASE_FEATURE(kDocumentIsolationPolicy, base::FEATURE_ENABLED_BY_DEFAULT);
```

### 2. DIP without site isolation is ENABLED by default
`content/common/features.cc:198-199`:
```cpp
BASE_FEATURE(kDocumentIsolationPolicyWithoutSiteIsolation,
             base::FEATURE_ENABLED_BY_DEFAULT);
```

### 3. Process lock relaxation for DIP
`content/browser/process_lock.cc:166-177`:
```cpp
if (AllowsAnySite() &&
    !SiteIsolationPolicy::UseDedicatedProcessesForAllSites() &&
    !SiteIsolationPolicy::AreDynamicIsolatedOriginsEnabled() &&
    base::FeatureList::IsEnabled(
        features::kDocumentIsolationPolicyWithoutSiteIsolation)) {
  return true;  // DIP content can run in any-site process
}
```

### 4. Chrome Android does NOT override COI mode
Unlike Android WebView which returns `kLogical` (no SAB), Chrome Android uses the default `OriginSupportsConcreteCrossOriginIsolation()` which returns `true`, granting `kConcrete` mode = full SAB access.

### 5. No mode downgrade when isolation is missing
`navigation_request.cc:11413-11416` (TODO comment):
```cpp
// TODO(crbug.com/342364564): Support platforms that do not support OOPIF 
// and return an AgentClusterKey with a CrossOriginIsolationKey that has a 
// kLogical cross-origin isolation mode.
```

## Attack Scenario

1. On a low-memory Android Chrome device (site isolation disabled):
2. Attacker page at `evil.com` sets DIP header:
   ```
   Document-Isolation-Policy: isolate-and-credentialless
   ```
3. Browser grants `kConcrete` COI → SAB access enabled
4. `evil.com` page is placed in a shared process (no dedicated process)
5. Victim page at `bank.com` may share the same renderer process
6. Attacker uses SAB + `SharedArrayBuffer` to create high-resolution timer
7. Timer enables Spectre-V1 speculative execution attacks against `bank.com` data in the same address space

## Why This Is Significant

DIP's security model explicitly states (in the code comment at `local_dom_window.cc:2539-2540`):
> "with DIP, the cross-origin iframe is guaranteed to be out-of-process"

This guarantee does NOT hold on low-memory Android, yet the security bypass (granting COI without checking the `kCrossOriginIsolated` permissions policy) still applies.

The permission policy bypass at `local_dom_window.cc:2545-2548`:
```cpp
bool permission_policy_allows_coi =
    IsFeatureEnabled(PermissionsPolicyFeature::kCrossOriginIsolated) ||
    GetPolicyContainer()->GetPolicies().cross_origin_isolation_enabled_by_dip;
```

## Limitations

- Only affects low-memory Android Chrome devices where full site isolation is disabled
- Actual exploitation requires Spectre-class attack expertise
- The Agent-level isolation in the renderer still prevents direct SAB sharing (just not timing attacks)
- Chrome's partial site isolation may still isolate high-value sites (banks, Google)

## Suggested Fix

On platforms without strict site isolation, DIP should grant `kLogical` mode (no SAB) instead of `kConcrete`:

```cpp
AgentClusterKey::CrossOriginIsolationKey ComputeKey(...) {
  auto mode = CrossOriginIsolationMode::kConcrete;
  if (!SiteIsolationPolicy::UseDedicatedProcessesForAllSites() &&
      base::FeatureList::IsEnabled(kDocumentIsolationPolicyWithoutSiteIsolation)) {
    mode = CrossOriginIsolationMode::kLogical;
  }
  return AgentClusterKey::CrossOriginIsolationKey(origin, mode);
}
```

## Platform

Chrome for Android on devices with ≤2GB RAM (where site isolation is disabled).

## Files

- `content/common/features.cc:198-199` (kDocumentIsolationPolicyWithoutSiteIsolation ENABLED)
- `content/browser/process_lock.cc:166-177` (AllowsAnySite relaxation)
- `content/browser/renderer_host/navigation_request.cc:11358-11438` (COI key computation)
- `content/browser/site_info.cc:1215-1225` (RequiresDedicatedProcess)
- `third_party/blink/renderer/core/frame/local_dom_window.cc:2534-2549` (permission policy bypass)
- `services/network/public/cpp/features.cc:355` (DIP enabled by default)
