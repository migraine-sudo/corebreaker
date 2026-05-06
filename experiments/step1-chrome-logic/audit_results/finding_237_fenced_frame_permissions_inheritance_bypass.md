# Finding 237: Fenced Frame Permissions Policy Inheritance Check Bypass

## Summary

`IsFencedFrameRequiredPolicyFeatureAllowed()` in `navigation_request.cc` fails to detect when a required Privacy Sandbox feature is disabled by inherited policy (from a grandparent frame). The function uses `GetAllowlistForFeatureIfExists()` which returns `std::nullopt` when a feature is disabled by inheritance, and the caller interprets `nullopt` as "no restriction exists" rather than "feature is disabled."

This allows a fenced frame to navigate successfully and use Privacy Sandbox capabilities (Attribution Reporting, Private Aggregation, Shared Storage) even when an ancestor page has explicitly disabled those features via Permissions Policy headers.

## Severity: Medium (Permissions Policy Bypass for Privacy Sandbox Features)

## Affected Component

- Fenced Frames (FLEDGE/Protected Audience, Shared Storage)
- Permissions Policy inheritance
- Privacy Sandbox features

## Root Cause

**`services/network/public/cpp/permissions_policy/permissions_policy.cc:378-383`**:
```cpp
std::optional<const PermissionsPolicy::Allowlist>
PermissionsPolicy::GetAllowlistForFeatureIfExists(
    network::mojom::PermissionsPolicyFeature feature) const {
  // Return an empty allowlist when disabled through inheritance.
  if (!IsFeatureEnabledByInheritedPolicy(feature)) {
    return std::nullopt;  // BUG: Returns nullopt for DISABLED features
  }
  // ...
}
```

**`content/browser/renderer_host/navigation_request.cc:10410-10416`**:
```cpp
std::optional<const network::PermissionsPolicy::Allowlist>
    embedder_allowlist = GetParentFrameOrOuterDocument()
                             ->GetPermissionsPolicy()
                             ->GetAllowlistForFeatureIfExists(feature);
if (embedder_allowlist && !embedder_allowlist->MatchesAll()) {
    return false;  // Only rejects if allowlist EXISTS and doesn't match all
}
// Falls through to container policy check when nullopt (disabled by inheritance)
```

The logic error:
1. Grandparent sends `Permissions-Policy: attribution-reporting=()`
2. Parent frame inherits this — feature is DISABLED by inherited policy
3. Parent embeds a fenced frame with `allow="attribution-reporting *"`
4. `GetAllowlistForFeatureIfExists(kAttributionReporting)` on parent returns `nullopt`
5. The `if (embedder_allowlist && ...)` check evaluates to FALSE (nullopt is falsy)
6. Code falls through to container policy check
7. Container policy (`allow` attribute) grants the feature → fenced frame navigates

## Attack Scenario

1. Top-level page (`publisher.com`) sets `Permissions-Policy: attribution-reporting=(), private-aggregation=()` to prevent any cross-origin tracking on their page
2. An embedded ad iframe (`ads.com`) embeds a fenced frame from FLEDGE auction
3. The fenced frame's container policy includes `attribution-reporting *` (set by FLEDGE config)
4. Despite the publisher explicitly disabling attribution-reporting, the fenced frame can:
   - Register attribution sources/triggers
   - Use Private Aggregation API
   - Exfiltrate data via SharedStorage selectURL

## Impact

- **Publisher permission override**: A publisher that explicitly disables Privacy Sandbox tracking features cannot prevent FLEDGE fenced frames from using them
- **Attribution Reporting abuse**: Fenced frames can register attribution events even when the embedding context has disabled it
- **Private Aggregation data exfiltration**: Combined with Finding 232 (filtering_id budget bypass), this amplifies the privacy loss
- **Permissions Policy trust model violation**: The fundamental invariant that child frames cannot have MORE permissions than their ancestors is broken

## Affected Features

Per `kFencedFrameFledgeDefaultRequiredFeatures`:
- `kAttributionReporting`
- `kPrivateAggregation`
- `kSharedStorage`
- `kSharedStorageSelectUrl`

## Preconditions

- Fenced frame must be created from FLEDGE/Protected Audience or Shared Storage API
- The `effective_enabled_permissions_` must include the affected feature
- An ancestor frame (not the direct parent, but a grandparent or higher) must have disabled the feature via Permissions-Policy header
- The direct parent's container policy (`allow` attribute) must grant the feature

## Suggested Fix

```cpp
bool NavigationRequest::IsFencedFrameRequiredPolicyFeatureAllowed(
    const url::Origin& origin,
    const network::mojom::PermissionsPolicyFeature feature) {
  // Check if the embedder's permissions policy allows the feature at all
  // (including inherited policy from ancestors)
  auto* parent_policy = GetParentFrameOrOuterDocument()->GetPermissionsPolicy();
  if (!parent_policy->IsFeatureEnabledByInheritedPolicy(feature)) {
    return false;  // Feature disabled by ancestor — cannot be re-enabled
  }
  
  std::optional<const network::PermissionsPolicy::Allowlist>
      embedder_allowlist = parent_policy->GetAllowlistForFeatureIfExists(feature);
  if (embedder_allowlist && !embedder_allowlist->MatchesAll()) {
    return false;
  }
  // ... rest unchanged
}
```

## Files

- `content/browser/renderer_host/navigation_request.cc:10402-10436` (buggy check)
- `services/network/public/cpp/permissions_policy/permissions_policy.cc:377-391` (returns nullopt for disabled)
- `services/network/public/cpp/permissions_policy/fenced_frame_permissions_policies.h:27-31` (required features list)

## Distinction from Prior Findings

This is distinct from Finding 230 (SharedStorage per-page budget bypass) — that finding bypasses the budget enforcement, while this finding bypasses the permissions policy gating that determines whether the feature is available at all.
