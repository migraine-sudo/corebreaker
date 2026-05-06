# Chrome VRP Report: Fenced Frame Permissions Policy Inheritance Bypass via GetAllowlistForFeatureIfExists

## Summary

Chrome's `IsFencedFrameRequiredPolicyFeatureAllowed()` function in `navigation_request.cc` fails to detect when a Privacy Sandbox feature (Attribution Reporting, Private Aggregation, Shared Storage) is disabled by an ancestor's Permissions-Policy header. The function uses `GetAllowlistForFeatureIfExists()` which returns `std::nullopt` for features disabled by inherited policy, and the caller interprets this as "no restriction" rather than "disabled." This allows a FLEDGE/SharedStorage fenced frame to use Privacy Sandbox APIs even when a publisher has explicitly disabled them.

## Severity Assessment

- **Type**: Permissions Policy Bypass (Privacy Sandbox)
- **User Interaction**: None required
- **Preconditions**: FLEDGE auction must select a creative; the publisher's page must have an intermediate frame that embeds the fenced frame
- **Chrome Version**: All versions supporting Fenced Frames with Privacy Sandbox features
- **Flags Required**: None (default configuration)
- **Compromised Renderer**: Not required
- **Platform**: All desktop and Android platforms with fenced frame support

## Reproduction Steps

### 1. Setup: Publisher disables Attribution Reporting

```
Publisher page (publisher.com):
HTTP Header: Permissions-Policy: attribution-reporting=(), private-aggregation=()
```

This publisher explicitly disables attribution reporting and private aggregation for all embedded content.

### 2. Intermediate ad frame

```html
<!-- publisher.com page -->
<iframe src="https://adtech.com/frame"
        allow="attribution-reporting *; private-aggregation *; shared-storage *">
</iframe>
```

The intermediate frame (`adtech.com`) has the `allow` attribute delegating these features. However, the publisher's Permissions-Policy header should override this — child frames cannot have MORE permissions than their ancestors.

### 3. FLEDGE auction creates a fenced frame

```javascript
// Inside adtech.com/frame — runs a FLEDGE auction
const config = await navigator.runAdAuction({
  seller: "https://adtech.com",
  // ... auction config
});
// config has effective_enabled_permissions_ including kAttributionReporting
document.querySelector("fencedframe").config = config;
```

### 4. Bug: Fenced frame successfully navigates despite ancestor ban

The fenced frame navigation calls `CheckPermissionsPoliciesForFencedFrames()` which calls `IsFencedFrameRequiredPolicyFeatureAllowed()`.

For `kAttributionReporting`:
1. `GetParentFrameOrOuterDocument()->GetPermissionsPolicy()->GetAllowlistForFeatureIfExists(kAttributionReporting)` is called
2. The parent's policy inherited the publisher's ban, so `IsFeatureEnabledByInheritedPolicy(kAttributionReporting)` returns `false`
3. `GetAllowlistForFeatureIfExists()` returns `std::nullopt` (line 381-382 of permissions_policy.cc)
4. The check `if (embedder_allowlist && !embedder_allowlist->MatchesAll())` evaluates to `false` (nullopt is falsy)
5. Code falls through to container policy check, which passes
6. Fenced frame navigates successfully!

### 5. Inside the fenced frame — Privacy Sandbox APIs work

```javascript
// Inside the fenced frame:
// Attribution Reporting works despite publisher's ban
document.querySelector("a").setAttribute("attributionsrc", "");

// Private Aggregation works  
sharedStorage.worklet.addModule("worklet.js");
// worklet.js can call privateAggregation.contributeToHistogram(...)
```

## Technical Root Cause

**`services/network/public/cpp/permissions_policy/permissions_policy.cc:378-383`**:
```cpp
std::optional<const PermissionsPolicy::Allowlist>
PermissionsPolicy::GetAllowlistForFeatureIfExists(
    network::mojom::PermissionsPolicyFeature feature) const {
  if (!IsFeatureEnabledByInheritedPolicy(feature)) {
    return std::nullopt;  // Returns nullopt for DISABLED-by-inheritance
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
    return false;  // BUG: Only rejects when allowlist EXISTS and is restrictive
}
// Falls through when nullopt (feature disabled by inheritance) ← BUG
```

The semantic mismatch:
- `GetAllowlistForFeatureIfExists()` returns `nullopt` to mean "feature is disabled" OR "feature has no explicit allowlist"
- `IsFencedFrameRequiredPolicyFeatureAllowed()` interprets `nullopt` as ONLY "no explicit restriction"

## Impact

1. **Publisher policy override**: A publisher that explicitly disables Privacy Sandbox tracking features via Permissions-Policy headers cannot prevent FLEDGE fenced frames from using them.

2. **Attribution Reporting abuse**: Fenced frames can register attribution sources and triggers, enabling conversion tracking that the publisher explicitly forbade.

3. **Private Aggregation data collection**: Combined with the filtering_id budget bypass (separate finding), this enables unrestricted data exfiltration through Privacy Sandbox channels that the publisher banned.

4. **Permissions Policy trust model violation**: The fundamental invariant that child frames cannot exceed ancestor permissions is broken for Privacy Sandbox features.

## Affected Features

- `attribution-reporting`
- `private-aggregation`  
- `shared-storage`
- `shared-storage-select-url`

## Suggested Fix

```cpp
bool NavigationRequest::IsFencedFrameRequiredPolicyFeatureAllowed(
    const url::Origin& origin,
    const network::mojom::PermissionsPolicyFeature feature) {
  auto* parent_policy = GetParentFrameOrOuterDocument()->GetPermissionsPolicy();
  
  // First check: is the feature enabled at all in the parent's inherited policy?
  if (!parent_policy->IsFeatureEnabledByInheritedPolicy(feature)) {
    return false;  // Feature disabled by ancestor — cannot be re-enabled
  }
  
  // Second check: does the parent's allowlist permit all origins?
  std::optional<const network::PermissionsPolicy::Allowlist>
      embedder_allowlist = parent_policy->GetAllowlistForFeatureIfExists(feature);
  if (embedder_allowlist && !embedder_allowlist->MatchesAll()) {
    return false;
  }
  
  // Third check: container policy
  // ... (existing code)
}
```

## References

- Permissions Policy spec: "A feature is disabled for a document if it is disabled in any of the document's ancestor navigables"
- Fenced Frames explainer: https://github.com/nicoptere/nicoptere.github.io/blob/master/nicoptere-blog-engine/specs/fenced-frames/
- `kFencedFrameFledgeDefaultRequiredFeatures` defines which features are checked
