# Round 3: Permission Policy Inheritance & Cross-Origin Audit

## Audit Scope

Chromium source audit focused on:
1. Fenced Frames permission policy inheritance
2. Permission delegation via iframe `allow` attribute parsing
3. Permission Policy + document.open() interaction
4. Permission Policy + Prerender activation
5. Local-network-access permission policy split logic

## Key Files Analyzed

- `services/network/public/cpp/permissions_policy/permissions_policy.cc` (core policy engine)
- `services/network/public/cpp/permissions_policy/fenced_frame_permissions_policies.h` (fenced frame feature lists)
- `services/network/public/cpp/permissions_policy/origin_with_possible_wildcards.cc` (wildcard matching)
- `content/browser/renderer_host/render_frame_host_impl.cc` (browser-side policy reset, document.open)
- `content/browser/renderer_host/navigation_request.cc` (fenced frame permission checks)
- `content/browser/fenced_frame/fenced_frame_config.cc` (fenced frame config and properties)
- `content/browser/preloading/prerender/prerender_host.cc` (prerender activation)
- `third_party/blink/renderer/core/permissions_policy/permissions_policy_parser.cc` (allow attribute parsing)
- `third_party/blink/renderer/core/dom/document.cc` (document.open implementation)
- `third_party/blink/renderer/core/execution_context/security_context_init.cc` (policy initialization)

---

## FINDING-PP-01: Local-Network-Access Split Permissions - Container Policy Override Bypass

**Severity: Medium (documented behavior, but security-relevant design issue)**
**Exploitable without compromised renderer: YES**
**Chrome stable with default flags: YES (FEATURE_ENABLED_BY_DEFAULT)**
**Note: The Chromium developers are AWARE of this behavior (see comments at lines 605-615) and treat it as intentional for backwards compatibility. However, it remains a security-relevant design issue.**

### Location

`services/network/public/cpp/permissions_policy/permissions_policy.cc`, lines 623-632 in `CreateFromParentPolicy()`:

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

Feature flag: `kLocalNetworkAccessChecksSplitPermissions` is defined at `services/network/public/cpp/features.cc:286` as `FEATURE_ENABLED_BY_DEFAULT`.

### Description

When the `local-network-access` feature is inherited by an iframe, the code unconditionally adds `local-network` and `loopback-network` to the `inherited_policies` bitset. This happens inside the `for` loop that iterates all features, and `inherited_policies` is a bitset where `Add()` is idempotent (setting a bit that's already set has no effect, and there is no `Remove` called).

This means if an iframe has:
```html
<iframe allow="local-network-access; loopback-network 'none'">
```

The processing order is:
1. `local-network-access` is processed first. `InheritedValueForFeature` returns true (container policy allows it). `inherited_policies.Add(kLocalNetworkAccess)`, then unconditionally `inherited_policies.Add(kLocalNetwork)` and `inherited_policies.Add(kLoopbackNetwork)`.
2. `loopback-network` is processed later. `InheritedValueForFeature` returns false (container policy says 'none'). But `kLoopbackNetwork` was already added to the bitset in step 1. The bit cannot be removed.

Result: The iframe has `loopback-network` enabled despite the explicit `'none'` restriction.

### Impact

An embedder explicitly restricting `loopback-network` while allowing `local-network-access` would fail to enforce the restriction. The iframe could access localhost/loopback services despite the embedder's attempt to block that specific capability. This could be used to access local services that should be protected.

The same issue applies to `local-network`: an embedder setting `allow="local-network-access; local-network 'none'"` would still grant `local-network` to the iframe.

While the comments acknowledge this as "not supported" behavior, a web developer writing the `allow` attribute would reasonably expect that explicit `'none'` overrides take effect. The silent failure to enforce the restriction creates a false sense of security.

### Preconditions

- `kLocalNetworkAccessChecksSplitPermissions` must be enabled (it IS enabled by default)
- The embedder must use the old `local-network-access` feature name alongside the new split feature names
- The iframe must be same-origin or the container policy must be configured to allow the features

---

## FINDING-PP-02: Fenced Frame Navigation Permission Check Bypass via Inherited Policy Disabled State

**Severity: Low-Medium (defense-in-depth gap)**
**Exploitable without compromised renderer: Unlikely in isolation**

### Location

`content/browser/renderer_host/navigation_request.cc`, lines 10402-10436 in `IsFencedFrameRequiredPolicyFeatureAllowed()`:

```cpp
std::optional<const network::PermissionsPolicy::Allowlist>
    embedder_allowlist = GetParentFrameOrOuterDocument()
                             ->GetPermissionsPolicy()
                             ->GetAllowlistForFeatureIfExists(feature);
if (embedder_allowlist && !embedder_allowlist->MatchesAll()) {
    return false;
}
```

### Description

`GetAllowlistForFeatureIfExists()` returns `std::nullopt` when the inherited policy for a feature is disabled (permissions_policy.cc:381). This means if the embedder's parent has disabled a feature (e.g., via `Permissions-Policy: shared-storage=()`), the embedder itself has `inherited_policies_` with that feature disabled, and `GetAllowlistForFeatureIfExists` returns `std::nullopt`.

The navigation check at line 10414 only blocks when `embedder_allowlist` has a value AND doesn't match all origins. When `std::nullopt` is returned, the check passes through to the container policy check, which then checks the feature default -- all fenced frame features default to `EnableForAll`, so this check also passes.

Result: A fenced frame could theoretically navigate even when the embedder's permission for the required feature is disabled through inheritance from a parent frame.

### Mitigation

This is likely not reachable in practice because the APIs that create fenced frame configs (FLEDGE, Shared Storage) check permissions themselves before creating configs. However, the check is logically incorrect as a defense-in-depth measure. The function should explicitly check `IsFeatureEnabled` on the embedder's policy rather than relying on `GetAllowlistForFeatureIfExists`.

### Recommended Fix

```cpp
// Instead of:
auto embedder_allowlist = GetParentFrameOrOuterDocument()
    ->GetPermissionsPolicy()
    ->GetAllowlistForFeatureIfExists(feature);
if (embedder_allowlist && !embedder_allowlist->MatchesAll()) {
    return false;
}

// Use:
if (!GetParentFrameOrOuterDocument()
    ->GetPermissionsPolicy()
    ->IsFeatureEnabled(feature)) {
    return false;
}
```

---

## FINDING-PP-03: document.open() Preserves Permissions Policy Without Browser-Side Recalculation

**Severity: Low (by design, but worth noting)**

### Location

- `content/browser/renderer_host/render_frame_host_impl.cc:6625` (`DidOpenDocumentInputStream`)
- `third_party/blink/renderer/core/dom/document.cc:3703` (`Document::open`)

### Description

When `document.open()` is called (either on the same window or a different same-origin window), the browser-side handler `DidOpenDocumentInputStream` only updates the URL. It does NOT call `ResetPermissionsPolicy()`. The renderer side also does not reinitialize the permissions policy.

For the cross-window `document.open()` case (`DocumentOpenDifferentWindow`, used on 0.1% of page loads):
- Window A at `https://example.com` opens window B's document at `https://example.com`
- B's permissions policy is preserved from its original frame context
- A writes content into B that runs under B's permissions policy

This is largely by design since `document.open()` is same-origin only, and the permissions policy is tied to the frame's position in the tree, not the document content. The existing comments in the code (lines 3815-3820) acknowledge that security properties should not be mutated by `document.open()`.

However, there is a theoretical confused-deputy scenario: if frame B has permissions granted by its container policy (`allow="camera"`) that frame A does not have, then A could use `document.open()` on B to inject content that exercises B's camera permission. This is limited by the same-origin requirement and is arguably intended behavior.

---

## FINDING-PP-04: Prerender Activation Does Not Recalculate Permissions Policy

**Severity: Informational**

### Location

`content/browser/renderer_host/render_frame_host_impl.cc:5371-5377`:

```cpp
// Navigations that activate an existing bfcached or prerendered document do
// not create a new document.
bool did_create_new_document =
    !navigation_request->IsPageActivation() && !was_within_same_document;
if (did_create_new_document) {
    DidCommitNewDocument(params, navigation_request);
}
```

### Description

When a prerendered page is activated, `DidCommitNewDocument` is NOT called, which means `ResetPermissionsPolicy()` is NOT called. The prerendered page retains its permissions policy from the prerender context.

For top-level prerendered pages, this is correct behavior because:
1. The prerender is a top-level page with its own permissions policy based on its own HTTP headers
2. When activated, it replaces the current page and keeps its own policy
3. `PrerenderHost::IsFramePolicyCompatibleWithPrimaryFrameTree()` validates that frame policies are compatible before activation

The compatibility check (lines 1004-1024) ensures that `frame_policy` (which includes container_policy) matches between the prerender root and primary root. Since main frames typically have empty frame policies, this check passes.

No security issue identified here for the current implementation, but the lack of permissions policy recalculation during activation could become problematic if prerender semantics change in the future.

---

## FINDING-PP-05: Header-Level Local-Network-Access Ordering Dependency

**Severity: Low**

### Location

`services/network/public/cpp/permissions_policy/permissions_policy.cc:462-472`:

```cpp
if (feature == kLocalNetworkAccess) {
    allow_lists_and_reporting_endpoints.allowlists_.emplace(
        kLocalNetwork, Allowlist::FromDeclaration(parsed_declaration));
    allow_lists_and_reporting_endpoints.allowlists_.emplace(
        kLoopbackNetwork, Allowlist::FromDeclaration(parsed_declaration));
}
```

### Description

The `emplace` call does not overwrite existing entries. This creates an ordering dependency in HTTP headers. If a site sends:

```
Permissions-Policy: loopback-network=()
Permissions-Policy: local-network-access=(self)
```

The first header sets `loopback-network` to empty (disabled). The second header tries to copy `local-network-access=(self)` to `loopback-network` via `emplace`, but `emplace` fails because the key already exists. Result: `loopback-network` remains disabled.

Conversely:
```
Permissions-Policy: local-network-access=(self)
Permissions-Policy: loopback-network=()
```

Now `local-network-access` copies `(self)` to `loopback-network` first, then the second header's `loopback-network=()` tries to set it via the main loop's `emplace`, but it also fails (key exists). Result: `loopback-network` is enabled for self.

This ordering dependency is explicitly documented in comments (lines 432-461) but creates a confusing security model where the order of HTTP headers changes the effective policy. The code comments describe this as a known limitation.

---

## FINDING-PP-06: iframe `allow` Attribute Wildcard Restriction Correctly Enforced

**Severity: N/A (No vulnerability found)**

### Location

`services/network/public/cpp/permissions_policy/origin_with_possible_wildcards.cc:70-76`

### Description

For attribute-sourced policies (`NodeType::kAttribute`), subdomain wildcards, port wildcards, and host wildcards are properly rejected:

```cpp
if (type == NodeType::kAttribute &&
    (origin_with_possible_wildcards.csp_source.host.empty() ||
     origin_with_possible_wildcards.csp_source.is_port_wildcard ||
     origin_with_possible_wildcards.csp_source.is_host_wildcard)) {
    return std::nullopt;
}
```

The parser correctly distinguishes between header policies (which allow subdomain wildcards like `https://*.example.com`) and attribute policies (which only allow exact origins). No bypass found.

---

## FINDING-PP-07: CopyStateFrom Drops Reporting Endpoints

**Severity: Informational (not a security issue)**

### Location

`services/network/public/cpp/permissions_policy/permissions_policy.cc:154-159`:

```cpp
std::unique_ptr<PermissionsPolicy> new_policy =
    base::WrapUnique(new PermissionsPolicy(
        source->origin_, {source->allowlists_, {}},  // {} = empty reporting_endpoints
        source->inherited_policies_,
        ...
```

### Description

`CopyStateFrom` copies allowlists and inherited policies but passes an empty map `{}` for `reporting_endpoints_`. This means that when a policy is copied (e.g., for `InitPermissionsPolicyFrom` during certain document creation paths), Permissions-Policy violation reports configured via the `report-to` parameter are lost. This is a functionality bug, not a security issue, but could mask policy violations.

---

## Summary

| Finding | Severity | Exploitable w/o Compromised Renderer | On Stable/Default |
|---------|----------|--------------------------------------|-------------------|
| PP-01: LNA Split Container Policy Override | Medium (documented) | Yes | Yes |
| PP-02: Fenced Frame Nav Check Bypass | Low-Medium | Unlikely | Yes |
| PP-03: document.open() Policy Preservation | Low | By design | Yes |
| PP-04: Prerender Activation Policy Retention | Informational | N/A | Yes |
| PP-05: LNA Header Ordering Dependency | Low | Yes | Yes (behind flag) |
| PP-06: Allow Attribute Wildcards | N/A | N/A | N/A |
| PP-07: CopyStateFrom Drops Reports | Informational | N/A | Yes |

**Most impactful finding: FINDING-PP-01** -- The local-network-access split permissions logic unconditionally adds `local-network` and `loopback-network` to inherited policies when `local-network-access` is inherited, ignoring explicit restrictions in the container policy. This is documented as intentional for backwards compatibility but creates a security-relevant design issue where explicit `'none'` restrictions are silently ignored.

**Most novel finding: FINDING-PP-02** -- The fenced frame navigation permission check has a logic gap where `GetAllowlistForFeatureIfExists` returning `std::nullopt` (due to inherited policy being disabled) bypasses the embedder allowlist check. While unlikely to be reachable in practice due to upstream API checks, this represents a defense-in-depth gap that should be hardened.
