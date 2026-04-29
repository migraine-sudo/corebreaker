# Finding 138: SameSite=None Sandbox Cookie Override Uses Precursor Origin for Ancestor Checks

**Severity: MEDIUM**

**Component:** `content/browser/renderer_host/render_frame_host_impl.cc`

## Summary

The `allow-same-site-none-cookies` CSP sandbox value allows sandboxed frames to access SameSite=None cookies. The ancestor validation in `AncestorsAllowSameSiteNoneCookiesOverride()` uses `GetTupleOrPrecursorTupleIfOpaque()` to derive the scheme+host+port for comparison. This means it compares based on the *precursor* origin (the origin the opaque origin was derived from), not the actual opaque origin. This creates a potential confusion where two differently-sandboxed frames from the same precursor origin would be treated identically, and the same-site check could pass when it conceptually should not.

## Vulnerable Code

```cpp
// content/browser/renderer_host/render_frame_host_impl.cc:7241-7262
bool RenderFrameHostImpl::AncestorsAllowSameSiteNoneCookiesOverride(
    const url::Origin& frame_origin) const {
  // Use precursor for cases where the current or parent frames are sandboxed
  // and have an opaque origin.
  const url::SchemeHostPort scheme_host_port =
      frame_origin.GetTupleOrPrecursorTupleIfOpaque();

  for (const RenderFrameHostImpl* frame = parent_; frame;
       frame = frame->parent_) {
    url::SchemeHostPort parent_scheme_host_port =
        frame->last_committed_origin_.GetTupleOrPrecursorTupleIfOpaque();
    if ((scheme_host_port != parent_scheme_host_port) ||
        (net::SchemefulSite(scheme_host_port.GetURL()) !=
         net::SchemefulSite(parent_scheme_host_port.GetURL()))) {
      return false;
    }
  }
  return true;
}
```

```cpp
// content/browser/renderer_host/render_frame_host_impl.cc:775-787
bool IsOriginSandboxedWithAllowSameSiteNoneCookiesValue(
    network::mojom::WebSandboxFlags sandbox_flags) {
  if (sandbox_flags == network::mojom::WebSandboxFlags::kNone) {
    return false;
  }
  if ((sandbox_flags & network::mojom::WebSandboxFlags::kOrigin) ==
      network::mojom::WebSandboxFlags::kNone) {
    return false;
  }
  return (sandbox_flags &
          network::mojom::WebSandboxFlags::kAllowSameSiteNoneCookies) ==
         network::mojom::WebSandboxFlags::kNone;
}
```

## Security Concern

1. **Precursor-based comparison**: By using precursor origins for the ancestor check, the security model relies on the precursor origin being trustworthy. If an attacker can influence which precursor origin an opaque origin is derived from (e.g., via a crafted sandbox attribute on an iframe), they could make the ancestor check pass.

2. **Two-path activation**: The override is set in two independent code paths:
   - `ForLastCommittedNavigation()` (line 2036-2042) for committed documents
   - `ForPendingNavigation()` (line 2097-2104) for pending navigations
   Both paths check `AncestorsAllowSameSiteNoneCookiesOverride()` but with slightly different input origins. The pending navigation path uses `GetOriginToCommit()` which could differ from the final committed origin.

3. **Sandbox flag bit logic**: The `IsOriginSandboxedWithAllowSameSiteNoneCookiesValue` function checks that `kOrigin` IS set (frame is origin-sandboxed) and `kAllowSameSiteNoneCookies` is NOT set (the flag is inverted -- absence means the value IS present). This inverted logic is confusing and easy to get wrong in future changes.

4. **Cookie override propagation**: Once `kAllowSameSiteNoneCookiesInSandbox` is set in `cookie_setting_overrides_`, it persists for all subresource requests from that frame, including to third parties. A sandboxed iframe from `a.com` with this override could have SameSite=None cookies sent on all its subresource requests.

## Rating Justification

MEDIUM: The feature is relatively new (referenced by an external explainer). The ancestor check provides defense but uses precursor origins which is a weaker guarantee than actual origin comparison. The main risk is in the interaction between sandbox flags and this cookie override, particularly if sandbox flags can be influenced by the attacker.

## Related Code

- `content/browser/loader/navigation_url_loader_impl.cc:480-492` - Navigation path activation
- `net/cookies/cookie_setting_override.h:39-43` - Override definition
- `net/cookies/cookie_inclusion_status.h:282-283` - Exemption reason for metrics
