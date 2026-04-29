# Finding 074: Same-Document Navigation Origin Invariants Not Enforced (kEnforceSameDocumentOriginInvariants Disabled)

## Summary

The `kEnforceSameDocumentOriginInvariants` feature flag is DISABLED by default. When disabled:
1. `SetLastCommittedOrigin()` is called even for same-document navigations, allowing the renderer to update the browser's committed origin on pushState/replaceState
2. Changes to `insecure_request_policy` and `insecure_navigations_set` during same-document navigations are not checked
3. These invariant violations would normally kill the renderer process, but the checks are gated behind the disabled flag

## Affected Files

- `content/common/features.cc:245-246` — `kEnforceSameDocumentOriginInvariants` DISABLED_BY_DEFAULT
- `content/browser/renderer_host/render_frame_host_impl.cc:5291-5296` — Origin updated on same-doc nav when flag disabled
- `content/browser/renderer_host/render_frame_host_impl.cc:16027-16043` — insecure_request_policy check skipped when flag disabled

## Details

### Origin update on same-document navigation

```cpp
// render_frame_host_impl.cc:5291-5296
// The origin is only updated for cross-document navigations.
if (!was_within_same_document ||
    !features::IsEnforceSameDocumentOriginInvariantsEnabled()) {
    SetLastCommittedOrigin(params.origin,
                           params.has_potentially_trustworthy_unique_origin);
}
```

When the flag is disabled (default), `SetLastCommittedOrigin` is called for ALL navigations including same-document ones. This means the renderer's `params.origin` is trusted even during pushState/replaceState.

### Insecure request policy check skipped

```cpp
// render_frame_host_impl.cc:16027-16043
if (is_same_document_navigation &&
    features::IsEnforceSameDocumentOriginInvariantsEnabled()) {
    if (params->insecure_request_policy != ...) {
        bad_message::ReceivedBadMessage(GetProcess(), ...);  // DEAD CODE
        return false;
    }
}
```

When the flag is disabled, a compromised renderer can change:
- `insecure_request_policy` (controls upgrade-insecure-requests behavior)
- `insecure_navigations_set` (list of navigations that should be upgraded)

## Attack Scenario (requires compromised renderer)

### Origin confusion via same-document navigation

1. Page at `https://target.example/page` performs a same-document navigation
2. Compromised renderer sends `params.origin = https://victim.example` in DidCommitSameDocumentNavigation
3. `CanCommitOriginAndUrl` check catches the mismatch and returns CANNOT_COMMIT_ORIGIN (so origin change is blocked)
4. **But**: the `insecure_request_policy` and `insecure_navigations_set` changes are NOT checked
5. Renderer can downgrade from `upgrade-insecure-requests` to allow mixed content

### Mixed content downgrade

1. Page at `https://bank.example` has `upgrade-insecure-requests` CSP policy
2. Compromised renderer does a same-document navigation with `insecure_request_policy` cleared
3. The browser accepts the change (no validation when flag is disabled)
4. Subsequent subresource loads are no longer upgraded to HTTPS
5. Attacker can perform MitM on HTTP subresources

## Impact

- **Requires compromised renderer**: Direct exploitation
- **Mixed content downgrade**: upgrade-insecure-requests can be disabled
- **Known issue**: crbug.com/40580002 tracks this
- **Kill switch design**: The fix exists but is behind a disabled flag (gradual rollout)

## VRP Value

**Low-Medium** — Requires compromised renderer. The origin change is still blocked by CanCommitOriginAndUrl, but insecure_request_policy changes are completely unvalidated. The practical impact is mixed content downgrade after renderer compromise.
