# Finding 107: Same-Document Origin Invariant Enforcement Disabled — Origin Changeable via Same-Doc Nav

## Summary

The `kEnforceSameDocumentOriginInvariants` feature is **DISABLED by default**. When disabled, a compromised renderer can change the committed origin, insecure request policy, and insecure navigations set via same-document navigations. The browser accepts these renderer-supplied values and updates its own state accordingly.

## Affected Files

- `content/common/features.cc:245-246` — Feature DISABLED_BY_DEFAULT
- `content/browser/renderer_host/render_frame_host_impl.cc:5292-5296` — Origin updated even for same-doc
- `content/browser/renderer_host/render_frame_host_impl.cc:16028-16043` — Kill-switch only when ENABLED
- `content/browser/renderer_host/navigator.cc:647-653` — Insecure policy updated for same-doc

## Details

```cpp
// features.cc:245-246
BASE_FEATURE(kEnforceSameDocumentOriginInvariants,
             base::FEATURE_DISABLED_BY_DEFAULT);

// render_frame_host_impl.cc:5290-5296
SetLastCommittedUrl(params.url);
// The origin is only updated for cross-document navigations.
if (!was_within_same_document ||
    !features::IsEnforceSameDocumentOriginInvariantsEnabled()) {
  SetLastCommittedOrigin(params.origin,   // RENDERER-SUPPLIED
                         params.has_potentially_trustworthy_unique_origin);
}
```

When disabled (current default):
1. `SetLastCommittedOrigin()` accepts renderer's origin for same-document navigations
2. `insecure_request_policy` is updated from renderer params
3. `insecure_navigations_set` is updated from renderer params
4. No `bad_message::ReceivedBadMessage` kill for mismatched values

When enabled (not default):
1. Origin is NOT updated for same-document navigations
2. `insecure_request_policy` changes trigger renderer kill
3. `insecure_navigations_set` changes trigger renderer kill

## Attack Scenario

1. Compromised renderer on `https://example.com` performs same-document navigation
2. Sets `params.origin` to `https://bank.com` in the DidCommitProvisionalLoad message
3. Browser calls `SetLastCommittedOrigin()` with the forged origin
4. Browser now believes the document is from `https://bank.com`
5. Note: CanCommitOriginAndUrl check at line 12061-12066 catches basic origin changes even when disabled, but there may be race conditions or edge cases in MHTML/about:blank handling

## Important Caveat

The `CanCommitOriginAndUrl` check at line 12061-12066 provides a basic guard even when the feature is disabled — it checks `origin != GetLastCommittedOrigin()` and returns `CANNOT_COMMIT_ORIGIN`. However:
- This check happens during `ValidateDidCommitParams`, which may have edge cases
- The `insecure_request_policy` and `insecure_navigations_set` updates are NOT guarded at all when the feature is disabled
- The feature description says it "defends against renderer misbehavior and session history corruption"

## Impact

- **Requires compromised renderer**: Yes
- **Insecure request policy manipulation**: Renderer can downgrade security policy
- **Session history corruption**: Acknowledged in feature description
- **Known issue**: crbug.com/40580002

## VRP Value

**Medium-High** — The insecure request policy manipulation is the clearest impact. A compromised renderer can upgrade-insecure-requests policy downgrade, potentially allowing mixed content that should be blocked.
