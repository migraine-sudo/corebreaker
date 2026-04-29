# Finding 038: Cross-Origin Prefetch BuildClientSecurityState Race — Previous Document Policy Confusion

## Summary

A documented race condition causes `CreateCrossOriginPrefetchLoaderFactoryBundle()` to call `BuildClientSecurityState()` on the previous document before the new document is committed. The `ClientSecurityState` (COEP, DIP, IP address space, local network access policy) is sourced from the wrong document. The null-pointer crash case has a maximally-restrictive fallback bandaid, but the non-null case (previous document's policies used for new document's prefetch) remains unfixed.

## Affected Files

- `content/browser/renderer_host/render_frame_host_impl.cc:15498-15527` — Race condition bandaid

## Details

```cpp
// render_frame_host_impl.cc:15498-15527
network::mojom::ClientSecurityStatePtr
RenderFrameHostImpl::BuildClientSecurityState() const {
  // TODO(crbug.com/40752428) Remove this bandaid.
  //
  // Due to a race condition, CreateCrossOriginPrefetchLoaderFactoryBundle() is
  // sometimes called on the previous document, before the new document is
  // committed. In that case, it mistakenly builds a client security state
  // based on the policies of the previous document.
  if (!policy_container_host_) {
    DCHECK_EQ(lifecycle_state_, LifecycleStateImpl::kSpeculative);
    // Returns maximally-restrictive fallback...
    return network::mojom::ClientSecurityState::New(
        coep_require_corp, false, kUnknown, kBlock, dip_require_corp);
  }
  // Non-null case: uses whatever PolicyContainerHost is present
  // which may belong to the PREVIOUS document
```

### The unfixed path

When `policy_container_host_` is non-null (from the previous document), `BuildClientSecurityState()` returns the **previous document's** COEP, DIP, IP address space, and local network access policy. A prefetch for the new document inherits the old document's policies.

### Concrete confusion

If the previous document had:
- COEP: `unsafe-none` (permissive)
- Local Network Access: `allow`

And the new document has:
- COEP: `require-corp` (restrictive)
- Local Network Access: `block`

A cross-origin prefetch during the race window uses the permissive policies, loading resources that should have been blocked by the new document's COEP/LNA.

## Attack Scenario

1. Attacker page (`evil.com`) sets permissive COEP and local network access policies
2. Attacker triggers navigation to `bank.com` (which has strict COEP/LNA)
3. During the speculative RFH creation window (before `bank.com` commits):
   - A cross-origin prefetch is initiated for `bank.com`'s resources
   - `BuildClientSecurityState()` is called on the speculative RFH
   - The PolicyContainerHost from `evil.com` is still attached
   - The prefetch uses `evil.com`'s permissive policies
4. Resources that should be blocked by `bank.com`'s `require-corp` COEP are loaded
5. Private network resources that should be blocked by LNA are accessible

## Impact

- **No compromised renderer needed**: Triggered by navigation timing
- **COEP bypass**: Cross-Origin-Embedder-Policy enforcement weakened during race window
- **Local Network Access bypass**: Private network requests may proceed under wrong policy
- **Acknowledged but unfixed**: The TODO (crbug.com/40752428) says "remove this bandaid" — the fundamental race remains

## VRP Value

**Medium** — The race window is narrow but the bug is acknowledged by the Chromium team with a TODO. The null-pointer case is mitigated but the policy-confusion case is not. The attack surface is web-level (navigation timing).
