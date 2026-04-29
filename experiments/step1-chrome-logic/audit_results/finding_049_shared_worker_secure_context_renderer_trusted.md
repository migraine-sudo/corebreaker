# Finding 049: SharedWorker Secure Context State Trusted from Renderer (kSharedWorkerSecureContextDerivationFromBrowser Disabled)

## Summary

When creating a SharedWorker, the browser trusts the renderer-supplied `creation_context_type` (secure vs non-secure context) instead of deriving it from its own authoritative `PolicyContainerHost`. The fix is gated behind `kSharedWorkerSecureContextDerivationFromBrowser`, which is `FEATURE_DISABLED_BY_DEFAULT`. A compromised renderer can claim a non-secure context is secure (or vice versa), bypassing secure context requirements for SharedWorker.

## Affected Files

- `content/browser/worker_host/shared_worker_service_impl.cc:216-219` — Browser derivation disabled
- `content/common/features.cc` — kSharedWorkerSecureContextDerivationFromBrowser DISABLED_BY_DEFAULT

## Details

### The disabled fix

```cpp
// shared_worker_service_impl.cc:216-219
if (base::FeatureList::IsEnabled(
        features::kSharedWorkerSecureContextDerivationFromBrowser)) {
  creation_context_type = browser_derived_context_type;  // DEAD CODE
}
```

When disabled (default), the `creation_context_type` is whatever the renderer sent, not what the browser derived from `PolicyContainerHost`. The mismatch is logged as a UMA metric but not acted upon.

### What this enables

A compromised renderer can:
1. Claim an insecure context is secure → access secure-context-only APIs in the SharedWorker
2. Claim a secure context is insecure → connect to non-secure SharedWorkers from a secure page

## Attack Scenario

### Secure context API access from insecure context

1. Compromised renderer on an HTTP page claims `creation_context_type = kSecure`
2. Browser accepts the renderer's claim (flag disabled)
3. SharedWorker is created with secure context type
4. SharedWorker can access APIs that require secure contexts (crypto.subtle, ServiceWorker, etc.)
5. APIs that should only be available in secure contexts are now accessible from an insecure page

## Impact

- **Requires compromised renderer**: Must forge IPC parameters
- **Secure context bypass**: Access to crypto, SW, and other secure-only APIs
- **Trust boundary violation**: Browser accepts renderer assertion about its own security properties

## VRP Value

**Low-Medium** — Requires compromised renderer. The impact is limited to secure context API access elevation. The UMA metric logging suggests Chrome is tracking mismatches in preparation for enforcement.
