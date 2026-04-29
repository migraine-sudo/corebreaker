# Finding 073: SharedWorker Secure Context Derived from Renderer, Not Browser

## Summary

The `kSharedWorkerSecureContextDerivationFromBrowser` feature flag is DISABLED by default, meaning SharedWorker's secure context status is determined by a renderer-supplied `creation_context_type` parameter rather than browser-derived `PolicyContainerHost` data. A compromised renderer can claim any SharedWorker is in a secure context.

## Affected Files

- `content/common/features.cc:757-759` — `kSharedWorkerSecureContextDerivationFromBrowser` DISABLED_BY_DEFAULT
- `content/browser/worker_host/shared_worker_service_impl.cc:199-219` — Renderer-supplied vs browser-derived mismatch logged but not enforced

## Details

```cpp
// features.cc:757-759
// (PolicyContainerHost) instead of trusting the renderer-supplied parameter.
BASE_FEATURE(kSharedWorkerSecureContextDerivationFromBrowser,
             base::FEATURE_DISABLED_BY_DEFAULT);
```

```cpp
// shared_worker_service_impl.cc:216-218
if (base::FeatureList::IsEnabled(
        features::kSharedWorkerSecureContextDerivationFromBrowser)) {
    creation_context_type = browser_derived_context_type;  // DEAD CODE
}
```

When the flag is disabled (default):
1. The renderer sends `creation_context_type` (kSecure or kNonsecure)
2. The browser derives its own value from `PolicyContainerHost`
3. Mismatches are logged to UMA metrics
4. But the renderer's value is used (not the browser's)

## Attack Scenario

### Secure context upgrade for SharedWorker (requires compromised renderer)

1. A page at `http://example.com` (insecure) creates a SharedWorker
2. The compromised renderer sends `creation_context_type = kSecure` in the Mojo IPC
3. The browser detects the mismatch (renderer says secure, browser says nonsecure)
4. The mismatch is only logged to UMA — the renderer's value is used
5. The SharedWorker is created as a "secure context"
6. The SharedWorker gains access to secure-context-only APIs:
   - `crypto.subtle` (WebCrypto)
   - Cache API
   - Potentially Service Worker registration
   - Geolocation, Notifications, etc.

## Impact

- **Requires compromised renderer**: The renderer must forge the creation_context_type parameter
- **Secure context upgrade**: Insecure-context SharedWorkers gain access to powerful APIs
- **Known but unfixed**: The fix exists (use browser-derived value) but is gated behind a disabled flag
- **UMA tracking**: Chrome is monitoring mismatches, suggesting they plan to enable the fix

## VRP Value

**Low-Medium** — Requires compromised renderer. Similar to Finding 069 (has_potentially_trustworthy_unique_origin). The impact is secure-context API access from insecure contexts.
