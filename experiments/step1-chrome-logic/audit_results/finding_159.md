# Finding 159: kPaymentRequestUseRendererUrlLoader Enables Renderer-Controlled Network for Manifest Downloads

## Summary
The `kPaymentRequestUseRendererUrlLoader` feature flag (DISABLED_BY_DEFAULT) switches payment manifest downloads from using the browser process's URL loader factory to the renderer's URL loader factory. When enabled, this gives the renderer (and by extension, the merchant page) influence over how payment method manifests are fetched. This breaks the security model where manifest fetching should be a browser-side operation independent of the renderer.

## Affected Files
- `components/payments/core/features.cc:48-49` - Feature flag definition
- `components/payments/content/payment_manifest_downloader.cc:475-489` - Conditional URL loader selection

## Details
```cpp
// payment_manifest_downloader.cc
if (use_url_loader_factory_rfh &&
    base::FeatureList::IsEnabled(
        features::kPaymentRequestUseRendererUrlLoader)) {
  loader->DownloadToString(
      url_loader_factory_rfh_.get(),    // Renderer's URL loader factory
      ...);
} else {
  loader->DownloadToString(
      url_loader_factory_.get(),        // Browser's URL loader factory
      ...);
}
```

When using the renderer's URL loader factory:
1. The network request inherits the renderer's security context
2. Service worker interception may be possible (the renderer's network stack includes service worker interception)
3. The renderer's network partition may differ from the browser's
4. A compromised renderer could manipulate the URL loader factory to return crafted manifest content

This is particularly dangerous because manifest content determines:
- Which payment apps are authorized (via `supported_origins`)
- Which service workers can be JIT-installed
- What payment handler metadata is trusted

## Attack Scenario
1. Feature flag `kPaymentRequestUseRendererUrlLoader` is enabled (via enterprise policy or chrome://flags)
2. Compromised renderer creates its own `URLLoaderFactory` that intercepts manifest download requests
3. When a PaymentRequest is created, the browser uses the renderer's URL loader to fetch payment method manifests
4. The compromised factory returns a crafted manifest that:
   - Authorizes the attacker's origin in `supported_origins`
   - Points to attacker-controlled web app manifests
5. The browser trusts this manifest and installs the attacker's payment handler
6. The attacker's handler is now invoked for payments that should go to legitimate providers

## Impact
When enabled, allows a compromised renderer to control payment method manifest resolution, potentially authorizing arbitrary payment handlers. Currently disabled by default but represents a significant trust boundary violation if enabled.

## VRP Value
Medium (requires non-default flag)
