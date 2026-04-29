# Finding 155: Manifest Verifier Cache-First Strategy Allows Stale Authorization

## Summary
The `ManifestVerifier` uses a cache-first verification strategy where payment apps are authorized based on cached manifest data, and the fresh download is used only to update the cache for next time. If a payment method provider revokes authorization for a payment app origin in their manifest, the app continues to be authorized until the cache entry expires or is overwritten with the fresh (restrictive) data. The verifier fires the `finished_verification_callback_` using cached data before the fresh download completes.

## Affected Files
- `components/payments/content/manifest_verifier.cc:142-186` - Cache-first verification flow
- `components/payments/content/manifest_verifier.cc:221-258` - Fresh download updates cache but may arrive after verification

## Details
```cpp
// manifest_verifier.cc
void ManifestVerifier::OnGetPaymentMethodManifest(
    const GURL& method_manifest_url,
    WebDataServiceBase::Handle handle,
    std::unique_ptr<WDTypedResult> result) {
  ...
  // Enable apps based on CACHED data
  EnableMethodManifestUrlForSupportedApps(
      method_manifest_url, supported_origin_strings, &apps_,
      manifest_url_to_app_id_map_[method_manifest_url],
      &prohibited_payment_methods_);

  if (!supported_origin_strings.empty()) {
    cached_manifest_urls_.insert(method_manifest_url);
    if (--number_of_manifests_to_verify_ == 0) {
      RemoveInvalidPaymentApps();
      // VERIFICATION COMPLETE - using cached (potentially stale) data!
      std::move(finished_verification_callback_)
          .Run(std::move(apps_), first_error_message_);
    }
  }

  // Download fresh manifest (will update cache, but verification already done)
  downloader_->DownloadPaymentMethodManifest(
      merchant_origin_, method_manifest_url,
      base::BindOnce(&ManifestVerifier::OnPaymentMethodManifestDownloaded, ...));
}
```

The flow is:
1. Read from cache -> authorize apps based on cached `supported_origins`
2. If cache had data, fire verification callback immediately (verification done!)
3. Asynchronously download fresh manifest
4. Parse fresh manifest and update cache (this happens AFTER verification completed)
5. If cache had no data, wait for download to complete before verification

This means:
- If the cache has stale authorization (Origin X was previously in `supported_origins` but has since been removed), Origin X's payment app is authorized
- The fresh download updates the cache, so the NEXT payment request will see the correct data
- But the CURRENT payment request already completed with stale authorization

## Attack Scenario
1. Attacker registers a payment handler at `https://evil-handler.com` for method `https://legit-pay.com/pay`
2. Initially, `legit-pay.com`'s manifest includes `https://evil-handler.com` in `supported_origins`
3. User uses the payment method, caching the manifest with the evil origin authorized
4. `legit-pay.com` discovers the compromise and removes `evil-handler.com` from `supported_origins`
5. On the user's next payment request, the verifier reads the OLD cached manifest first
6. The evil handler is still authorized for this payment (cached authorization)
7. The fresh download updates the cache, so the THIRD request would correctly exclude the evil handler
8. There is a window of at least one payment request where the revocation is not effective

## Impact
Delayed revocation of payment handler authorization. A revoked payment app continues to be treated as authorized for one additional payment session after revocation. This is a TOCTOU-like issue where the cached state diverges from the actual authorization.

## VRP Value
Medium
