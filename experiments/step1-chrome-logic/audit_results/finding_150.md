# Finding 150: Payment Method Manifest Redirect Validation Uses DCHECK-Only Same-Domain Check

## Summary
When the installable payment app crawler downloads a payment method manifest, it receives both the original URL and the URL after redirects. The security-critical check that these URLs are on the same domain uses `DCHECK` -- which is compiled out in release builds -- rather than an enforced runtime check. The actual enforcement relies on the `PaymentManifestDownloader` implementation, creating a defense-in-depth gap.

## Affected Files
- `components/payments/content/installable_payment_app_crawler.cc:131-134` - DCHECK-only domain check for payment method manifest
- `components/payments/content/installable_payment_app_crawler.cc:245-254` - DCHECK-only URL check for web app manifest

## Details
```cpp
// installable_payment_app_crawler.cc:131
void InstallablePaymentAppCrawler::OnPaymentMethodManifestDownloaded(
    const GURL& method_manifest_url,
    const GURL& method_manifest_url_after_redirects,
    const std::string& content,
    const std::string& error_message) {
  // Enforced in PaymentManifestDownloader.
  DCHECK(net::registry_controlled_domains::SameDomainOrHost(
      method_manifest_url, method_manifest_url_after_redirects,
      net::registry_controlled_domains::INCLUDE_PRIVATE_REGISTRIES));
  ...
```

And for web app manifest downloads:
```cpp
// installable_payment_app_crawler.cc:245-253
#if DCHECK_IS_ON()
  GURL::Replacements replacements;
  if (ignore_port_in_origin_comparison_for_testing_)
    replacements.ClearPort();
  // Enforced in PaymentManifestDownloader.
  DCHECK_EQ(
      web_app_manifest_url.ReplaceComponents(replacements),
      web_app_manifest_url_after_redirects.ReplaceComponents(replacements));
#endif  // DCHECK_IS_ON()
```

The web app manifest redirect check is entirely inside `#if DCHECK_IS_ON()`, meaning it does not exist at all in release builds.

The comment says "Enforced in PaymentManifestDownloader", delegating the security to another component. If PaymentManifestDownloader has a bug or is refactored to relax its redirect policy, the crawler would silently accept cross-domain redirected manifests.

## Attack Scenario
1. Attacker finds or creates a bug in `PaymentManifestDownloader` that allows a cross-domain redirect (e.g., through an open redirect on the target domain, or HTTP-level redirect before HTTPS upgrade)
2. The crawler processes the redirected manifest content without any runtime validation that the redirect stayed on the same domain
3. Attacker's manifest (from a different domain) is treated as authoritative for the original payment method domain
4. This could allow the attacker to install a service worker payment handler that impersonates a legitimate payment provider

## Impact
Defense-in-depth gap. If the manifest downloader's redirect enforcement is ever bypassed, the crawler has no independent verification in release builds. The web app manifest check is completely absent in release builds.

## VRP Value
Medium
