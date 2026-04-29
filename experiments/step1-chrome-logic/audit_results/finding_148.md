# Finding 148: JIT Payment App Installation Lacks User Consent Gate

## Summary
The Just-In-Time (JIT) payment app installation flow (`kWebPaymentsJustInTimePaymentApp`, ENABLED_BY_DEFAULT) automatically registers a service worker and installs a payment handler on behalf of a payment method URL, triggered solely by a merchant requesting that payment method. There is no explicit user consent dialog before the service worker is registered. The user only sees the payment sheet UI after installation is complete. If `kAllowJITInstallationWhenAppIconIsMissing` (DISABLED_BY_DEFAULT) is also enabled, installation proceeds even without a valid icon.

## Affected Files
- `components/payments/core/features.cc:19-20` - JIT feature flag (ENABLED_BY_DEFAULT)
- `components/payments/core/features.cc:32-33` - Missing icon bypass flag
- `content/browser/payments/payment_app_installer.cc` - Service worker registration
- `components/payments/content/installable_payment_app_crawler.cc` - Manifest crawling and validation
- `components/payments/content/service_worker_payment_app_finder.cc:117-124` - JIT crawl trigger

## Details
```cpp
// features.cc
BASE_FEATURE(kWebPaymentsJustInTimePaymentApp,
             base::FEATURE_ENABLED_BY_DEFAULT);
BASE_FEATURE(kAllowJITInstallationWhenAppIconIsMissing,
             base::FEATURE_DISABLED_BY_DEFAULT);
```

The JIT installation flow:
1. Merchant creates PaymentRequest with URL-based payment method (e.g., `https://bobpay.test/pay`)
2. Browser downloads payment method manifest from `https://bobpay.test/pay`
3. Browser follows manifest to web app manifest, validates same-origin constraints
4. Browser registers a service worker from the web app manifest's `sw_js_url`
5. Browser installs the payment app into the database
6. Only THEN is the user shown the payment sheet

The `SelfDeleteInstaller` in `payment_app_installer.cc` registers the service worker with `RegisterServiceWorker()` -- a privileged browser API -- using credentials from the crawled manifest, without any user prompt.

```cpp
// payment_app_installer.cc
service_worker_context_->RegisterServiceWorker(
    sw_url_,
    blink::StorageKey::CreateFirstParty(url::Origin::Create(option.scope)),
    option,
    base::BindOnce(&SelfDeleteInstaller::OnRegisterServiceWorkerResult, this));
```

While the crawler does perform same-origin checks between the payment method manifest URL, web app manifest URL, and service worker URL, these checks are only about URL consistency -- not about user intent.

## Attack Scenario
1. Attacker controls `https://payment-method.evil.com` and hosts a valid payment method manifest pointing to a web app manifest with a service worker
2. Attacker convinces a legitimate merchant to include `https://payment-method.evil.com/pay` as a payment method
3. When a user visits the merchant and the merchant creates PaymentRequest, the browser automatically:
   - Downloads the attacker's payment method manifest
   - Downloads the attacker's web app manifest
   - Registers the attacker's service worker at `https://payment-method.evil.com`
4. The service worker is now installed and can receive future canMakePayment events from other merchants
5. User never explicitly consented to installing this payment handler

## Impact
Silent service worker registration as a side effect of a merchant's PaymentRequest constructor. While the service worker is restricted to its own origin and the payment handler permission check exists, the installation itself requires no user interaction.

## VRP Value
Medium
