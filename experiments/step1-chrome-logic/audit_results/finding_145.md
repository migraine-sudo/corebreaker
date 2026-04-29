# Finding 145: kEnforceFullDelegation Disabled by Default Allows Partial Delegation Abuse

## Summary
The `kEnforceFullDelegation` feature flag (DISABLED_BY_DEFAULT) controls whether payment handler apps must support all requested payment options (shipping, email, phone, name). When disabled, a payment handler that claims to handle only a subset of delegations (e.g., shipping but not email) is still shown to the user as a valid payment option. This creates a gap where a malicious payment handler service worker can register with partial delegation support and then request data it should not handle.

## Affected Files
- `components/payments/core/features.cc:35` - Feature flag definition
- `components/payments/content/service_worker_payment_app_factory.cc:121-131` - Guard logic

## Details
```cpp
// components/payments/core/features.cc
BASE_FEATURE(kEnforceFullDelegation, base::FEATURE_DISABLED_BY_DEFAULT);

// components/payments/content/service_worker_payment_app_factory.cc
bool ShouldSkipAppForPartialDelegation(...) const {
    return (base::FeatureList::IsEnabled(features::kEnforceFullDelegation) ||
            has_app_store_billing_method) &&
           !supported_delegations.ProvidesAll(
               delegate->GetSpec()->payment_options());
}
```

Since `kEnforceFullDelegation` is DISABLED_BY_DEFAULT and the `has_app_store_billing_method` is false for regular web payment methods, the `ShouldSkipAppForPartialDelegation` check always returns `false`. Payment apps with partial delegation are not filtered out.

## Attack Scenario
1. Attacker registers a payment handler service worker at `https://evil.com/pay` that supports only `shippingAddress` delegation
2. Merchant page requests `secure-payment-confirmation` or URL-based payment with `requestShipping: true, requestPayerEmail: true`
3. The evil payment handler is presented as a valid option even though it only handles shipping
4. The payment handler receives the payment event including the merchant's top_origin and payment_request_origin information
5. This allows a social engineering vector where partial payment data flows through a handler that should have been excluded

## Impact
Low-severity information leakage and potential user confusion. The payment handler still receives payment request events with top_origin/payment_request_origin data. User must actively select the malicious handler.

## VRP Value
Low
