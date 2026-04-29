# Finding 163: Payment Request canMakePayment() and hasEnrolledInstrument() Controlled by User Pref Without Rate Limiting

## Summary
The `canMakePayment()` and `hasEnrolledInstrument()` methods on `PaymentRequest` check a user preference `kCanMakePaymentEnabled` to decide whether to actually query payment apps. When the pref is enabled (default), there is no per-origin rate limiting on these queries. A page can call `canMakePayment()` and `hasEnrolledInstrument()` an unlimited number of times with different payment method identifiers, each time triggering canMakePayment events to installed payment handlers. This enables a probing attack to discover which payment apps are installed.

## Affected Files
- `components/payments/content/payment_request.cc:553-619` - canMakePayment/hasEnrolledInstrument implementation
- `components/payments/content/has_enrolled_instrument_query_factory.h` - Query factory

## Details
```cpp
// payment_request.cc
void PaymentRequest::CanMakePayment() {
  ...
  bool can_make_payment_allowed_by_pref = true;
  if (!spec_->IsSecurePaymentConfirmationRequested()) {
    can_make_payment_allowed_by_pref =
        delegate_->GetPrefService()->GetBoolean(kCanMakePaymentEnabled);
  }

  if (!can_make_payment_allowed_by_pref) {
    // Lie and say payment is supported to prevent information leakage
    CanMakePaymentCallback(true);
  } else {
    // Actually query all matching payment apps - no rate limit
    state_->CanMakePayment(
        base::BindOnce(&PaymentRequest::CanMakePaymentCallback, ...));
  }
}
```

When `kCanMakePaymentEnabled` is false, the code returns `true` to prevent leakage. When it is `true` (default), the actual query is performed. Interestingly, `hasEnrolledInstrument()` returns `false` when the pref is disabled, while `canMakePayment()` returns `true` -- creating an inconsistency.

The real issue is that when the pref is enabled (default), a page can:
1. Create a PaymentRequest with method A, call canMakePayment() -> learn if method A handler exists
2. Create a PaymentRequest with method B, call canMakePayment() -> learn if method B handler exists
3. Repeat for all known payment method URLs
4. Build a fingerprint of the user's installed payment handlers

## Attack Scenario
1. Attacker page at `https://fingerprint.evil.com` creates multiple PaymentRequest objects
2. Each PaymentRequest uses a different URL-based payment method identifier
3. For each request, attacker calls `canMakePayment()` or `hasEnrolledInstrument()`
4. The boolean responses reveal which payment handlers the user has installed
5. This creates a fingerprint: e.g., the user has Google Pay, Samsung Pay, but not Apple Pay
6. Combined with other fingerprinting signals, this narrows user identity
7. The canMakePayment events are also dispatched to installed handlers, leaking the attacker's origin to them

## Impact
Payment app installation fingerprinting. While the pref exists to disable this, it defaults to enabled. Each query also dispatches canMakePayment events to matching handlers, creating bidirectional information leakage.

## VRP Value
Medium
