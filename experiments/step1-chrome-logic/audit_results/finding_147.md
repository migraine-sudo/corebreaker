# Finding 147: canMakePayment Event Leaks Merchant Origin and Method Data to Payment Handlers

## Summary
The `canMakePaymentEvent` dispatched to payment handler service workers exposes `topOrigin`, `paymentRequestOrigin`, full `methodData` (including stringified JSON data), and `modifiers` to the service worker. A payment handler can use this information to fingerprint merchants, track user browsing behavior across sites, and detect what other payment methods a merchant supports -- all without user interaction or consent.

## Affected Files
- `third_party/blink/renderer/modules/payments/can_make_payment_event.h:45-48` - Exposed properties
- `content/browser/payments/payment_app_provider_impl.cc:216-249` - Data sent in CanMakePayment event
- `content/browser/payments/payment_event_dispatcher.cc:170-200` - Event dispatch

## Details
The `CanMakePaymentEvent` interface exposes:
```idl
// can_make_payment_event.h
const String& topOrigin() const;              // Full merchant top-level origin
const String& paymentRequestOrigin() const;    // Payment request frame origin
const HeapVector<Member<PaymentMethodData>>& methodData() const;   // All requested methods + data
const HeapVector<Member<PaymentDetailsModifier>>& modifiers() const; // All modifiers
```

When a merchant calls `new PaymentRequest([...methods...], details)`, the browser dispatches `canMakePaymentEvent` to ALL installed payment handlers that match ANY of the requested methods. Each handler receives:
- The full top-level page origin (e.g., `https://shopping.example.com`)
- The payment request frame origin
- ALL payment method data, including method-specific JSON strings for ALL requested methods (not just the one this handler supports)
- ALL payment modifiers

This happens silently without any UI or user consent -- the event fires as soon as the merchant constructs a PaymentRequest.

## Attack Scenario
1. Attacker registers a payment handler service worker at `https://tracker.evil.com` for a common payment method
2. User visits `https://merchant-a.com` which creates a PaymentRequest with methods including the attacker's
3. The attacker's canMakePayment handler fires silently, receiving `topOrigin=https://merchant-a.com` plus all method data
4. The attacker can:
   - Track which merchants the user visits (cross-site tracking)
   - Learn what payment methods the merchant supports (competitive intelligence)
   - Detect if the merchant uses specific payment providers based on stringified_data
5. This happens for every merchant site the user visits that requests payment methods matching the attacker's handler

## Impact
Cross-site information leakage. The canMakePayment event effectively creates a cross-site tracking side channel. While Chrome has attempted to limit this (the event is only dispatched to installed handlers, not arbitrary origins), the data exposed in each event is extensive and can be used for fingerprinting.

## VRP Value
Medium
