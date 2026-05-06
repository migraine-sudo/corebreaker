# Finding 235: CanMakePayment Event Leaks Merchant Origin to Payment Handler Without User Interaction

## Summary

When a web page calls `PaymentRequest.canMakePayment()`, Chrome immediately dispatches a `CanMakePaymentEvent` to registered payment handler service workers. This event exposes the `topOrigin` and `paymentRequestOrigin` of the calling merchant to the payment handler, without any user interaction or consent. A malicious payment handler can use this as a cross-site oracle to track which merchant sites users visit.

## Severity: Medium (Cross-Site Information Leak Without User Consent)

## Affected Component

- Payment Handler API
- Payment Request API
- Service Workers

## Root Cause

`third_party/blink/public/mojom/payments/payment_app_events.mojom:53-58`:
```
struct CanMakePaymentEventData {
  url.mojom.Url top_origin;
  url.mojom.Url payment_request_origin;
  // ...
};
```

`third_party/blink/renderer/modules/payments/payment_event_data_conversion.cc:132-134`:
The `top_origin` and `payment_request_origin` are passed to the payment handler's service worker in the `CanMakePaymentEvent` init dict.

## Attack Scenario

1. Attacker registers a payment handler service worker at `evil-payments.com` supporting a common payment method (e.g., `basic-card` or a custom URL-based method)
2. User visits `merchant-a.com`, which calls `new PaymentRequest([{supportedMethods: "https://evil-payments.com/pay"}]).canMakePayment()`
3. Chrome dispatches `CanMakePaymentEvent` to `evil-payments.com`'s service worker
4. The SW receives `event.topOrigin = "https://merchant-a.com"` and `event.paymentRequestOrigin = "https://merchant-a.com"`
5. The SW can log this and respond `true` or `false`
6. **No user interaction required** — `canMakePayment()` fires without a user gesture

## Information Leaked

- Which merchant origins the user visits (that support the attacker's payment method)
- When they visit (timing of the event)
- Whether the user is the same across visits (same SW registration)
- The iframe structure (topOrigin vs paymentRequestOrigin differ in iframe contexts)

## Preconditions

- User must have previously interacted with/visited `evil-payments.com` (for the SW to be registered)
- Merchant must include `evil-payments.com`'s payment method in their PaymentRequest
- OR: Attacker also controls a popular payment processing library that merchants embed

## Feature Gate

None — this is the standard Payment Handler API behavior on Chrome stable.

## Files

- `third_party/blink/public/mojom/payments/payment_app_events.mojom:53-58` (event data includes origins)
- `third_party/blink/renderer/modules/payments/payment_event_data_conversion.cc:132-134` (origin exposure)
- `content/browser/payments/payment_app_provider_impl.cc` (event dispatch)
