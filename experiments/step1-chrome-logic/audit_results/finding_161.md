# Finding 161: FindReadyRegistrationForIdOnly Used Without Origin Cross-Check

## Summary
The `PaymentEventDispatcher` uses `FindReadyRegistrationForIdOnly()` to look up service worker registrations by numeric ID when dispatching payment events (InvokePayment, CanMakePayment, AbortPayment). While the `sw_origin` is passed alongside the `registration_id`, the dispatcher never validates that the found registration's origin matches the expected `sw_origin`. The `sw_origin` is only used for DevTools logging, not for security validation.

## Affected Files
- `content/browser/payments/payment_event_dispatcher.cc:150-168` - AbortPayment dispatch
- `content/browser/payments/payment_event_dispatcher.cc:202-221` - CanMakePayment dispatch
- `content/browser/payments/payment_event_dispatcher.cc:253-272` - InvokePayment dispatch
- `content/browser/payments/payment_event_dispatcher.cc:274-283` - FindRegistration

## Details
```cpp
// payment_event_dispatcher.cc
void PaymentEventDispatcher::AbortPayment(
    int64_t registration_id,
    const url::Origin& sw_origin,  // Passed but never validated
    const std::string& payment_request_id,
    scoped_refptr<ServiceWorkerContextWrapper> service_worker_context,
    PaymentAppProvider::AbortCallback callback) {
  service_worker_context->FindReadyRegistrationForIdOnly(
      registration_id,  // Only the ID is used for lookup
      base::BindOnce(
          &DidFindRegistration,
          base::BindOnce(
              &PaymentEventDispatcher::DispatchAbortPaymentEvent,
              ...,
              base::BindOnce(&OnResponseForAbortPayment, payment_app_provider(),
                             registration_id, sw_origin,  // Only used for logging
                             ...))));
}
```

The `FindReadyRegistrationForIdOnly` function looks up a registration by its numeric ID without any origin constraint. The `sw_origin` is passed through the callback chain but is only used in `OnResponseForAbortPayment`, `OnResponseForCanMakePayment`, and `OnResponseForPaymentRequest` -- exclusively for DevTools logging.

In `DidFindRegistration`:
```cpp
void DidFindRegistration(
    PaymentEventDispatcher::ServiceWorkerStartCallback callback,
    blink::ServiceWorkerStatusCode service_worker_status,
    scoped_refptr<ServiceWorkerRegistration> service_worker_registration) {
  ...
  ServiceWorkerVersion* active_version =
      service_worker_registration->active_version();
  DCHECK(active_version);  // No origin check on the found registration
  active_version->RunAfterStartWorker(...);
}
```

No check is performed that `service_worker_registration->scope()` or its origin matches the expected `sw_origin`.

## Attack Scenario
This is primarily a defense-in-depth concern. In the normal flow, the `registration_id` and `sw_origin` are determined by the payment system and should be consistent. However:

1. If a logic bug elsewhere causes an incorrect `registration_id` to be passed (e.g., through a race condition in the payment app finder), a payment event could be dispatched to the wrong service worker
2. The wrong service worker would receive the full payment event data (merchant origin, payment details, instrument key, etc.)
3. Since there's no origin cross-check, this would not be detected

## Impact
Defense-in-depth gap. The `sw_origin` parameter exists but is never used for validation. If a registration ID is ever incorrect due to a bug elsewhere, there is no safety net to prevent events from being dispatched to the wrong service worker.

## VRP Value
Low
