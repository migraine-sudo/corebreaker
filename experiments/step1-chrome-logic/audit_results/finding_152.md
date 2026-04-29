# Finding 152: Payment Event Dispatcher Incorrect EventType for AbortPayment Request

## Summary
In `PaymentEventDispatcher::DispatchAbortPaymentEvent`, the code starts a service worker request with `EventType::CAN_MAKE_PAYMENT` instead of the correct `EventType::ABORT_PAYMENT`. This causes incorrect event accounting in the service worker, potentially allowing the abort event to run longer than intended or bypass abort-specific timeout handling.

## Affected Files
- `content/browser/payments/payment_event_dispatcher.cc:137-138` - Incorrect event type

## Details
```cpp
// payment_event_dispatcher.cc
void PaymentEventDispatcher::DispatchAbortPaymentEvent(
    PaymentAppProvider::AbortCallback callback,
    scoped_refptr<ServiceWorkerVersion> active_version,
    blink::ServiceWorkerStatusCode service_worker_status) {
  ...
  int event_finish_id = active_version->StartRequest(
      ServiceWorkerMetrics::EventType::CAN_MAKE_PAYMENT, base::DoNothing());
      //                                ^^^^^^^^^^^^^^^^^^^
      // Should be EventType::ABORT_PAYMENT
  ...
  active_version->endpoint()->DispatchAbortPaymentEvent(
      respond_with_callback->BindNewPipeAndPassRemote(),
      active_version->CreateSimpleEventCallback(event_finish_id));
}
```

Compare with the correct usage in `DispatchCanMakePaymentEvent`:
```cpp
int event_finish_id = active_version->StartRequest(
    ServiceWorkerMetrics::EventType::CAN_MAKE_PAYMENT, base::DoNothing());
// This one is correct - it IS dispatching a CAN_MAKE_PAYMENT event
```

And in `DispatchPaymentRequestEvent`:
```cpp
int event_finish_id = active_version->StartRequest(
    ServiceWorkerMetrics::EventType::PAYMENT_REQUEST, base::DoNothing());
// Correct - matches the event being dispatched
```

Note that the `RespondWithCallback` constructor also starts its own request with the correct event type (`EventType::ABORT_PAYMENT` via `AbortRespondWithCallback`), creating a potential double-request issue where one request uses the wrong type.

## Attack Scenario
1. A payment handler service worker receives an abort payment event
2. Due to the incorrect event type in `StartRequest`, the service worker's internal accounting tracks it as a `CAN_MAKE_PAYMENT` event
3. If the service worker has different timeout or quota policies for different event types, the abort event gets the `CAN_MAKE_PAYMENT` timeout instead of the `ABORT_PAYMENT` timeout
4. A malicious payment handler could delay abort processing, keeping the payment flow active longer than expected
5. Metrics data is polluted, making it harder to detect abuse patterns

## Impact
Incorrect service worker event lifecycle management. The abort event is tracked with wrong metrics and may get incorrect timeout handling. Could allow delayed abort processing. Also a double-request accounting bug since both DispatchAbortPaymentEvent and AbortRespondWithCallback call StartRequest.

## VRP Value
Low
