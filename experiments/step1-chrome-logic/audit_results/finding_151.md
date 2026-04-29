# Finding 151: Service Worker Timeout Suppression While Payment Handler Window Open

## Summary
The feature `kServiceWorkerSuppressTimeoutWhenPaymentWindowOpen` (in content/common/features.cc) causes the service worker timeout mechanism to be completely suppressed while a payment handler window is open. This means a malicious payment handler service worker can remain alive indefinitely as long as it keeps its payment window open, bypassing the normal service worker lifecycle timeout protections.

## Affected Files
- `content/common/features.cc:725` - Feature flag definition
- `content/browser/service_worker/service_worker_version.cc:2723-2728` - Timeout suppression logic

## Details
```cpp
// service_worker_version.cc
// Suppress timeout while a Payment Handler window is open.
if (base::FeatureList::IsEnabled(
        features::kServiceWorkerSuppressTimeoutWhenPaymentWindowOpen) &&
    payment_handler_connected_) {
  return;  // Skip ALL timeout processing
}
```

When this feature is enabled and `payment_handler_connected_` is true, the `OnTimeoutTimer` callback returns immediately without performing any timeout checks. This means:
- The `kStopWorkerTimeout` check for stalled stopping workers is skipped
- The stale worker marking (`MarkIfStale`) is skipped
- All event timeout processing is skipped
- The worker stays alive as long as the payment handler window is connected

## Attack Scenario
1. Attacker registers a payment handler service worker at `https://evil-pay.com`
2. When the payment handler is invoked, it opens a payment handler window via `openWindow()`
3. The payment handler window keeps the connection alive (stays open)
4. The service worker's timeout timer fires, but due to the feature flag, all timeout processing is suppressed
5. The service worker can now:
   - Maintain long-running connections
   - Continue processing events without timeout
   - Avoid the normal service worker lifecycle termination
   - Potentially exhaust browser resources if many such workers are kept alive

## Impact
Resource exhaustion and service worker lifecycle bypass. A malicious payment handler can keep its service worker alive indefinitely, consuming memory and potentially performing background computation. The service worker normally has strict timeouts to prevent exactly this kind of abuse.

## VRP Value
Low
