# Finding 162: Payment Handler Dialog Initiator Origin Taken From Merchant Page URL

## Summary
The `kPaymentHandlerDialogUseInitiatorInUrlLoad` feature flag (DISABLED_BY_DEFAULT) controls whether the payment handler dialog's URL load includes an `initiator_origin`. When enabled, the initiator origin is derived from the merchant's last committed URL. This exposes the merchant's full origin to the payment handler's navigation request, which may be visible in server logs, Referer headers, or the payment handler's document.

## Affected Files
- `components/payments/core/features.cc:57-58` - Feature flag definition
- `chrome/browser/ui/views/payments/payment_handler_web_flow_view_controller.cc:333-341` - Initiator origin setting

## Details
```cpp
// payment_handler_web_flow_view_controller.cc
if (base::FeatureList::IsEnabled(
        payments::features::kPaymentHandlerDialogUseInitiatorInUrlLoad)) {
  content::NavigationController::LoadURLParams params(target_);
  params.initiator_origin =
      url::Origin::Create(state()->GetWebContents()->GetLastCommittedURL());
  web_view->GetWebContents()->GetController().LoadURLWithParams(params);
} else {
  web_view->LoadInitialURL(target_);
}
```

When this flag is enabled:
1. The merchant page's full origin (from the outermost page's last committed URL) is set as the `initiator_origin` for the payment handler window's navigation
2. The `initiator_origin` influences:
   - The `Referer` header sent with the navigation request
   - The `Sec-Fetch-Site` header computation
   - CSP checks on the payment handler's page
   - The navigation's `initiator_origin` accessible to navigation throttles

Without the flag (default), the payment handler window loads its URL without an initiator, which means it navigates as if opened by the browser itself (no merchant origin exposed in navigation metadata).

## Attack Scenario
1. Flag is enabled (e.g., via Finch experiment or enterprise policy)
2. User visits `https://secret-intranet.corp.com` which requests payment via `https://payment-handler.com`
3. The payment handler dialog navigates to `https://payment-handler.com/pay`
4. The navigation includes `initiator_origin = https://secret-intranet.corp.com`
5. The payment handler's server sees the initiator origin in the `Referer` header or logs
6. This reveals that the user was visiting `secret-intranet.corp.com`, which may be sensitive

## Impact
When enabled, leaks merchant page origin to payment handler via navigation metadata. This is a cross-origin information leak where the payment handler learns which site the user was on when initiating the payment.

## VRP Value
Low (requires non-default flag)
