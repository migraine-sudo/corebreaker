# Finding 160: Payment Handler ChangePaymentMethod/ChangeShippingAddress Forwarded to Merchant Without Origin Validation

## Summary
The `PaymentHandlerHost` receives `ChangePaymentMethod`, `ChangeShippingOption`, and `ChangeShippingAddress` Mojo messages from the payment handler service worker and forwards them directly to the merchant page (via `PaymentRequest::client_`). While the handler host validates that method names and shipping option IDs are non-empty, it does not verify that the payment handler sending these change events is the same handler that was originally invoked. The `PaymentHandlerHost` Mojo binding is established once and does not track the origin of the connected payment handler.

## Affected Files
- `components/payments/content/payment_handler_host.cc:185-221` - ChangePaymentMethod forwarding
- `components/payments/content/payment_handler_host.cc:223-251` - ChangeShippingOption forwarding
- `components/payments/content/payment_handler_host.cc:253-301` - ChangeShippingAddress forwarding
- `components/payments/content/payment_request.cc:622-670` - Forwarding to merchant client

## Details
```cpp
// payment_handler_host.cc
void PaymentHandlerHost::ChangePaymentMethod(
    mojom::PaymentHandlerMethodDataPtr method_data,
    ChangePaymentRequestDetailsCallback callback) {
  // Only validates that method_data exists and method_name is non-empty
  if (!method_data) { RunCallbackWithError(...); return; }
  if (method_data->method_name.empty()) { RunCallbackWithError(...); return; }

  // Forwards to merchant without checking WHO sent this
  delegate_->ChangePaymentMethod(method_data->method_name, stringified_data);
  change_payment_request_details_callback_ = std::move(callback);
}
```

```cpp
// payment_request.cc
bool PaymentRequest::ChangePaymentMethod(const std::string& method_name,
                                         const std::string& stringified_data) {
  DCHECK(!method_name.empty());  // DCHECK-only validation
  if (!state_ || !state_->IsPaymentAppInvoked() || !client_)
    return false;
  // Directly sends to merchant renderer
  client_->OnPaymentMethodChange(method_name, stringified_data);
  return true;
}
```

The `ChangePaymentMethod` method forwards arbitrary `stringified_data` to the merchant page. A payment handler can include any JSON data in this field, which the merchant page processes.

Similarly, `ChangeShippingAddress` only validates the country code format, but the rest of the address fields (address_line, city, region, postal_code, recipient, phone) are forwarded without sanitization.

## Attack Scenario
1. Attacker creates a payment handler at `https://evil-pay.com`
2. Merchant site includes `https://evil-pay.com/pay` as a payment method and requests shipping
3. User selects the attacker's payment handler
4. During the payment flow, the attacker's service worker calls:
   - `paymentRequestEvent.changePaymentMethod({methodName: "https://legit-pay.com/pay", data: malicious_json})`
   - `paymentRequestEvent.changeShippingAddress({country: "US", recipient: "<script>alert(1)</script>"})`
5. The merchant page receives these events via `onpaymentmethodchange` and `onshippingaddresschange`
6. If the merchant processes the data without proper sanitization, this could lead to injection attacks
7. The `methodName` in the change event could be different from the handler's actual method, potentially confusing the merchant's payment processing logic

## Impact
A payment handler can send arbitrary data to the merchant page via change events. The method_name in change events is not validated against the handler's actual registered methods. The merchant must handle this data defensively, but the browser does not enforce any relationship between the handler's identity and the data it sends.

## VRP Value
Low
