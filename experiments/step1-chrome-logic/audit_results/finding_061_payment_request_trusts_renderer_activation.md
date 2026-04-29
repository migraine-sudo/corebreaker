# Finding 061: Payment Request show() Trusts Renderer-Supplied User Activation

## Summary

The Payment Request API's `show()` method sends the user activation state as a boolean parameter in the Mojo IPC. The browser-side (`components/payments/content/payment_request.cc`) trusts this renderer-supplied value without independent verification. A compromised renderer can claim user activation was present, bypassing the "activationless show" restriction that normally prevents automatic payment dialogs.

## Affected Files

- `third_party/blink/renderer/modules/payments/payment_request.cc:1026-1032` — Renderer check
- `components/payments/content/payment_request.cc:274,309` — Browser trusts renderer bool

## Details

The renderer sends `had_user_activation` as a Mojo parameter. The browser uses this to decide whether to show the payment sheet. Unlike `window.open` (which independently checks `HasTransientUserActivation()` browser-side), Payment Request just trusts the boolean.

## Impact

- **Requires compromised renderer**: Direct exploitation
- **Automatic payment dialog**: Without user clicking, a payment sheet could appear
- **User confusion**: Unexpected payment UI could lead to accidental payments

## VRP Value

**Low-Medium** — Requires compromised renderer. The payment sheet still requires user interaction to confirm, limiting the practical impact.
