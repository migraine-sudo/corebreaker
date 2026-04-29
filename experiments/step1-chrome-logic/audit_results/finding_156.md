# Finding 156: Payment Request Show() Trusts Renderer-Supplied had_user_activation Boolean

## Summary
The `PaymentRequest::Show()` method in the browser process receives a `had_user_activation` boolean from the renderer process via Mojo IPC. While the renderer does check `LocalFrame::HasTransientUserActivation()`, the boolean is sent as an untrusted value. A compromised renderer could send `had_user_activation=true` regardless of actual user activation state, bypassing the browser-side activation check entirely.

## Affected Files
- `third_party/blink/renderer/modules/payments/payment_request.cc:1026-1060` - Renderer sends activation state
- `components/payments/content/payment_request.cc:273-332` - Browser trusts the boolean

## Details
In the renderer:
```cpp
// payment_request.cc (renderer)
bool has_transient_user_activation =
    LocalFrame::HasTransientUserActivation(local_frame);
bool has_delegated_activation = DomWindow()->IsPaymentRequestTokenActive();
bool has_activation =
    has_transient_user_activation || has_delegated_activation;
...
payment_provider_->Show(is_waiting_for_show_promise_to_resolve_,
                        has_activation);  // Sent via Mojo
```

In the browser:
```cpp
// payment_request.cc (browser)
void PaymentRequest::Show(bool wait_for_updated_details,
                          bool had_user_activation) {
  ...
  if (!had_user_activation) {
    // Only enforced if renderer says no activation
    if (manager->HadActivationlessShow()) {
      // Reject
    }
    is_activationless_show_ = true;
    manager->RecordActivationlessShow();
  }
  // If had_user_activation == true, no checks at all
```

The browser-side check only kicks in when `had_user_activation == false`. If the renderer sends `true`, the browser skips all activation checks. There is no independent browser-side verification of the user activation state.

This differs from other gesture-gated APIs (like `window.open()`) where the browser has its own independent tracking of user activation state.

## Attack Scenario
1. Attacker has a compromised renderer (e.g., via a renderer exploit)
2. Attacker's JavaScript creates a PaymentRequest
3. Compromised renderer sends `Show(false, true)` via Mojo -- claiming user activation exists
4. Browser process accepts this without verification
5. Payment sheet appears without any user gesture
6. Attacker can repeatedly show payment dialogs (unlimited activationless shows since the activationless tracking is only triggered when `had_user_activation=false`)

This is particularly concerning because:
- The payment sheet is a trusted browser UI that users may feel compelled to interact with
- Multiple payment sheets could be shown in sequence as a harassment vector
- Combined with a UI redressing attack, the payment sheet could be used to trick users

## Impact
User activation bypass with a compromised renderer. While compromised renderers are a known threat model expansion, the browser-side payment code should ideally maintain its own activation state rather than trusting the renderer.

## VRP Value
Medium (requires compromised renderer)
