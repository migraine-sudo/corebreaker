# Finding 149: Activationless PaymentRequest.show() Allows One Free Show Per Navigation

## Summary
The `PaymentRequest.show()` method intentionally allows ONE call without user activation (gesture) per navigation. This "activationless show" is tracked per-WebContents via `PaymentRequestWebContentsManager`, but the tracking is reset on browser-initiated (non-reload) navigations and renderer-initiated navigations WITH a user gesture. A malicious page can exploit this by triggering PaymentRequest.show() without any user interaction, which can be used for UI spoofing or annoyance attacks.

## Affected Files
- `components/payments/content/payment_request.cc:273-332` - Show() activation logic
- `components/payments/content/payment_request_web_contents_manager.cc:32-72` - Activationless show tracking
- `third_party/blink/renderer/modules/payments/payment_request.cc:1024-1060` - Renderer-side activation handling

## Details
```cpp
// payment_request.cc (browser process)
void PaymentRequest::Show(bool wait_for_updated_details,
                          bool had_user_activation) {
  ...
  if (!had_user_activation) {
    PaymentRequestWebContentsManager* manager = ...;
    if (manager->HadActivationlessShow()) {
      // Reject: already had one activationless show
      client_->OnError(mojom::PaymentErrorReason::USER_ACTIVATION_REQUIRED, ...);
      return;
    } else {
      // Allow the activationless show!
      is_activationless_show_ = true;
      manager->RecordActivationlessShow();
    }
  }
```

The renderer side consumes activation and sends `had_user_activation` to the browser, but the renderer is not trusted -- a compromised renderer could always send `had_user_activation=true`. However, even WITHOUT a compromised renderer, the spec allows one free activation-less show.

The reset logic in `DidStartNavigation`:
```cpp
if ((!is_renderer_initiated && reload_type == content::ReloadType::NONE) ||
    has_user_gesture) {
    had_activationless_show_ = false;  // Reset!
}
```

This means after any browser-initiated navigation (clicking a link from the address bar, bookmarks), the counter resets and another activationless show is permitted.

## Attack Scenario
1. User navigates to `https://malicious.com` (browser-initiated, resets activationless counter)
2. Page JavaScript immediately calls `new PaymentRequest(...).show()` without any user click
3. A payment sheet UI appears, potentially covering important content or mimicking trusted UI
4. User navigates away (browser-initiated), resetting the counter
5. Another site (or redirect back) can show another activationless payment dialog

For a compromised renderer scenario, the `had_user_activation` boolean sent via Mojo is trivially spoofable, but this finding focuses on the non-compromised case where one free show is by design.

## Impact
One unsolicited payment dialog per navigation flow. Can be used for UI spoofing or annoyance. Limited by the fact that only one PaymentRequest UI can be shown at a time and the user must interact with it.

## VRP Value
Low
