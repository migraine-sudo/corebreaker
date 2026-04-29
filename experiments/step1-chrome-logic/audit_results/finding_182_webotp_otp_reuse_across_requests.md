# Finding 182: WebOTP One-Time Code Reusable Across Requests

## Summary
In `webotp_service.cc`, when a new `Receive()` call arrives while a consent handler is still active from a previous request, the service reuses the previously received one-time code (`one_time_code_`) without re-fetching or re-validating it. The code explicitly states this is intentional ("it is only safe for us to use the in flight otp with the new request since both requests belong to the same origin") but the TODO on line 211 suggests the safety check (`is_active()`) is not robust.

## Affected Files
- `content/browser/sms/webotp_service.cc:195-218` -- `Receive()` reuses in-flight OTP
- `content/browser/sms/webotp_service.cc:332-345` -- `CleanUp()` preserves OTP while consent is active
- `content/browser/sms/webotp_service.cc:211-213` -- TODO about weak `is_active()` check

## Details
```cpp
void WebOTPService::Receive(ReceiveCallback callback) {
  // ...
  // |one_time_code_| and prompt are still present from the previous request so
  // a new subscription is unnecessary. Note that it is only safe for us to use
  // the in flight otp with the new request since both requests belong to the
  // same origin.
  // TODO(majidvp): replace is_active() check with a check on existence of the
  // handler.
  auto* consent_handler = GetConsentHandler();
  if (consent_handler && consent_handler->is_active())
    return;
```

And in `CleanUp()`:
```cpp
auto* consent_handler = GetConsentHandler();
bool consent_in_progress = consent_handler && consent_handler->is_active();
if (!consent_in_progress) {
    one_time_code_.reset();
    // ...
}
```

The `is_active()` check is flagged in two TODOs as being weak. If the consent handler is in an inconsistent state (e.g., the handler exists but is not truly active), the OTP code persists across request boundaries.

## Attack Scenario
1. A website uses WebOTP to receive a one-time code via SMS.
2. The user's phone receives the SMS and the OTP is captured by the browser.
3. The first request is cancelled (e.g., via `SmsStatus::kCancelled` which calls `CleanUp()`).
4. If the consent handler's `is_active()` returns true even though the previous request was cancelled, `one_time_code_` is NOT cleared.
5. The website immediately calls `Receive()` again.
6. The new request inherits the old OTP without a new SMS being received or user consent being re-obtained.
7. This effectively replays the OTP across request boundaries without fresh user consent.

## Impact
- One-time codes may be delivered to new requests without fresh user consent.
- The `is_active()` check is acknowledged as unreliable (TODO in two places).
- Undermines the "one-time" guarantee of OTP codes.
- Limited by same-origin restriction on WebOTPService.

## VRP Value
**Low-Medium** -- The same-origin restriction limits the attack surface, but the reuse of OTP codes without fresh consent weakens the security model. The acknowledged weakness of the `is_active()` check adds concern.
