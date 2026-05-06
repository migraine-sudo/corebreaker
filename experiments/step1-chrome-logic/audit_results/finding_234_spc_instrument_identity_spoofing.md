# Finding 234: SPC Instrument Identity Spoofing via Unvalidated displayName/icon

## Summary

The Secure Payment Confirmation (SPC) API allows any calling origin to assert WebAuthn credentials for ANY Relying Party (RP) ID, and provides attacker-controlled instrument `displayName`, `icon`, and `details` fields that are displayed in Chrome's trusted payment dialog without validation. Combined with the existing Finding 228 (unvalidated `payeeOrigin`/`payeeName`), this allows a complete phishing attack where EVERY field the user sees in the browser-trusted SPC dialog is attacker-controlled.

## Severity: Medium-High (UI Spoofing + Cross-Origin Credential Assertion)

## Affected Component

- Secure Payment Confirmation (SPC) API
- Payment Request API
- WebAuthn credential assertion

## Root Cause 1: RP ID Validation Skipped for SPC Assertions

`content/browser/webauth/webauth_request_security_checker.cc:174-181`:
```cpp
// SecurePaymentConfirmation allows third party payment service provider to
// get assertions on behalf of the Relying Parties. Hence it is not required
// for the RP ID to be a registrable suffix of the caller origin, as it would
// be for WebAuthn requests.
if (request_type == RequestType::kGetPaymentCredentialAssertion) {
  std::move(callback).Run(blink::mojom::AuthenticatorStatus::SUCCESS);
  return nullptr;
}
```

Any origin can invoke SPC with `rpId: "victim-bank.com"` and trigger a WebAuthn assertion for a credential created by `victim-bank.com`.

## Root Cause 2: Instrument Fields Are Attacker-Controlled

`third_party/blink/renderer/modules/payments/secure_payment_confirmation_helper.cc:90-120`:
- `instrument.displayName` — validated only for non-empty
- `instrument.icon` — validated only for valid URL format
- `instrument.details` — arbitrary string up to 4096 bytes

These are provided entirely by the calling web page and displayed directly in Chrome's browser-chrome SPC dialog.

`components/payments/content/secure_payment_confirmation_controller.cc:297-300`:
```cpp
model->set_instrument_label(request->instrument_label());
model->set_instrument_icon(request->instrument_icon());
```

No validation that these match the actual payment instrument associated with the credential.

## Combined Attack

An attacker at `evil-merchant.com` can:
1. Discover a user's SPC credential ID (e.g., from a previous transaction, or by brute-forcing known patterns)
2. Call SPC with:
   - `rpId: "victim-bank.com"` (no validation for assertions)
   - `payeeOrigin: "https://legitimate-store.com"` (Finding 228 — unvalidated)
   - `payeeName: "Amazon"` (Finding 228 — unvalidated)
   - `instrument.displayName: "Visa ****1234"` (unvalidated)
   - `instrument.icon: "https://evil.com/visa-logo.png"` (any HTTPS URL)
3. Chrome shows a trusted-looking dialog with:
   - "Pay Amazon" (spoofed payee)
   - "legitimate-store.com" (spoofed merchant origin)
   - "Visa ****1234" (spoofed instrument name)
   - A real-looking Visa logo (attacker-hosted icon)
4. User biometrically confirms, believing they're paying Amazon with their Visa card
5. Attacker receives a valid WebAuthn assertion signed for `victim-bank.com`'s RP ID

## Server-Side Mitigation (Incomplete)

The `clientDataJSON` includes the actual caller's origin (`evil-merchant.com`) and top-level origin. A properly-implemented server SHOULD reject the assertion based on origin mismatch. However:
- Not all implementations validate the origin correctly
- The browser UI provides zero indication to the user that something is wrong
- The user has already biometrically authenticated, leaking their fingerprint/face to the assertion
- If the attacker controls a relay to the real bank's server, a man-in-the-middle could modify the origin before forwarding

## Files

- `content/browser/webauth/webauth_request_security_checker.cc:174-181` (RP ID validation bypass)
- `third_party/blink/renderer/modules/payments/secure_payment_confirmation_helper.cc:90-120` (instrument field validation)
- `components/payments/content/secure_payment_confirmation_controller.cc:297-300` (model population)
- `components/payments/content/secure_payment_confirmation_app_factory.cc:470-473` (credential matching)
