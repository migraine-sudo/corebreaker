# Finding 146: SPC Debug Flag Downgrades User Verification and Enables All Transport Protocols

## Summary
The `kSecurePaymentConfirmationDebug` feature flag (DISABLED_BY_DEFAULT) simultaneously downgrades the user verification requirement from `kRequired` to `kPreferred` AND enables authentication through ALL transport protocols (including USB, BLE, NFC) instead of restricting to internal authenticators only. While this is a debug flag not enabled in production, if an enterprise or user enables it (e.g., through chrome://flags), it fundamentally weakens the security model of Secure Payment Confirmation (SPC).

## Affected Files
- `content/public/common/content_features.cc:958` - Feature flag definition
- `components/payments/content/secure_payment_confirmation_app.cc:125-138` - UV downgrade + transport expansion
- `components/payments/content/secure_payment_confirmation_service.cc:97-105` - Availability check bypass
- `components/payments/content/secure_payment_confirmation_app_factory.cc:252-254` - Authenticator requirement bypass

## Details
```cpp
// secure_payment_confirmation_app.cc
if (base::FeatureList::IsEnabled(
        ::features::kSecurePaymentConfirmationDebug)) {
    options->user_verification =
        device::UserVerificationRequirement::kPreferred;  // Downgrade from kRequired
    // Enables ALL transport protocols (USB, BLE, NFC, etc.)
    credentials.emplace_back(device::CredentialType::kPublicKey,
                             credential_id_);
} else {
    // Production: internal authenticator only
    credentials.emplace_back(device::CredentialType::kPublicKey, credential_id_,
                             base::flat_set<device::FidoTransportProtocol>{
                                 device::FidoTransportProtocol::kInternal});
}
```

Additionally in secure_payment_confirmation_service.cc, the debug flag causes `SecurePaymentConfirmationAvailability` to return `kAvailable` without checking if a real authenticator exists.

In secure_payment_confirmation_app_factory.cc, the debug flag bypasses the authenticator availability requirement, allowing SPC to proceed even without a user-verifying platform authenticator.

## Attack Scenario
1. Target has `kSecurePaymentConfirmationDebug` enabled (enterprise policy, developer setting, or social engineering via chrome://flags)
2. Attacker hosts a merchant page requesting SPC payment
3. With debug mode, the SPC flow accepts external authenticators over USB/BLE/NFC
4. User verification is only "preferred" not "required" -- authenticators that skip UV can complete the assertion
5. A remote attacker with physical proximity could relay FIDO assertions via BLE/NFC to complete payments without biometric verification
6. The authenticator availability check is bypassed, so the SPC flow proceeds even without a real platform authenticator

## Impact
Critical degradation of SPC security model if the debug flag is enabled. Removes the core guarantee that SPC requires user-verifying platform authenticator with internal transport only.

## VRP Value
Low (requires non-default flag enablement)
