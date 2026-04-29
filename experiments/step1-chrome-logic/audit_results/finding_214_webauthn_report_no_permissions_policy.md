# Finding 214: WebAuthn Report Request Has No Permissions Policy Check

## Summary

When checking if a frame is allowed to make WebAuthn requests, the code correctly verifies permissions policies for most request types (e.g., `kGetAssertion` checks `kPublicKeyCredentialsGet`, `kGetPaymentCredentialAssertion` checks `kPayment`). However, `kReport` type requests bypass all permissions policy checks and always return SUCCESS. This is acknowledged with a TODO.

## Affected Files

- `content/browser/webauth/webauth_request_security_checker.cc:139-142` — No permissions policy for kReport

## Details

```cpp
// webauth_request_security_checker.cc:134-144
if (type == RequestType::kGetPaymentCredentialAssertion &&
    render_frame_host_->IsFeatureEnabled(
        network::mojom::PermissionsPolicyFeature::kPayment)) {
    return blink::mojom::AuthenticatorStatus::SUCCESS;
}
// TODO(crbug.com/347727501): Add a permissions policy for report.
if (type == RequestType::kReport) {
    return blink::mojom::AuthenticatorStatus::SUCCESS;  // Always allowed!
}
```

All other WebAuthn request types have permissions policy requirements:
- `kMakeCredential`: Requires `kPublicKeyCredentialsCreate`
- `kGetAssertion`: Requires `kPublicKeyCredentialsGet`  
- `kGetPaymentCredentialAssertion`: Requires `kPayment`
- `kReport`: **No policy check** — always returns SUCCESS

## Attack Scenario

1. Top-level page embeds a cross-origin iframe
2. The top-level page's Permissions-Policy header restricts WebAuthn: `publickey-credentials-create=(self)`
3. The cross-origin iframe cannot make WebAuthn creation or get requests (correctly blocked)
4. However, the iframe CAN make WebAuthn report requests (not blocked by any policy)
5. Depending on what information the report endpoint reveals or what state it modifies, this could be exploited:
   - Information about the user's WebAuthn credentials
   - State changes in the relying party's server
   - Cross-origin correlation of credential existence

## Impact

- **No compromised renderer required**: Standard WebAuthn API in a cross-origin iframe
- **Permissions policy bypass**: Report requests bypass all frame-level restrictions
- **Cross-origin abuse**: Third-party iframes can make WebAuthn reports regardless of parent's policy
- **Incomplete enforcement**: All other request types have policy checks

## VRP Value

**Low-Medium** — Permissions policy gap for WebAuthn report requests. The impact depends on what the report endpoint exposes, but the inconsistency in enforcement (all other request types checked, report not) is a design gap. A permissions policy exists specifically to restrict WebAuthn in cross-origin contexts, and report bypasses it.
