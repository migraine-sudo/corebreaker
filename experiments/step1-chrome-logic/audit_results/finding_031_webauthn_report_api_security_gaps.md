# Finding 031: WebAuthn Report (Signal) API Missing Multiple Security Checks

## Summary

The WebAuthn `navigator.credentials.report()` (Signal API) is missing three security checks that all other WebAuthn operations enforce:

1. **No TLS certificate verification** — `IsSecurityLevelAcceptableForWebAuthn()` is never called
2. **No cross-origin permissions policy** — explicitly returns SUCCESS for all cross-origin iframes (TODO at crbug.com/347727501)
3. **No actor/credential request gate** — `ShouldDisallowCredentialRequest()` is never called
4. **No focus check** — background tabs can invoke the API

Combined, these gaps allow a cross-origin iframe on a MITM'd connection to silently delete or modify a user's passkeys.

## Affected Files

- `content/browser/webauth/authenticator_common_impl.cc:2124-2167` — Report() entry point, missing TLS and actor checks
- `content/browser/webauth/authenticator_common_impl.cc:2169+` — ContinueReportAfterRpIdCheck(), missing TLS check
- `content/browser/webauth/webauth_request_security_checker.cc:139-142` — ValidateAncestorOrigins, unconditional SUCCESS for kReport

## Details

### Missing TLS check

All other WebAuthn operations check TLS certificate validity:

```cpp
// MakeCredential (line 1158):
!GetContentClient()->browser()->IsSecurityLevelAcceptableForWebAuthn(...)

// GetAssertion (line 1722):
!GetContentClient()->browser()->IsSecurityLevelAcceptableForWebAuthn(...)

// GetPasswordOnlyCredential (line 1639):
!GetContentClient()->browser()->IsSecurityLevelAcceptableForWebAuthn(...)

// Report() — NO SUCH CHECK
```

### Missing permissions policy (explicit TODO)

```cpp
// webauth_request_security_checker.cc:139-142
// TODO(crbug.com/347727501): Add a permissions policy for report.
if (type == RequestType::kReport) {
    return blink::mojom::AuthenticatorStatus::SUCCESS;
}
```

Every other request type requires a permissions policy for cross-origin iframes:
- kMakeCredential → `publickey-credentials-create`
- kGetAssertion → `publickey-credentials-get`
- kMakePaymentCredential → `publickey-credentials-create` OR `payment`
- kGetPaymentCredentialAssertion → `payment`
- **kReport → NONE REQUIRED**

### Missing actor check

```cpp
// MakeCredential (line 1093):
GetContentClient()->browser()->ShouldDisallowCredentialRequest(...)

// GetAssertion (line 1556):
GetContentClient()->browser()->ShouldDisallowCredentialRequest(...)

// GetPasswordOnlyCredential (line 1619):
GetContentClient()->browser()->ShouldDisallowCredentialRequest(...)

// Report() — NO SUCH CHECK
```

## Attack Scenario

### Cross-origin passkey deletion via ad iframe

1. User visits `news-site.com` which embeds `evil-ad.example/ad.html` in an iframe
2. The ad iframe calls `navigator.credentials.report()` with:
   - `relying_party_id: "news-site.com"`
   - `allAcceptedCredentials: []` (empty — signals no credentials are valid)
3. Since there's no permissions policy check, the cross-origin call succeeds
4. Chrome's passkey store deletes the user's passkeys for `news-site.com`

Note: RP ID validation still applies — the attacker must target an RP ID that resolves to a domain they can embed as an iframe. But the permissions policy bypass means any cross-origin content on the page can do this, not just first-party code.

### MITM passkey modification

1. Attacker performs MITM on the user's connection to `bank.com`
2. The MITM'd page calls `navigator.credentials.report()` with:
   - `currentUserDetails: { name: "attacker@evil.com", displayName: "Legitimate User" }`
3. Since there's no TLS security level check, the call proceeds despite the compromised connection
4. Chrome updates the passkey's user details

## Impact

- **No compromised renderer needed**: Standard JavaScript API usage
- **Passkey deletion**: Via `allAcceptedCredentials` signal with empty list
- **Passkey metadata modification**: Via `currentUserDetails` signal
- **Cross-origin**: Any iframe can invoke without permissions policy
- **Background**: No focus check means background tabs can do this

## VRP Value

**Medium** — The Signal API has significantly weaker security gates than all other WebAuthn operations. The permissions policy bypass is explicitly acknowledged as a known gap (TODO crbug.com/347727501). The TLS check gap and actor check gap appear unintentional. The practical impact is passkey deletion/modification, not credential theft.

## Suggested Fix

1. Add `IsSecurityLevelAcceptableForWebAuthn()` check in Report() path
2. Create a dedicated permissions policy for the Signal API (as the TODO suggests)
3. Add `ShouldDisallowCredentialRequest()` check
4. Consider adding focus requirement for destructive operations (allAcceptedCredentials, unknownCredentialId)
