# Finding 177: Email Verification SD-JWT Response Fields Not Validated

## Summary
When the browser receives an SD-JWT from the email verification issuer, it parses the token but explicitly does NOT validate that all necessary fields are present and valid. A TODO comment at line 258 acknowledges this gap. The browser accepts and re-presents any well-formed SD-JWT regardless of whether it contains the expected email claim, expiration, or issuer fields. This allows a malicious issuer to return arbitrary claims that the browser will blindly sign and present to the relying party.

## Affected Files
- `content/browser/webid/delegation/email_verification_request.cc:254-264` -- Missing field validation after SD-JWT parse
- `content/browser/webid/delegation/email_verification_request.cc:279-281` -- Hard-coded algorithm in KB-JWT header regardless of actual key type

## Details
```cpp
auto token = sdjwt::SdJwt::Parse(result.token->GetString());

// Step 5.1: The browser parses and verifies if the SD-JWT
// is valid.
// TODO: check if all of the necessary fields of the SD-JWT
// are present and valid.

if (!token) {
    std::move(callback).Run(std::nullopt);
    return;
}

auto sd_jwt = sdjwt::SdJwt::From(*token);
```

Additionally, the key-binding JWT header unconditionally sets `alg = "RS256"` even though the private key may be an EdDSA or EC key:
```cpp
sdjwt::Header header;
header.alg = "RS256";  // Always RS256 regardless of actual key type
header.typ = "kb+jwt";
```

This is a mismatch that could cause verification failures or, worse, could be exploited if a verifier accepts the mismatched algorithm claim.

## Attack Scenario
1. An attacker controls the email domain's DNS TXT record (`_email-verification.evil.com`).
2. The attacker sets up an issuer that returns an SD-JWT with arbitrary claims (e.g., claims about a different email, or claims about permissions/roles).
3. The browser parses the SD-JWT, finds it syntactically valid, but does not check that it contains an email claim matching the requested email.
4. The browser signs a key-binding JWT over the attacker-controlled claims and presents it to the relying party.
5. The relying party receives a browser-endorsed SD-JWT+KB that may contain false claims.

## Impact
- Relying parties may trust browser-signed SD-JWT+KB tokens that contain arbitrary or incorrect claims.
- Email verification can be spoofed if the attacker controls the DNS for the email domain.
- Algorithm mismatch (`RS256` in header vs actual key algorithm) may cause interoperability issues or enable algorithm confusion attacks.

## VRP Value
**Medium** -- The email verification protocol is behind a feature flag and is in early development. However, the complete absence of claim validation in a cryptographic token flow is a fundamental security gap that would be critical once the feature ships.
