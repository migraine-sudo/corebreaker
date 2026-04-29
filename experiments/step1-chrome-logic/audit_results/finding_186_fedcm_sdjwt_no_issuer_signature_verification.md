# Finding 186: FedCM SD-JWT Handler Does Not Verify Issuer Signature

## Summary
The `FederatedSdJwtHandler::ProcessSdJwt()` function parses and processes the SD-JWT received from the IdP's issuance endpoint, but never verifies the issuer's signature on the JWT. It calls `SdJwt::Parse()` and `SdJwt::From()` which perform structural parsing only, not cryptographic verification. This means a malicious or compromised IdP endpoint (or a network MITM if the connection is somehow degraded) can provide a structurally valid but unsigned or incorrectly signed SD-JWT that the browser will accept and present to the relying party.

## Affected Files
- `content/browser/webid/delegation/federated_sd_jwt_handler.cc:70-106` -- `ProcessSdJwt()` parses but doesn't verify signature
- `content/browser/webid/delegation/sd_jwt.cc` -- `Parse()` and `From()` are purely structural parsers

## Details
```cpp
void FederatedSdJwtHandler::ProcessSdJwt(const std::string& token) {
  DCHECK(webid::IsDelegationEnabled());

  auto value = sdjwt::SdJwt::Parse(token);  // Structural parse only
  if (!value) { /* error */ }

  auto sd_jwt = sdjwt::SdJwt::From(*value);  // Structural conversion only
  if (!sd_jwt) { /* error */ }

  // Proceeds to selective disclosure and key-binding
  // WITHOUT verifying the issuer's signature on the JWT
```

The `SdJwt::Parse()` function splits the token by `.` and `~` delimiters and base64-decodes the components. The `SdJwt::From()` function extracts claims from the parsed structure. Neither function verifies the JWT's signature.

The browser then:
1. Selectively discloses fields from the unverified SD-JWT.
2. Signs a key-binding JWT over the unverified content.
3. Returns the combined SD-JWT+KB to the relying party.

## Attack Scenario
1. A website requests a federated SD-JWT credential from an IdP.
2. The IdP's issuance endpoint (or a compromised CDN/proxy) returns a structurally valid SD-JWT with a forged or missing signature.
3. The browser accepts the SD-JWT without verifying the signature.
4. The browser creates a key-binding JWT over the unverified claims and presents it to the RP.
5. The RP receives an SD-JWT+KB where the browser's key-binding signature is valid, but the underlying SD-JWT issuer signature may be forged.
6. If the RP relies on the browser's endorsement (key-binding) without independently verifying the issuer signature, it trusts forged claims.

## Impact
- Forged or incorrectly signed SD-JWTs are accepted and presented to RPs.
- The browser's key-binding signature gives false confidence in the SD-JWT's authenticity.
- RPs may interpret the browser's endorsement as validating the entire token chain.
- This is a fundamental violation of the SD-JWT security model, which requires issuer signature verification before presentation.

## VRP Value
**Medium-High** -- While the FedCM delegation feature is behind `FEATURE_DISABLED_BY_DEFAULT`, the complete absence of signature verification in a cryptographic credential flow is a critical gap. The browser is acting as a "holder" in the SD-JWT model and has an obligation to verify the issuer's signature before presenting the credential.
