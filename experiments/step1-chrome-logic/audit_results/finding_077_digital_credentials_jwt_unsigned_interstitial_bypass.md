# Finding 077: Digital Credentials Interstitial Bypass via Unsigned JWT Claims Parsing

## Summary

The Digital Credentials API decides whether to show a security interstitial (warning about sensitive credential requests) based on parsing a JWT's payload. The JWT signature is NEVER verified. A malicious relying party can forge a JWT claiming only low-risk attributes (like age_over_21) to bypass the interstitial, while the actual request to the wallet may request high-risk attributes.

## Affected Files

- `content/browser/digital_credentials/digital_identity_request_impl.cc:251-282` — JWT parsed without signature verification
- `content/browser/webid/sd_jwt.cc:550` — `Jwt::Parse()` only splits and base64-decodes

## Details

```cpp
// digital_identity_request_impl.cc:251-282
bool CanRequestCredentialBypassInterstitialForOpenid4vpProtocol(
    const base::Value& request) {
  // The request may be a JWT. Parse it to get the actual payload.
  if (const std::string* jwt_str = request_dict->FindString("request")) {
    std::optional<base::ListValue> parsed_jwt = sdjwt::Jwt::Parse(*jwt_str);
    // ⚠️ NO SIGNATURE VERIFICATION
    payload = base::JSONReader::Read(jwt->payload.value(), ...);
    request_dict = &payload->GetDict();
  }
  // ... then decides based on unverified claims
```

```cpp
// sd_jwt.cc:550
// Jwt::Parse only splits header.payload.signature and base64-decodes
// TODO: implement the validations described here:
//   https://www.rfc-editor.org/rfc/rfc7519.html#section-7.2
```

### The interstitial decision logic

The code checks whether the requested claims match a set of "interstitial-bypass-eligible" claims (like `age_over_21`). If all requested claims are on this allow-list, no interstitial is shown. A forged JWT can claim to request only these safe attributes.

## Attack Scenario

### Bypass security interstitial for sensitive credential requests

1. Malicious RP creates a Digital Credentials request with OpenID4VP protocol
2. The `request` field contains a JWT with a forged payload:
   ```json
   {
     "request": "eyJ...forged_header.eyJ...{\"vp_token\":{\"presentation_definition\":{\"input_descriptors\":[{\"constraints\":{\"fields\":[{\"path\":[\"$.age_over_21\"]}]}}]}}}.fake_signature"
   }
   ```
3. Chrome parses the JWT payload (no signature check) and sees only `age_over_21`
4. `CanClaimBypassInterstitial()` returns true → no warning shown to user
5. The JWT (with fake payload) is passed to the wallet app
6. The wallet app may interpret the request differently, or the RP may use a different communication channel to the wallet with the real (sensitive) request
7. User credentials are obtained without the expected security warning

### Real-world impact

The interstitial is designed to warn users when a website requests sensitive personal information (full name, SSN, address, etc.). Bypassing it means users won't see this warning for potentially dangerous credential requests.

## Impact

- **No compromised renderer required**: The RP controls the request content
- **Feature ENABLED by default**: `kWebIdentityDigitalCredentials` is enabled
- **Interstitial is the primary user-facing security boundary**: The only warning users see before sharing credentials
- **Affects all Digital Credentials requests**: Any openid4vp request with a JWT

## VRP Value

**High** — No compromised renderer. Feature enabled by default. Security interstitial bypass for sensitive credential requests. The interstitial exists specifically to protect users from unwanted credential disclosure.
