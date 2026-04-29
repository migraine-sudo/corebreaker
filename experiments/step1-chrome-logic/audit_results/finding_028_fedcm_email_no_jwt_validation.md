# Finding 028: FedCM Email Verification — No SD-JWT Signature Validation

## Summary

The FedCM Email Verification Protocol implementation (`content/browser/webid/delegation/`) does not validate the issuer's SD-JWT signature. The `Jwt::Parse()` function at `sd_jwt.cc:550-578` only splits the JWT into header/payload/signature parts without verifying the signature against any public key.

Additionally, the `aud` claim in the request token uses `render_frame_host_->GetLastCommittedOrigin().Serialize()` (email_verification_request.cc:90) without checking if the origin is opaque, which would produce `"null"` as the audience.

## Affected Files

- `content/browser/webid/delegation/sd_jwt.cc:550-578` — `Jwt::Parse` with explicit TODO: "implement the validations described here" (RFC 7519 section 7.2)
- `content/browser/webid/delegation/email_verification_request.cc:87-90` — opaque origin not checked for `aud` claim
- `content/browser/webid/delegation/email_verification_request.cc:258-259` — TODO: "check if all of the necessary fields of the SD-JWT are present and valid"
- `content/browser/webid/delegation/email_verification_request.cc:280` — hardcoded `RS256` for key binding JWT when initial key may be EdDSA/ES256

## Attack Scenario

1. Attacker controls DNS for victim email domain (or MITM between browser and issuer)
2. DNS `_email-verification.evil.example` TXT record points to attacker's server
3. Attacker's server returns a forged SD-JWT with arbitrary claims (e.g., verified email for victim)
4. Browser accepts the forged JWT without signature verification
5. Website receives the SD-JWT+KB and trusts it as proof of email ownership

## Impact

- **MITM/DNS attacker**: Can forge email verification for any email domain they can intercept
- **Malicious issuer**: Any issuer can claim any email is verified, since the browser doesn't verify the SD-JWT's cryptographic binding

## VRP Value

**Low-Medium** — Feature is `FEATURE_DISABLED_BY_DEFAULT` (content_features.cc:409), so not enabled in production. But the bugs should be fixed before the feature ships:
1. Missing JWT signature validation is a fundamental cryptographic flaw
2. Opaque origin in `aud` is a correctness issue
3. Algorithm mismatch (RS256 hardcoded for KB-JWT regardless of initial key) could cause interop issues

## Chromium Awareness

Fully known — explicit TODO comments reference the missing validations (crbug.com/380367784).
