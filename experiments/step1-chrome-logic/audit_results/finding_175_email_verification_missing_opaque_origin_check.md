# Finding 175: Email Verification Protocol Missing Opaque Origin Check

## Summary
The `EmailVerificationRequest::CreateRequestToken()` function uses `render_frame_host_->GetLastCommittedOrigin().Serialize()` as the JWT audience (`aud`) field without validating that the origin is not opaque. A TODO comment on line 87-89 explicitly acknowledges this gap. If the RenderFrameHost has an opaque origin (e.g., sandboxed iframe, data: URL), the audience field will be serialized as `"null"`, creating a JWT with a meaningless audience claim that could be replayed across different opaque contexts.

## Affected Files
- `content/browser/webid/delegation/email_verification_request.cc:86-90` -- Missing opaque origin validation in `CreateRequestToken()`
- `content/browser/webid/delegation/email_verification_request.cc:284` -- Same issue in `OnTokenRequestComplete()` for the key-binding JWT

## Details
```cpp
sdjwt::Payload payload;
payload.email = email;
// TODO(crbug.com/380367784): check if `render_frame_host_` isn't an
// opaque origin, or any other validation that might be
// necessary.
payload.aud = render_frame_host_->GetLastCommittedOrigin().Serialize();
```

And the same issue in the key-binding JWT:
```cpp
sdjwt::Payload payload;
payload.aud = render_frame_host_->GetLastCommittedOrigin().Serialize();
payload.nonce = nonce;
```

When an origin is opaque, `Serialize()` returns `"null"`. This means the JWT audience claim is the string `"null"`, which is:
1. Not unique to any particular origin
2. Shared across all opaque origins

## Attack Scenario
1. A sandboxed iframe (with opaque origin) on attacker.com triggers the email verification flow.
2. The browser creates a request token JWT with `aud: "null"`.
3. The issuer returns an SD-JWT bound to audience `"null"`.
4. The SD-JWT+KB presentation is created with `aud: "null"` in the key-binding JWT.
5. This presentation can be replayed by any other opaque-origin context since the audience is effectively unbound.
6. Alternatively, the attacker manipulates the context so the verifier website sees `"null"` as the audience, which matches any opaque context.

## Impact
- SD-JWT presentations from opaque origins have no meaningful audience binding.
- Cross-context replay of email verification tokens is possible among opaque origins.
- Undermines the security guarantees of the email verification protocol.

## VRP Value
**Medium** -- The email verification protocol is behind `FEATURE_DISABLED_BY_DEFAULT` (kEmailVerificationProtocol), so not yet widely deployed. However, this is a fundamental cryptographic binding flaw acknowledged by the developers in a TODO that affects the integrity of the entire protocol when used from sandboxed contexts.
