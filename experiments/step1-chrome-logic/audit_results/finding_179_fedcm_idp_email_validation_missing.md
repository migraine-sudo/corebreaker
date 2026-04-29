# Finding 179: FedCM IDP Account Email Address Not Validated

## Summary
When parsing account information from the IdP's accounts endpoint response, the email field is accepted without any validation. A TODO at `idp_network_request_manager.cc:252` explicitly notes this gap. This means a malicious IdP can return arbitrary strings as "email addresses" (e.g., XSS payloads, URLs, or misleading text) which are displayed in the browser-mediated FedCM UI and passed to the relying party as trusted account data.

## Affected Files
- `content/browser/webid/idp_network_request_manager.cc:252` -- TODO acknowledging missing email validation
- `content/browser/webid/idp_network_request_manager.cc:230-256` -- Account parsing accepts any non-empty string as email
- `content/browser/webid/user_info_request.cc:277-279` -- Email passed through to RP via `IdentityUserInfo`

## Details
```cpp
if (!IsEmptyOrWhitespace(email)) {
    // TODO(crbug.com/40849405): validate email address.
    identifiers.emplace_back(*email);
} else {
    email = &empty_string;
}
```

The email value flows from the IdP's JSON response directly into the account object:
```cpp
return base::MakeRefCounted<IdentityRequestAccount>(
    *id, display_identifier, display_name, *email, *name,
    given_name ? *given_name : "", picture ? GURL(*picture) : GURL(),
    // ...
```

This email is then:
1. Displayed in the FedCM consent dialog shown to the user.
2. Returned to the RP in the `getUserInfo()` response.
3. Used as a display identifier in various UI surfaces.

## Attack Scenario
1. A malicious IdP is registered (or is a legitimate IdP with a compromised accounts endpoint).
2. The IdP returns account data with the email field set to misleading text like `"admin@your-bank.com"` or `"Click here to verify"` or even control characters.
3. The browser's FedCM dialog displays this unvalidated string as the account's email address.
4. The user may be confused by the displayed email, potentially consenting to share an account they do not actually own.
5. Alternatively, excessively long or specially formatted email strings could cause UI rendering issues.

## Impact
- Social engineering: users see misleading email addresses in trusted browser UI.
- No format validation means arbitrary strings are treated as emails.
- Display confusion in FedCM consent dialogs.
- RPs trusting the "email" field receive unvalidated data.

## VRP Value
**Low-Medium** -- This is a data validation gap in browser-mediated UI. While the IdP controls its own account data, the browser's consent dialog implicitly endorses the information shown. The impact is primarily social engineering via misleading account display information. Does not require a compromised renderer.
