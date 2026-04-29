# Finding 184: FedCM IdentityCredentialSource Fetches Accounts Without Client ID

## Summary
The `IdentityCredentialSourceImpl::GetIdentityCredentialSuggestions()` function creates FedCM account fetch requests with an empty string for `client_id`. This means the accounts endpoint receives no client identification, preventing the IdP from performing client-specific authorization checks. Additionally, the code explicitly acknowledges that `client_is_third_party_to_top_frame_origin` cannot be checked because no client_id was provided.

## Affected Files
- `content/browser/webid/identity_credential_source_impl.cc:102-103` -- `client_id` set to empty string
- `content/browser/webid/identity_credential_source_impl.cc:208-209` -- Cannot check third-party status without client_id

## Details
```cpp
options->config = blink::mojom::IdentityProviderConfig::New();
options->config->config_url = idp;
// We don't have the client_id here, so we pass an empty string.
options->config->client_id = "";
```

And later:
```cpp
for (const auto& result : results) {
    // We did not pass client_id, so we cannot check
    // client_is_third_party_to_top_frame_origin here.
    if (result.accounts.has_value()) {
```

This means:
1. The accounts endpoint is called without a `client_id`, so the IdP cannot determine which RP is making the request.
2. The `approved_clients` list cannot be checked against a valid client_id, so login state determination may be wrong.
3. The third-party check is skipped entirely.

## Attack Scenario
1. An embedder (e.g., a browser extension or native application) requests identity credential suggestions.
2. The request is sent to the IdP's accounts endpoint without a client_id.
3. The IdP may return accounts that should not be visible to the requesting party, since it cannot perform client-specific filtering.
4. If the IdP's accounts endpoint returns different data when no client_id is present (e.g., all accounts instead of a filtered subset), the embedder learns about accounts it should not see.
5. The missing third-party check means accounts from IdPs that are third-party to the top frame are included in suggestions.

## Impact
- IdP accounts endpoint called without client identification, preventing server-side authorization.
- `approved_clients` filtering cannot work correctly with an empty client_id.
- Third-party IdP filtering is bypassed.
- Potential information disclosure of user accounts to unauthorized embedders.

## VRP Value
**Low-Medium** -- The `IdentityCredentialSource` is a newer API surface (copyright 2026) for embedder-initiated login. The missing client_id weakens the IdP's ability to perform access control, but the impact depends on how IdPs handle requests with empty client_id.
