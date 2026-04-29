# Finding 180: FedCM Document Metadata Parser Missing Field Validation

## Summary
The `document_metadata.cc` parser for schema.org LoginAction entities extracts FedCM provider configuration (configURL, clientId, nonce, fields) from page metadata without validating that these fields are well-formed. A TODO at line 88 explicitly acknowledges this. The parser uses renderer-supplied data from a mojom interface (`schema_org::mojom::Entity`) to construct `IdentityProviderGetParameters` objects that feed directly into the FedCM request flow. The only validation is that `config_url` produces a valid GURL.

## Affected Files
- `content/browser/webid/document_metadata.cc:65-121` -- `Parse()` function with missing validation
- `content/browser/webid/document_metadata.cc:88-89` -- TODO acknowledging the gap
- `content/browser/webid/document_metadata.cc:125-128` -- Uses `GetRemoteInterfaces()` to get renderer-controlled data

## Details
```cpp
std::optional<blink::mojom::IdentityProviderGetParametersPtr> Parse(
    const schema_org::mojom::Entity& entity) {
  // ...
  for (const auto& provider_entity : property->values->get_entity_values()) {
    auto options = blink::mojom::IdentityProviderRequestOptions::New();
    options->config = blink::mojom::IdentityProviderConfig::New();

    // TODO(crbug.com/477699742): validate that the necessary fields
    // are present and well-formed.
    auto config_url = GetStringProperty(provider_entity, kConfigUrlProperty);
    if (config_url) {
      options->config->config_url = GURL(*config_url);
    }

    auto client_id = GetStringProperty(provider_entity, kClientIdProperty);
    if (client_id) {
      options->config->client_id = *client_id;  // No validation
    }

    auto nonce = GetStringProperty(provider_entity, kNonceProperty);
    if (nonce) {
      options->nonce = *nonce;  // No validation
    }

    options->fields = GetStringArrayProperty(provider_entity, kFieldsProperty);
    // No validation of fields array contents
```

The data comes from the renderer:
```cpp
DocumentMetadata::DocumentMetadata(RenderFrameHost* rfh) {
  rfh->GetRemoteInterfaces()->GetInterface(
      metadata_remote_.BindNewPipeAndPassReceiver());
}
```

## Attack Scenario
1. A page includes schema.org metadata with a LoginAction entity containing malicious values.
2. The renderer (even uncompromised) sends this metadata via the mojom interface.
3. The browser-side parser extracts `client_id` without validation -- it could be empty, excessively long, or contain special characters that affect URL construction when used in the token request.
4. The `nonce` field is accepted without validation -- it could be empty or contain characters that break the token request format.
5. The `fields` array is passed through without checking for invalid or excessive entries.
6. These unvalidated values are used to construct FedCM requests, potentially causing unexpected behavior in the IdP's token endpoint.

## Impact
- Renderer-controlled metadata values are passed to the browser-side FedCM flow without validation.
- Malformed `client_id` or `nonce` values could cause unexpected behavior at the IdP's endpoints.
- Excessive or invalid `fields` entries could confuse the disclosure flow.
- While the downstream FedCM flow has some checks (e.g., the `RequestService::ShouldTerminateRequest` validates provider count), individual field values are not validated.

## VRP Value
**Low** -- This is a data validation gap for renderer-sourced parameters. The document metadata feature is new and the impact is bounded by downstream validation in the FedCM flow. However, the principle of not trusting renderer-supplied data browser-side is important.
