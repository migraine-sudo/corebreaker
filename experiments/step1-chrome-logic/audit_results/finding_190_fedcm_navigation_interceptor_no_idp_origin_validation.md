# Finding 190: FedCM Navigation Interceptor Does Not Validate IdP Config URL Origin Against Response Origin

## Summary
The `NavigationInterceptor` processes the `Federation-Initiate-Request` response header from any HTTPS URL that the navigation lands on. The header contains IdP configuration parameters (including the config URL) that are used to initiate a FedCM token request. However, the interceptor does not validate that the config URL in the header matches the origin of the responding server. This means a redirect to any HTTPS site that returns the header can trigger a FedCM flow for an arbitrary IdP.

## Affected Files
- `content/browser/webid/navigation_interceptor.cc:244-280` -- `OnHeaderParsed()` extracts config from header without origin validation
- `content/browser/webid/navigation_interceptor.cc:262-264` -- `RequestBuilder::Build()` takes URL from navigation, not from header validation
- `content/browser/webid/navigation_interceptor.cc:274-279` -- `RequestToken()` called with header-derived params

## Details
```cpp
void NavigationInterceptor::OnHeaderParsed(
    base::expected<net::structured_headers::Dictionary, std::string> result) {
  // ...
  RequestBuilder request_builder;
  auto idp_get_params_vector =
      request_builder.Build(navigation_handle()->GetURL(), *result);
  // ...
  service_builder_.Run(rfh)->RequestToken(
      std::move(*idp_get_params_vector),
      password_manager::CredentialMediationRequirement::kOptional,
      navigation_handle(),
      base::BindOnce(&NavigationInterceptor::OnTokenResponse,
                     weak_ptr_factory_.GetWeakPtr()));
}
```

The `navigation_handle()->GetURL()` is the URL of the server responding with the header, but the header's content can specify any config URL. The `RequestBuilder::Build()` constructs provider parameters from the header, which can point to a config URL on a different origin than the responding server.

## Attack Scenario
1. User clicks a link on rp.com that redirects through evil-redirector.com.
2. evil-redirector.com responds with `Federation-Initiate-Request: config="https://legitimate-idp.com/fedcm.json"`.
3. The navigation interceptor processes the header.
4. A FedCM flow is initiated for legitimate-idp.com, but the request originates from evil-redirector.com's response.
5. The user sees a FedCM dialog for legitimate-idp.com but the context is actually evil-redirector.com.
6. This could be used to phish credentials by making it appear that a legitimate IdP is requesting authentication when the actual context is an attacker's redirect.

## Impact
- Any server in a redirect chain can trigger FedCM flows for arbitrary IdPs.
- The FedCM request inherits the RP context of the original page, not the redirector.
- Phishing potential: users see a legitimate IdP dialog triggered by an attacker's redirect.
- The well-known file check (if not bypassed per Finding 178) provides some protection, but only validates that the config URL is in the well-known file, not that the responding server is authorized to trigger the flow.

## VRP Value
**Medium** -- While behind `FEATURE_DISABLED_BY_DEFAULT`, the navigation interception feature has significant security implications. The lack of origin validation between the responding server and the IdP config URL creates a trust boundary violation. Does not require a compromised renderer.
