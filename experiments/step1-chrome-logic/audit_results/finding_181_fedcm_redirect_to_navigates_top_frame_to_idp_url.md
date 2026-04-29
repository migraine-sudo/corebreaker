# Finding 181: FedCM redirect_to Navigates Top-Level Frame to IdP-Controlled URL

## Summary
When an IdP responds with a `redirect_to` field in its token response, the browser navigates the top-level frame to an arbitrary HTTPS URL chosen by the IdP. The navigation is performed with `is_renderer_initiated = true` and `has_user_gesture = had_transient_user_activation_`, which is almost always true due to Finding 174. The referrer is set to the intercepted URL. Combined with the ability to send POST data with an attacker-controlled body, this creates an open redirect from the RP's context to any HTTPS URL, with the RP's URL as the referrer.

## Affected Files
- `content/browser/webid/request_service.cc:1845-1912` -- `RedirectTo()` navigates top frame to IdP-controlled URL
- `content/browser/webid/request_service.cc:350-353` -- `can_accept_redirect_to_` is true when navigation interception is enabled
- `content/browser/webid/request_service.cc:1893-1901` -- POST method with attacker-controlled body

## Details
```cpp
void RequestService::RedirectTo(const GURL& idp_config_url,
                                blink::mojom::RedirectParams::Tag method,
                                const GURL& redirect_to,
                                const std::string& request_body) {
  if (!can_accept_redirect_to_ || !redirect_to.SchemeIsHTTPOrHTTPS()) {
    // error...
    return;
  }
  // ...
  content::NavigationController::LoadURLParams params(redirect_to);
  params.transition_type = ui::PAGE_TRANSITION_LINK;
  params.initiator_origin = origin();  // RP origin as initiator
  params.referrer = Referrer(intercepted_url_, network::mojom::ReferrerPolicy::kDefault);
  params.is_renderer_initiated = true;
  params.has_user_gesture = had_transient_user_activation_;
  // For POST:
  params.post_data = network::ResourceRequestBody::CreateFromCopyOfBytes(
      base::as_byte_span(request_body));
```

The `redirect_to` URL is only checked for `SchemeIsHTTPOrHTTPS()`. There is no origin restriction -- the IdP can redirect to any HTTPS URL, including attacker-controlled sites. The navigation carries the RP's URL as the referrer and the RP's origin as the initiator.

## Attack Scenario
1. User visits legitimate-rp.com which uses FedCM navigation interception.
2. The IdP (malicious-idp.com) returns a token response with `redirect_to: "https://attacker.com/steal?from=rp"`.
3. The browser navigates the top-level frame from legitimate-rp.com to attacker.com.
4. The navigation carries `Referer: https://legitimate-rp.com/login` and has `has_user_gesture = true`.
5. If POST method is used, the attacker can craft a CSRF-like request to any HTTPS endpoint, with a controlled body, initiated from the RP's context.
6. The user sees a sudden top-level navigation away from the RP to the attacker's site.

## Impact
- Open redirect from any RP that uses FedCM navigation interception.
- IdP can redirect the user to phishing pages that appear to originate from the RP.
- POST redirect enables cross-site request forgery-like attacks with attacker-controlled body.
- The RP's URL is leaked as referrer to the redirect target.
- Combined with Finding 174 (user activation always true), the navigation has user gesture, giving it elevated trust.

## VRP Value
**Medium-High** -- While FedCM navigation interception requires opt-in (behind `FEATURE_DISABLED_BY_DEFAULT`), and requires the IdP to be the attacker, the design allows a registered IdP to perform arbitrary top-level navigations with POST data from the RP's context. This is a significant trust boundary violation.
