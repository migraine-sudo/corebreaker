# Finding 137: FedCM SameSite=Lax Relaxation Allows Unsafe HTTP Methods with Lax Cookies

**Severity: MEDIUM**

**Component:** `services/network/url_loader_util.cc`, `net/cookies/cookie_util.cc`

## Summary

When the `kSendSameSiteLaxForFedCM` feature flag is enabled (currently disabled by default), FedCM requests with `RequestDestination::kWebIdentity` or `RequestDestination::kEmailVerification` set `ignore_unsafe_method_for_same_site_lax` to true. This causes SameSite=Lax cookies to be sent on POST requests to the identity provider, bypassing the core SameSite=Lax protection that unsafe methods should NOT get Lax cookies on cross-site navigation.

While there is a check ensuring FedCM requests must either disable redirects OR disable cookies, the enforcement relies on a CHECK in one code path and a validation in `CorsURLLoaderFactory::IsValidRequest` in another. The `IsValidRequest` validation can only be triggered from non-browser processes.

## Vulnerable Code

```cpp
// services/network/url_loader_util.cc:576-583
if (base::FeatureList::IsEnabled(features::kSendSameSiteLaxForFedCM) &&
    (request.destination == mojom::RequestDestination::kWebIdentity ||
     request.destination == mojom::RequestDestination::kEmailVerification)) {
  // This check is enforced by CorsURLLoaderFactory::IsValidRequest.
  CHECK(request.redirect_mode == mojom::RedirectMode::kError ||
        request.credentials_mode == mojom::CredentialsMode::kOmit);
  url_request.set_ignore_unsafe_method_for_same_site_lax(true);
}
```

```cpp
// net/cookies/cookie_util.cc:945-952
if (!ignore_unsafe_method_for_same_site_lax &&
    !net::HttpUtil::IsMethodSafe(http_method)) {
  if (result.context_type == ContextType::SAME_SITE_LAX) {
    result.context_type = ContextType::SAME_SITE_LAX_METHOD_UNSAFE;
  }
  // ...
}
```

## Security Concern

1. **Feature flag risk**: The feature is `FEATURE_DISABLED_BY_DEFAULT` but is being prepared for production use. When enabled, it fundamentally changes SameSite=Lax semantics for an entire request destination type.

2. **Destination-based gating**: The only thing preventing abuse is the `request.destination` check. In `CorsURLLoaderFactory::IsValidRequest()` (line 803-808), `kWebIdentity` and `kEmailVerification` destinations are forbidden from renderer processes. However, for browser-initiated requests (`process_id_.is_browser()`), the `InitiatorLockCompatibility` is set to `kBrowserProcess` and the destination check is skipped.

3. **Redirect-or-credentials constraint**: The CHECK ensures either redirects are disabled OR credentials are omitted. But `redirect_mode == kError` with credentials enabled still allows POST requests with SameSite=Lax cookies to be sent to the target without following redirects -- this is the design intent for FedCM, but it creates a precedent where cross-site POST requests can carry Lax cookies.

4. **FedCM flag interaction**: In `content/browser/webid/flags.cc`, `IsSameSiteLaxEnabled()` directly exposes this feature flag. When multiple FedCM features interact (delegation, autofill, lightweight mode), the relaxation surface grows.

## Rating Justification

MEDIUM: Currently disabled by default. When enabled, the relaxation is designed and somewhat constrained (redirect-or-no-cookies). The main risk is in the interaction between this relaxation and other FedCM features, or if the destination check can be spoofed from a compromised browser-process component. The CHECK is good defense-in-depth.

## Related Code

- `cors/cors_url_loader_factory.cc:803-825` - Destination validation
- `content/browser/webid/flags.cc:48-51` - Feature flag check
- `services/network/public/cpp/features.cc:568` - Feature definition
