# Finding 238: SameSite=Strict Cookies Sent Despite Cross-Site Redirect in Chain

## Summary

Chrome's `kCookieSameSiteConsidersRedirectChain` feature is DISABLED by default (`net/base/features.cc:204-205`). This means when computing SameSite cookie context, Chrome only considers the initiator and the final URL — intermediate redirects through cross-site URLs are ignored. A same-site initiator request that passes through a cross-site redirect still receives `SameSite=Strict` cookies.

## Severity: Medium (CSRF bypass for SameSite=Strict protection)

## Affected Component

- Cookie SameSite context computation
- `net/cookies/cookie_util.cc` (SameSite context functions)

## Root Cause

`net/base/features.cc:204-205`:
```cpp
BASE_FEATURE(kCookieSameSiteConsidersRedirectChain,
             base::FEATURE_DISABLED_BY_DEFAULT);
```

`net/cookies/cookie_util.cc:253-283`:
```cpp
if (same_site_initiator) {
    if (same_site_redirect_chain) {
        result.context_type = ContextType::SAME_SITE_STRICT;
        return result;
    }
    cross_site_redirect_downgraded_from_strict = true;
    use_strict = !base::FeatureList::IsEnabled(
        features::kCookieSameSiteConsidersRedirectChain);
    // use_strict = true (feature disabled) → keeps SAME_SITE_STRICT
}
// For subresource requests:
result.context_type =
    use_strict ? ContextType::SAME_SITE_STRICT : ContextType::CROSS_SITE;
```

## Attack Scenario

1. Attacker injects content on `victim.com` (e.g., via XSS on a low-privilege page, or user-generated content)
2. Injected content creates a request with same-site initiator that passes through attacker's redirect:
   ```html
   <!-- On victim.com -->
   <img src="https://evil.com/redirect?to=https://victim.com/api/transfer?amount=1000&to=attacker">
   ```
3. Request chain: initiator=victim.com → evil.com/redirect → victim.com/api/transfer
4. `same_site_initiator = true` (victim.com → victim.com)
5. `same_site_redirect_chain = false` (evil.com in chain)
6. With feature DISABLED: `use_strict = true` → `SAME_SITE_STRICT` context
7. **SameSite=Strict CSRF token cookie is sent to victim.com/api/transfer**
8. The redirect through evil.com allows the attacker to:
   - Add custom request headers (via 307 redirect preserving method/body)
   - Log that the request was made (timing side-channel)
   - Potentially observe the response via redirect chain manipulation

## Limitations

- Attacker needs ability to inject content on the victim site (for same-site initiator)
- GET-based CSRF only (unless using 307/308 redirects)
- Most modern APIs use POST for state-changing operations
- The attacker cannot read the response (it goes to the user's browser)

## Why This Is Not Just a "Known Issue"

While Chrome team has intentionally disabled this feature for compatibility reasons, the security implication is significant:
- SameSite=Strict is the STRONGEST cookie protection available
- Developers rely on it to prevent CSRF attacks
- The redirect chain bypass weakens the security guarantee without clear documentation to developers

## Platform

All platforms where Chrome runs with default configuration.

## Files

- `net/base/features.cc:204-205` (feature disabled by default)
- `net/cookies/cookie_util.cc:253-283` (context computation logic)
- `net/cookies/cookie_util.cc:264-265` (`use_strict` controlled by feature flag)
