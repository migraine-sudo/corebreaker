# Finding 136: Prerender Allows Plaintext HTTP by Default (kPrerender2DisallowNonTrustworthyHttp Disabled)

## Summary
The feature flag `kPrerender2DisallowNonTrustworthyHttp` is defined as `FEATURE_DISABLED_BY_DEFAULT` and is never referenced anywhere in the codebase beyond its definition. This means prerendering of plaintext HTTP URLs on non-trustworthy origins is permitted. An attacker on a shared network (MITM position) could inject speculation rules pointing to HTTP URLs, causing the browser to prerender attacker-controlled content that could then be activated as the user's primary page without the usual mixed-content or secure-context warnings that would apply during normal navigation.

## Affected Files
- `content/browser/preloading/prerender/prerender_features.cc` (lines 76-77) - Flag defined but disabled
- `content/browser/preloading/prerender/prerender_features.h` (line 61) - Flag declared
- `content/browser/preloading/prerender/prerender_navigation_throttle.cc` - No check for non-trustworthy HTTP

## Details
```cpp
// prerender_features.cc:76-77
// If enabled, disallows non-trustworthy plaintext HTTP prerendering.
// See https://crbug.com/340895233 for more details.
BASE_FEATURE(kPrerender2DisallowNonTrustworthyHttp,
             base::FEATURE_DISABLED_BY_DEFAULT);
```

The flag is defined with a comment referencing crbug.com/340895233 indicating it was intended to block non-trustworthy HTTP prerendering. However, grep of the entire codebase shows it is **never checked** -- it exists only as a definition in the features file. The `PrerenderNavigationThrottle::WillStartOrRedirectRequest()` only checks `SchemeIsHTTPOrHTTPS()` which allows both HTTP and HTTPS.

## Attack Scenario
1. Attacker is on a shared network (e.g., public WiFi) with a victim
2. Victim visits `https://attacker.com` which includes speculation rules: `{"prerender": [{"source": "list", "urls": ["http://victim-bank.com/transfer"]}]}`
3. The browser prerenders the HTTP URL. The attacker, being a MITM, can serve arbitrary content for the HTTP request
4. When the user clicks a link to `http://victim-bank.com/transfer`, the prerendered (attacker-injected) page activates as the primary page
5. The attacker's injected page could mimic the real bank page to phish credentials

Note: While modern browsers do have HTTPS-first mode and HSTS protections, not all users have these enabled, and not all sites use HSTS. The prerender path does not enforce the same protections as regular navigation would.

## Impact
Medium - Requires MITM position and targets only HTTP URLs, but the prerender activation path may bypass some of the UI warnings that would normally alert users to non-secure content. The feature was explicitly intended to address this (crbug.com/340895233) but remains unimplemented.

## VRP Value
Low
