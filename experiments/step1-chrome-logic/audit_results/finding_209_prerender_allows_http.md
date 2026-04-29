# Finding 209: Prerender Allows Non-Trustworthy HTTP Pages (kPrerender2DisallowNonTrustworthyHttp Disabled)

## Summary

`kPrerender2DisallowNonTrustworthyHttp` is DISABLED by default, meaning plain HTTP pages can be prerendered. Prerendering executes JavaScript and makes network requests in the background before the user navigates. For HTTP pages, this creates a MITM attack vector: a network attacker can inject malicious JavaScript into a prerendered HTTP page, which executes silently in the background.

## Affected Files

- `content/browser/preloading/prerender/prerender_features.cc:76-77` — Feature DISABLED_BY_DEFAULT

## Details

```cpp
// prerender_features.cc:74-77
// If enabled, disallows non-trustworthy plaintext HTTP prerendering.
// See https://crbug.com/340895233 for more details.
BASE_FEATURE(kPrerender2DisallowNonTrustworthyHttp,
             base::FEATURE_DISABLED_BY_DEFAULT);
```

## Attack Scenario

### MITM prerender injection
1. User is on a page that contains `<script type="speculationrules">` pointing to an HTTP URL
2. The HTTP URL is prerendered — Chrome fetches it and executes JavaScript in a hidden tab
3. A network attacker (e.g., on public WiFi) intercepts the HTTP prerender request
4. Attacker injects malicious JavaScript into the response
5. The injected code executes in the prerendered page's context
6. When the user navigates to the prerendered page, it activates with the attacker's code already running
7. The code has access to the page's origin, can steal cookies (if not HttpOnly), and modify the page content

### Amplification via speculation rules
1. Attacker controls an HTTPS page that includes speculation rules pointing to HTTP URLs
2. Visiting the HTTPS page triggers background prerendering of multiple HTTP targets
3. Each prerender is a separate MITM opportunity, multiplying the attack surface
4. The user sees no indication that HTTP pages are being loaded in the background

## Impact

- **No compromised renderer required**: Standard web API + network MITM
- **Silent execution**: Prerendered JavaScript runs before user navigates
- **MITM amplification**: Speculation rules can trigger multiple prerendering requests
- **Spec deviation**: The feature flag exists specifically to prevent this, but is disabled

## VRP Value

**Medium** — Prerendering HTTP pages enables MITM JavaScript injection before user navigation. The fix exists (kPrerender2DisallowNonTrustworthyHttp) but is disabled. This is a design-level security gap in the prerendering pipeline.
