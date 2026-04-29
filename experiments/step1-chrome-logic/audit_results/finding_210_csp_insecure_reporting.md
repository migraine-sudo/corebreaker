# Finding 210: CSP Violation Reports Sent to Insecure HTTP Endpoints (Mixed Content)

## Summary

Chrome sends CSP violation reports to HTTP (insecure) endpoints even from HTTPS pages. The code contains an explicit TODO (crbug.com/695363) acknowledging this is a mixed content violation that should be blocked. CSP violation reports contain sensitive information including the document URL, violated directive, source file, and line number — all of which could be intercepted by a network attacker when sent over HTTP.

## Affected Files

- `third_party/blink/renderer/core/frame/csp/content_security_policy.cc:1423-1424` — Known mixed content issue

## Details

```cpp
// content_security_policy.cc:1415-1424
// directive that was violated. The document's URL is safe to send because
// it's the document itself that's requesting that it be sent. You could
// make an argument that we shouldn't send HTTPS document URLs to HTTP
// report-uris (for the same reasons that we supress the Referer in that
// case), but the Referer is sent implicitly whereas this request is only
// sent explicitly. As for which directive was violated, that's pretty
// harmless information.
//
// TODO(mkwst): This justification is BS. Insecure reports are mixed content,
// let's kill them. https://crbug.com/695363
```

CSP violation reports contain:
- `document-uri`: The full URL of the page
- `referrer`: The referrer of the page
- `blocked-uri`: The URL that was blocked
- `source-file`: The source file where the violation occurred
- `line-number` and `column-number`: Exact code location
- `original-policy`: The complete CSP policy

## Attack Scenario

1. HTTPS page `https://victim.com` sets CSP with `report-uri http://report.example.com/`
2. When a CSP violation occurs, Chrome sends a POST request to the HTTP endpoint
3. Network attacker (MITM, public WiFi) intercepts the report
4. The report reveals:
   - What URLs the user is visiting (document-uri)
   - What external resources the page tried to load (blocked-uri)
   - Internal script locations and line numbers (source-file, line-number)
   - The site's complete security policy (original-policy)

### Active exploitation variant
1. MITM attacker controls the HTTP response to the CSP report
2. Attacker injects a redirect to a different endpoint
3. Or attacker correlates report timing with user activity
4. The CSP report acts as a side channel for tracking user behavior

## Impact

- **No compromised renderer required**: Standard CSP reporting mechanism
- **Information leak**: Sensitive page details sent over cleartext HTTP
- **Mixed content**: HTTPS page sends data to HTTP endpoint
- **Spec issue**: The CSP reporting spec (now deprecated in favor of Reporting API) allowed this
- **Long-standing**: crbug.com/695363 has been open since 2017

## VRP Value

**Low-Medium** — Information leakage through insecure CSP reporting. While `report-uri` is deprecated in favor of `report-to` (which uses the Reporting API), many sites still use `report-uri` and Chrome still supports it. The information in CSP reports is sensitive enough to warrant blocking insecure delivery.
