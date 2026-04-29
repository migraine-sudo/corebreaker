# Finding 071: Web Bundle Inner Responses Bypass Embedding Page's CSP

## Summary

The `WebBundleURLLoaderFactory` in the network service serves responses from web bundles without applying the embedding page's Content Security Policy to bundled resources. While CORP and ORB checks are performed, CSP enforcement is absent for bundled subresources.

## Affected Files

- `services/network/web_bundle/web_bundle_url_loader_factory.cc:824-911` — `SendResponseToLoader()` applies CORP/ORB but not CSP
- `services/network/web_bundle/web_bundle_url_loader_factory.cc:792` — Adds X-Content-Type-Options: nosniff but no CSP

## Details

In `SendResponseToLoader()`, the following security checks are performed:
- CORP (Cross-Origin-Resource-Policy) check
- ORB (Opaque Response Blocking) check
- Auction-only signal check
- X-Content-Type-Options: nosniff enforcement

But no CSP enforcement is applied. The embedding page's CSP directives (like `script-src`, `style-src`, `img-src`) are not checked against resources served from the bundle.

```cpp
// web_bundle_url_loader_factory.cc — Checks performed
// ✅ CORP check
// ✅ ORB check
// ✅ Auction-only signal
// ✅ X-Content-Type-Options: nosniff
// ❌ CSP enforcement — MISSING
```

## Attack Scenario

### CSP bypass via subresource web bundle

1. A page at `https://example.com` has `Content-Security-Policy: script-src 'self'`
2. The page loads a web bundle via `<script type="webbundle">`
3. The bundle contains a script resource at a same-origin URL (e.g., `https://example.com/injected.js`)
4. The bundled script is served from the bundle without CSP being applied
5. Even though the page's CSP would normally block inline/external scripts not matching the policy, the bundled resource bypasses this enforcement
6. The attacker-controlled script executes in the context of the page

### Prerequisite

The attacker needs the ability to make the page load a `<script type="webbundle">` pointing to their bundle. This requires either:
- An injection point (e.g., HTML injection without XSS due to CSP)
- The page already loading user-controlled web bundles

## Impact

- **No compromised renderer required**: Standard web APIs
- **CSP bypass**: Pages relying on CSP to prevent script injection lose that protection for bundled resources
- **Escalation**: HTML injection → XSS if the page uses web bundles

## VRP Value

**Medium** — CSP bypass is significant but exploitation requires specific conditions (page must use web bundles, and attacker needs some injection capability). However, the core issue — CSP not being enforced on bundled subresources — is a clear security gap in the web bundle implementation.
