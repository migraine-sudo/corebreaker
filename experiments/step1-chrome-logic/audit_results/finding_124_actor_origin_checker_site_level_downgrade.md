# Finding 124: Actor Origin Checker Can Be Downgraded to Site-Level Matching via Feature Flag

## Severity: MEDIUM

## Summary

The `kGlicNavigationGatingUseSiteNotOrigin` feature parameter (default: false) changes the origin checker from origin-based matching to site-based matching. When enabled, approving `https://a.example.com` would also approve `https://b.example.com`, `https://evil.example.com`, and any other subdomain. This is a significant security downgrade controllable via Finch.

## Affected Files

- `components/actor/core/origin_checker.cc:21-28` -- IsSameForNewOriginNavigationGating()
- `components/actor/core/actor_features.cc:74-77` -- Feature parameter definition

## Details

```cpp
// origin_checker.cc:21-28
bool IsSameForNewOriginNavigationGating(const url::Origin& reference_origin,
                                        const url::Origin& destination_origin) {
  if (kGlicNavigationGatingUseSiteNotOrigin.Get()) {
    return net::SchemefulSite::IsSameSite(reference_origin, destination_origin);
  }
  return reference_origin.IsSameOriginWith(destination_origin);
}
```

`SchemefulSite::IsSameSite()` compares the registrable domain (eTLD+1), meaning:
- `https://accounts.google.com` approves `https://malicious.google.com`
- `https://www.example.com` approves `https://attacker-subdomain.example.com`
- Any subdomain takeover becomes a full Actor origin bypass

This affects:
1. `IsNavigationAllowed()` -- whether navigation is pre-approved
2. The initiator origin check in the same function
3. All calls to `AllowNavigationTo()` that populate the allowlist

## Attack Scenario

1. Finch experiment enables `gate_on_site_not_origin=true` for a Chrome population
2. User approves Actor to navigate to `https://www.example.com`
3. `example.com`'s origin is added to the allowed list
4. Attacker exploits a subdomain takeover on `attacker.example.com`
5. AI agent navigates to `attacker.example.com` -- this passes the site-level check
6. No additional confirmation is shown to the user
7. Attacker controls a page that the Actor believes is pre-approved

## Impact

- Subdomain takeover attacks become Actor navigation bypasses
- Shared hosting platforms (e.g., GitHub Pages, Cloudflare Workers) where multiple parties control subdomains under the same eTLD+1 become dangerous
- User's approval of one subdomain silently approves all sibling subdomains
- Controllable via Finch server-side, no user consent for the downgrade

## Remediation

This feature parameter should be removed or, at minimum, gated behind a much stronger check. Site-level matching is fundamentally incompatible with the security requirements of an AI agent that can interact with web pages and handle credentials.
