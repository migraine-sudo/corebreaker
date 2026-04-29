# Finding 187: FedCM IdP Sign-In Status Uses Same-Site Check Instead of Same-Origin

## Summary
The `SetIdpSigninStatus()` function in both `request_service.cc` and `webid_utils.cc` uses `net::SchemefulSite::IsSameSite()` to validate whether a subresource or frame is allowed to set the IdP sign-in status. This is weaker than a same-origin check: it allows any subdomain of the same registrable domain to set the sign-in status. This means `tracker.example.com` can set the sign-in status for `accounts.example.com`, even though they are different origins.

## Affected Files
- `content/browser/webid/request_service.cc:684` -- `IsSameSiteWithAncestors()` check for Mojo-based SetIdpSigninStatus
- `content/browser/webid/webid_utils.cc:42-52` -- `IsSameSiteWithAncestors()` implementation uses `SchemefulSite::IsSameSite()`
- `content/browser/webid/webid_utils.cc:84-89` -- Header-based SetIdpSigninStatus uses `IsSameSite()` for initiator check
- `content/browser/webid/webid_utils.cc:100` -- Ancestor check uses `IsSameSiteWithAncestors()`

## Details
```cpp
bool IsSameSiteWithAncestors(const url::Origin& origin,
                             RenderFrameHost* render_frame_host) {
  while (render_frame_host) {
    if (!net::SchemefulSite::IsSameSite(
            origin, render_frame_host->GetLastCommittedOrigin())) {
      return false;
    }
    render_frame_host = render_frame_host->GetParent();
  }
  return true;
}
```

And in the header-based path:
```cpp
if (destination != network::mojom::RequestDestination::kDocument) {
    if (!initiator || !net::SchemefulSite::IsSameSite(idp_origin, *initiator)) {
      // ...
      return;
    }
}
```

Same-site means same registrable domain (eTLD+1), so `sub1.example.com` and `sub2.example.com` are considered same-site. This means:
- An embedded tracker on `tracker.example.com` can set the sign-in status for `idp.example.com`.
- A compromised subdomain can manipulate the IdP sign-in status for the main domain.

## Attack Scenario
1. An IdP operates at `accounts.example.com`.
2. The eTLD+1 `example.com` also hosts other subdomains, including `forum.example.com` or `ads.example.com`.
3. A cross-site attacker compromises or controls content on `forum.example.com`.
4. The attacker loads a subresource from `accounts.example.com` that includes a `Set-Login: logged-in` header, or uses the JavaScript API from a same-site context.
5. The browser sets the IdP sign-in status for `accounts.example.com` to "signed-in" based on the same-site check.
6. This enables the attacker to trigger FedCM flows that would otherwise be blocked (because the IdP appears signed-in).
7. Alternatively, the attacker sets the sign-in status to "logged-out" to disrupt legitimate FedCM flows.

## Impact
- IdP sign-in status can be manipulated by any same-site origin, not just same-origin.
- Cross-subdomain attackers can control whether FedCM requests proceed.
- Setting sign-in status to "signed-in" enables credentialed fetches to the IdP's accounts endpoint.
- Setting sign-in status to "signed-out" can deny service to legitimate FedCM flows.

## VRP Value
**Low-Medium** -- Same-site vs same-origin is a common design trade-off in web platform APIs. The comment in the code suggests this is intentional ("the document is same site with all ancestors"), but the security implications of allowing cross-subdomain sign-in status manipulation are not trivial. Does not require a compromised renderer.
