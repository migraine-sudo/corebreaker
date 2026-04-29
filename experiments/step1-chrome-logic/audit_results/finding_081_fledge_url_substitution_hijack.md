# Finding 081: Protected Audience deprecatedRenderURLReplacements Enables Ad Creative URL Hijacking

## Summary

In Protected Audience (FLEDGE) auctions, the seller can specify `deprecatedRenderURLReplacements` in the auction config. These string substitutions are applied to the winning ad's render URL after validation, with no same-origin or scheme check on the resulting URL. A malicious seller can hijack the ad creative destination by substituting macros in the buyer's URL.

## Affected Files

- `content/browser/interest_group/ad_auction_service_impl.cc:572-591` — DeprecatedReplaceInURN
- `content/browser/fenced_frame/fenced_frame_url_mapping.cc:467-496` — URL substitution
- `content/browser/interest_group/interest_group_auction.cc:1417-1432` — GetAdDescriptorWithReplacements

## Details

```cpp
// interest_group_auction.cc:1417-1432
// Substitutions applied with only is_valid() check after
url.spec() = base::ReplaceStringPlaceholders(
    url.spec(), replacements, nullptr);
// Only check: url.is_valid()
// No same-origin check, no scheme check
```

The seller provides `deprecatedRenderURLReplacements` via JavaScript `runAdAuction()`:
```javascript
navigator.runAdAuction({
  seller: 'https://seller.example',
  decisionLogicURL: 'https://seller.example/decision.js',
  deprecatedRenderURLReplacements: {
    '${CLICK_URL}': 'https://attacker.com/steal'
  }
});
```

## Attack Scenario

### Ad creative URL hijacking

1. Seller sets up a Protected Audience auction with `deprecatedRenderURLReplacements`
2. Buyer's ad URL contains standard ad macros: `https://ad-cdn.com/ad?click=${CLICK_URL}`
3. Seller substitutes `${CLICK_URL}` with `https://attacker.com/phishing`
4. The resulting URL passes `is_valid()` check
5. The fenced frame loads with the modified URL, redirecting ad clicks to attacker
6. User clicks the ad and lands on attacker's page instead of the expected destination

### Prerequisite

The buyer's ad creative URL must contain macro patterns (`${...}` or `%%...%%`). This is extremely common in programmatic advertising.

## Impact

- **No compromised renderer required**: Seller controls auction config via standard JS API
- **Ad hijacking**: Seller can modify buyer's ad URL to redirect to arbitrary destinations
- **Phishing vector**: Modified ad creative can display legitimate-looking content but link to phishing sites
- **Revenue theft**: Seller redirects ad clicks away from buyer's intended destination

## VRP Value

**Medium** — No compromised renderer. Straightforward exploitation via standard auction config. The `deprecatedRenderURLReplacements` API is designed for macro expansion but lacks same-origin validation after substitution.
