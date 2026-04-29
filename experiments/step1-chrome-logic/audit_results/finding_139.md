# Finding 139: Prerender CSP Bypass via should_check_main_world_csp Mismatch

## Summary
The prerender activation code explicitly skips comparison of `should_check_main_world_csp` between the prerender navigation and the activation navigation. The comment states this permits content scripts to activate the page. However, this means a navigation that would normally bypass main-world CSP checks (e.g., from a browser extension content script) can activate a prerendered page that was checked against CSP, or vice versa -- a page prerendered under one CSP policy could be activated by a navigation with different CSP enforcement expectations.

## Affected Files
- `content/browser/preloading/prerender/prerender_host.cc` (lines 1313-1317) - Explicit skip of CSP check comparison

## Details
```cpp
// prerender_host.cc:1313-1317
// No need to compare should_check_main_world_csp, as if the CSP blocks the
// initial navigation, it cancels prerendering, and we don't reach here for
// matching. So regardless of the activation's capability to bypass the main
// world CSP, the prerendered page is eligible for the activation. This also
// permits content scripts to activate the page.
```

The logic here is:
1. If prerender navigation is blocked by CSP, prerendering is cancelled
2. If prerender succeeds, it means CSP allowed it
3. Therefore, the activation navigation does not need to re-check CSP

The issue is that CSP disposition (`CHECK` vs `DO_NOT_CHECK`) is not symmetric: a prerendered page that passed CSP under `CHECK` mode gets activated by a navigation that has `DO_NOT_CHECK` (typically from privileged contexts). This means:
- An extension's content script can trigger navigation to a URL and activate a prerendered page, even if the extension's navigation would normally bypass CSP (the prerendered page was loaded under the page's CSP, not the extension's privileged context)
- Conversely, if a page's CSP allows a URL but the extension's CSP would not, the prerendered page still activates

## Attack Scenario
1. A web page includes strict CSP: `default-src 'self'`
2. The page also includes speculation rules to prerender `https://same-origin.com/page`
3. The prerender succeeds because `https://same-origin.com/page` is same-origin
4. A compromised or malicious extension content script triggers navigation to `https://same-origin.com/page` with `should_check_main_world_csp = DO_NOT_CHECK`
5. The prerendered page (which was loaded under the page's CSP) is activated, but the extension's privileged context properties are now associated with the activated page

This is a defense-in-depth concern rather than a direct exploit, as the prerendered page content was already validated against CSP. However, it could interact with other extension permission models in unexpected ways.

## Impact
Low - This is primarily a defense-in-depth issue. The prerendered page was already CSP-validated, so no additional content is loaded. The risk is in the mismatch between what the activation context expected and what was prerendered.

## VRP Value
Low
