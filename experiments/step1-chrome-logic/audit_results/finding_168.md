# Finding 168: Prerender Activation Does Not Re-validate COOP/COEP Compatibility

## Summary
During prerender activation in `PrerenderHost::Activate()`, the prerendered page's `StoredPage` is transferred from the prerender FrameTree to the primary FrameTree without re-validating that the prerendered page's Cross-Origin-Opener-Policy (COOP) and Cross-Origin-Embedder-Policy (COEP) are compatible with the activation context. The `CanNavigationActivateHost()` function in `PrerenderHostRegistry` checks effective URLs, auxiliary browsing contexts, visibility, navigation parameters, and frame policy, but does not include any COOP or COEP compatibility check. A search for "COOP", "COEP", "cross_origin_opener", and "cross_origin_embedder" across `prerender_host.cc` and `prerender_host_registry.cc` reveals zero references (except the unrelated `kProcessReuseOnPrerenderCOOPSwap` feature name).

## Affected Files
- `content/browser/preloading/prerender/prerender_host_registry.cc` (lines 1702-1795) - `CanNavigationActivateHost()` - no COOP/COEP check
- `content/browser/preloading/prerender/prerender_host.cc` (lines 843-989) - `Activate()` - transfers StoredPage without COOP/COEP validation

## Details
```cpp
// prerender_host_registry.cc:1702-1795
bool PrerenderHostRegistry::CanNavigationActivateHost(
    NavigationRequest& navigation_request,
    PrerenderHost& host) {
  // Checks: effective URL, auxiliary browsing contexts, visibility,
  // navigation params, frame policy
  // NO COOP/COEP CHECK
  ...
  return true;
}
```

```cpp
// prerender_host.cc:843-989
std::unique_ptr<StoredPage> PrerenderHost::Activate(
    NavigationRequest& navigation_request) {
  // Transfers StoredPage to primary frame tree
  // NO COOP/COEP re-validation
  std::unique_ptr<StoredPage> page =
      GetFrameTree()->root()->render_manager()->TakePrerenderedPage();
  ...
  return page;
}
```

The prerendered page is fetched in its own browsing context group. When it is activated and transferred to the primary frame tree, the COOP/COEP policies of the prerendered document become the policies of the primary page. If the prerendered page has a COOP policy that would normally cause a browsing context group swap during regular navigation, this swap is handled differently during prerender activation (via `kProcessReuseOnPrerenderCOOPSwap`). However, there is no check to ensure that the activation navigation's expected COOP/COEP state matches what the prerendered page actually has.

This could matter when:
1. The initiating page has a COOP of `same-origin`, but the prerendered page has `unsafe-none`
2. The activation transfers the `unsafe-none` policy into the context that expected `same-origin`
3. Other pages that were in the same COOP group might now have unexpected cross-origin window access

## Attack Scenario
1. Page `https://secure-app.com` has `COOP: same-origin` and prerenders `https://secure-app.com/page2`
2. During the prerender, the response for `/page2` returns with `COOP: unsafe-none` (different from the referring page)
3. In a normal navigation, this would trigger a browsing context group swap
4. During prerender activation, the prerendered page with `COOP: unsafe-none` is activated into the primary frame tree
5. While the browsing context group handling may be correct via the separate process reuse feature, the lack of explicit COOP/COEP validation in the activation path means this relies entirely on the prerender's separate browsing context group semantics being correct
6. If there is any edge case where the BrowsingContextGroup is not properly swapped, the `unsafe-none` COOP page could end up sharing a BCG with `same-origin` COOP pages

## Impact
Low - The prerender creates its own browsing context group which provides some natural isolation. The `kProcessReuseOnPrerenderCOOPSwap` feature handles process reuse, and the existing browsing context group swap during activation may handle COOP correctly at a lower layer. However, the absence of any explicit COOP/COEP check in the prerender activation code path is a defense-in-depth concern.

## VRP Value
Low
