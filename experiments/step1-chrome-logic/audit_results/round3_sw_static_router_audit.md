# Service Worker Static Router Opaque Response Audit

## Executive Summary

The `kServiceWorkerStaticRouterOpaqueCheck` feature flag (disabled by default) gates a critical validation that blocks opaque (cross-origin no-cors) responses from being served as navigation responses through the Service Worker static routing API. When this check is disabled (the current default), an opaque response from CacheStorage can be served as a navigation response.

**However, this is NOT a CORS bypass vulnerability exploitable without a compromised renderer.** The attack scenario is limited by a fundamental constraint: the service worker can only control responses for URLs within its scope (same-origin), and the committed page's origin is determined by the navigation URL, not by the response's source origin.

## Detailed Analysis

### 1. Feature Flag Confirmation

**File:** `content/common/features.cc` (lines 706-710)
```cpp
// crbug.com/495999481: When this is enabled, the navigation request should be
// blocked when it receives an opaque response from the service worker static
// router.
BASE_FEATURE(kServiceWorkerStaticRouterOpaqueCheck,
             base::FEATURE_DISABLED_BY_DEFAULT);
```

Also disabled: `kServiceWorkerStaticRouterCORPCheck` (line 703-704) which enforces Cross-Origin-Resource-Policy for cache source responses.

### 2. Validation Logic (when enabled)

**File:** `content/common/service_worker/service_worker_resource_loader.cc` (lines 28-70)

The `IsValidServiceWorkerResponse` function implements Fetch spec 4.4 Step 3.5.6:
- Navigation requests have `RequestMode::kNavigate`
- kNavigate != kNoCors, so an opaque response (FetchResponseType::kOpaque) is INVALID for navigations
- This correctly blocks opaque responses for navigations

### 3. Where the Check is Gated

**Main resource loader** (`service_worker_main_resource_loader.cc`, lines 914-935):
```cpp
if (!IsValidStaticRouterResponse(...) &&
    base::FeatureList::IsEnabled(
        features::kServiceWorkerStaticRouterOpaqueCheck)) {
  CommitCompleted(net::ERR_FAILED, "Invalid response from static router");
  return;
}
```

**Subresource loader** (`service_worker_subresource_loader.cc`, lines 1499-1513):
Same pattern - validation result computed but only enforced when flag is enabled.

When the flag is disabled (default), the response is served regardless of validation result.

### 4. Attack Scenario Analysis

**Can an attacker store a cross-origin opaque response in CacheStorage?**
YES. A service worker can `fetch('https://victim.com/secret', {mode: 'no-cors'})` which returns an opaque response, and store it via `cache.put()`. The body is stored in CacheStorage (it exists on disk), but JavaScript cannot read it through normal APIs.

**Can the static router serve it as a navigation response?**
YES, when `kServiceWorkerStaticRouterOpaqueCheck` is disabled (default). The service worker can register:
```js
event.addRoutes([{
  condition: { urlPattern: "/steal" },
  source: { cacheName: "my-cache" }  // contains opaque response
}]);
```

The `ServiceWorkerCacheStorageMatcher` calls `remote_->Match()` and returns the full response including body. No response-type filtering is applied to the body.

**What origin does the navigated page get?**
The navigated page gets `url::Origin::Create(GetURL())` - i.e., the origin of the navigation URL (within the attacker's SW scope), NOT the origin of the cross-origin resource.

### 5. Security Impact Assessment

**What actually happens:**
1. Attacker registers SW at `https://attacker.com/sw.js` with scope `https://attacker.com/`
2. SW fetches `https://victim.com/secret.html` with `mode: 'no-cors'` -> gets opaque response
3. SW stores opaque response in CacheStorage keyed to `https://attacker.com/steal`
4. SW registers static route: condition `"/steal"` -> source `cache`
5. User navigates to `https://attacker.com/steal`
6. Static router retrieves the opaque response from cache
7. Browser commits the response body as `https://attacker.com/steal`

**The page is rendered with the body of `victim.com/secret.html` but under `attacker.com` origin.**

This means:
- The attacker's JavaScript (from a different script on the page, or injected via `<script>` in the cached response) can read `document.body.innerHTML` of the cross-origin content
- Cookies for victim.com are NOT sent (the request to cache was no-cors)
- The page runs under attacker.com origin, so it has access to attacker.com cookies/storage

### 6. Practical Exploitability

**Severity: MEDIUM (not a full CORS bypass)**

The attack is limited by:
1. **No victim cookies sent**: The original fetch was `no-cors`, so victim's cookies were not included. The cached response contains only the PUBLIC content of the cross-origin page (what anyone could see without auth).
2. **Static content only**: The opaque response body is whatever was returned at fetch time. It cannot be used to steal authenticated content.
3. **Service worker scope**: The attacker can only control their own origin's service worker.

**Where it IS dangerous:**
- Pages that serve sensitive content based on IP address, VPN, or network location (not cookies)
- Internal network resources accessible from the browser but not the internet
- Resources behind IP-based access controls
- Resources with CORS restrictions meant to prevent embedding (but which are accessible without auth)

### 7. The CORP Check Gap

Additionally, `kServiceWorkerStaticRouterCORPCheck` is also disabled by default. This means even responses with `Cross-Origin-Resource-Policy: same-origin` headers can be served through the static router cache source without being blocked.

With COEP (Cross-Origin-Embedder-Policy) deployments increasing, this creates a mismatch: a site deploying COEP expects opaque cross-origin resources to be blocked, but the SW static router bypasses this check.

### 8. Comparison: Fetch Handler vs Static Router

Through the normal fetch handler path, a service worker CAN also serve opaque responses for navigations using `respondWith()`. In `DidDispatchFetchEvent()`, the only validation for the response is `status_code == 0` (network error). There is NO call to `IsValidServiceWorkerResponse` for the fetch handler path for main resource responses. This means the static router is not uniquely vulnerable -- the fetch handler has always permitted this behavior.

However, the static router introduces a qualitative difference:
- **Fetch handler path**: Requires active JS execution (`event.respondWith(opaqueResponse)`). Auditable. Intentional action by the SW author.
- **Static router path**: Automated. Registered declaratively during install. No JS runs during the response serving. The SW author may not realize the security implications of routing to a cache that contains opaque responses.

The `kServiceWorkerStaticRouterOpaqueCheck` flag was added specifically because the Chromium team recognized this gap (crbug.com/495999481), but it remains disabled, likely pending performance/compatibility evaluation.

### 8b. Cache Key Attack Vector

For the cache source attack to work, the attacker must store the opaque response keyed by the NAVIGATION URL:
```js
// In service worker install event:
const opaqueResponse = await fetch('https://victim.com/secret', {mode: 'no-cors'});
const cache = await caches.open('my-cache');
await cache.put('/steal', opaqueResponse);  // Key is attacker's URL path

// Register route:
event.addRoutes([{
  condition: { urlPattern: "/steal" },
  source: "cache"  // or { cacheName: "my-cache" }
}]);
```

This is valid because `cache.put()` accepts any Request/URL as the key regardless of the response type. The `ServiceWorkerCacheStorageMatcher` uses `blink::mojom::FetchAPIRequest::From(resource_request_)` which contains the navigation URL, matching against this stored entry.

### 9. Verdict

**This is a known but unpatched spec compliance gap, not a novel vulnerability.**

The Chromium team is aware (tracked at crbug.com/495999481) and the fix exists behind a feature flag. The security impact is real but limited:
- NOT a full CORS bypass (no victim credentials)
- CAN leak content of cross-origin pages accessible without authentication
- CAN bypass CORP headers protecting resources
- CAN be used for information disclosure of network-local resources

**Recommendation:** This should be escalated as a defense-in-depth issue. The flag should be enabled by default, as there is no legitimate use case for serving opaque responses as navigation responses through the static router.

## Files Analyzed

- `content/common/features.cc` (feature flag definition)
- `content/common/features.h` (feature flag declaration)
- `content/common/service_worker/service_worker_resource_loader.cc` (validation logic)
- `content/common/service_worker/service_worker_resource_loader.h` (interface)
- `content/browser/service_worker/service_worker_main_resource_loader.cc` (main resource flow)
- `content/renderer/service_worker/service_worker_subresource_loader.cc` (subresource flow)
- `content/browser/service_worker/service_worker_cache_storage_matcher.cc` (cache source)
- `content/common/service_worker/service_worker_router_evaluator.cc` (route evaluation)
- `services/network/public/mojom/fetch_api.mojom` (request mode/response type enums)
- `third_party/blink/renderer/modules/service_worker/install_event.cc` (route registration)
- `third_party/blink/renderer/modules/service_worker/service_worker_router_type_converter.cc` (source types)
- `third_party/blink/common/service_worker/service_worker_loader_helpers.cc` (response info)
- `content/browser/renderer_host/navigation_request.cc` (origin determination)
- `content/browser/cache_storage/cache_storage_cache.cc` (opaque response storage)
