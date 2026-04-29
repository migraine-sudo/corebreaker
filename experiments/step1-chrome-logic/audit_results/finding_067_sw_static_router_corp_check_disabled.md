# Finding 067: Service Worker Static Router CORP Check Disabled — Cross-Origin Responses Allowed

## Summary

The Service Worker Static Router's cache source can serve responses that violate Cross-Origin-Resource-Policy (CORP). The CORP enforcement is gated behind `kServiceWorkerStaticRouterCORPCheck` which is DISABLED by default. CORP violations are detected but only logged as metrics — the response is allowed through.

## Affected Files

- `content/common/features.cc:703-704` — `kServiceWorkerStaticRouterCORPCheck` DISABLED_BY_DEFAULT
- `content/common/service_worker/service_worker_resource_loader.cc:97-113` — CORP check bypassed

## Details

```cpp
// service_worker_resource_loader.cc:97-113
bool is_enabled = base::FeatureList::IsEnabled(
    features::kServiceWorkerStaticRouterCORPCheck);
if (network::CrossOriginResourcePolicy::IsBlockedByHeaderValue(...)) {
  if (is_enabled) {
    is_valid = false;             // Block the response
    result = CORPCheckResult::kBlocked;
  } else {
    result = CORPCheckResult::kViolation;  // Log but ALLOW through
  }
}
```

When the flag is disabled (default), a CORP-violating response from the SW static router's cache source is detected but allowed through. The violation is only recorded as a UMA metric.

## Attack Scenario

### Cross-origin data exfiltration via SW cache + static router

1. A page at `https://attacker.example` registers a Service Worker with static routing rules
2. The SW's cache contains a cached response from `https://victim.example` that has `Cross-Origin-Resource-Policy: same-origin`
3. When the page navigates/fetches a resource matching the static router rule, the cached response is served
4. Normally CORP would block this cross-origin response
5. But with `kServiceWorkerStaticRouterCORPCheck` disabled, the CORP violation is detected but the response is allowed through
6. The attacker reads the cross-origin response content

### Interaction with COEP

The CORP check is performed against the client's `cross_origin_embedder_policy`. Pages with `COEP: require-corp` expect all cross-origin responses to pass CORP checks. The SW static router bypass means COEP enforcement is incomplete for cached responses.

## Impact

- **No compromised renderer required**: Standard web platform APIs
- **CORP bypass**: Cross-origin responses served despite CORP headers
- **COEP undermined**: Cross-Origin-Embedder-Policy enforcement is incomplete
- **Spectre mitigation gap**: CORP is a key Spectre mitigation; bypassing it re-exposes cross-origin data

## VRP Value

**Medium-High** — No compromised renderer needed. Bypasses a key Spectre mitigation (CORP). The attack requires specific conditions (SW with static routing rules + cached cross-origin responses) but is achievable with standard web APIs.
