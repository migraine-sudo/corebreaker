# Finding 068: Service Worker Static Router Allows Opaque Responses Without Blocking

## Summary

When the Service Worker Static Router serves a response from its cache source, it checks whether the response is valid (non-opaque for no-cors requests). However, the blocking is gated behind `kServiceWorkerStaticRouterOpaqueCheck` which is DISABLED by default. Invalid/opaque responses from the static router are allowed through in both the browser (main resource) and renderer (subresource) paths.

## Affected Files

- `content/common/features.cc:709-710` — `kServiceWorkerStaticRouterOpaqueCheck` DISABLED_BY_DEFAULT
- `content/browser/service_worker/service_worker_main_resource_loader.cc:928-933` — Main resource path
- `content/renderer/service_worker/service_worker_subresource_loader.cc:1508-1512` — Subresource path

## Details

### Browser path (main resource)

```cpp
// service_worker_main_resource_loader.cc:928-933
if (!IsValidStaticRouterResponse(...) &&
    base::FeatureList::IsEnabled(
        features::kServiceWorkerStaticRouterOpaqueCheck)) {
  CommitCompleted(net::ERR_FAILED, "Invalid response from static router");
  return;  // DEAD CODE — flag is disabled
}
```

### Renderer path (subresource)

```cpp
// service_worker_subresource_loader.cc:1508-1512
if (!IsValidStaticRouterResponse(...) &&
    base::FeatureList::IsEnabled(
        features::kServiceWorkerStaticRouterOpaqueCheck)) {
  CommitCompleted(net::ERR_FAILED, "Invalid response from static router");
  return;  // DEAD CODE — flag is disabled
}
```

Both paths have the same pattern: validity check is performed but not enforced.

## Attack Scenario

### Opaque response served as main resource

1. A Service Worker registers static routing rules that match navigation requests
2. The SW's cache contains an opaque response (e.g., from a no-cors cross-origin fetch)
3. User navigates to a URL matching the static router rule
4. The opaque response is served as the main resource
5. Opaque responses should not be renderable as main resources (they contain cross-origin data that's supposed to be inaccessible)
6. With the flag disabled, the opaque response is rendered, potentially exposing cross-origin content

## Impact

- **No compromised renderer required**: Standard web APIs
- **Opaque response leakage**: Responses that should be opaque are served as readable content
- **Affects both main resources and subresources**: Double vulnerability in browser and renderer
- **Cross-origin data exposure**: Opaque responses contain cross-origin data that's supposed to be inaccessible to JavaScript

## VRP Value

**Medium-High** — Opaque responses are a key part of the browser's cross-origin security model. Allowing them to be served as readable content via the SW static router is a meaningful bypass. The specific crbug.com/495999481 tracks this issue.
