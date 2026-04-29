# Finding 212: Service Worker Origin-Key Consistency Check is DCHECK-Only

## Summary

`CheckOnUpdateUrls()` in `service_worker_security_utils.cc` validates that a service worker's script URL origin matches its StorageKey origin, but this entire check is inside `#if DCHECK_IS_ON()`. In release builds, a mismatch between the script URL and the StorageKey goes completely unvalidated. Additionally, the `top_frame_origin` to `top_level_site` consistency check is not even done in debug builds (it's a TODO).

## Affected Files

- `content/browser/service_worker/service_worker_security_utils.cc:54-77` — Entire check DCHECK-only

## Details

```cpp
// service_worker_security_utils.cc:54-77
void CheckOnUpdateUrls(const GURL& url, const blink::StorageKey& key) {
#if DCHECK_IS_ON()
    const url::Origin origin_to_dcheck = url::Origin::Create(url);
    DCHECK((origin_to_dcheck.opaque() && key.origin().opaque()) ||
           origin_to_dcheck.IsSameOriginWith(key.origin()))
        << origin_to_dcheck << " and " << key.origin() << " should be equal.";
    // TODO(crbug.com/40251360): verify that `top_frame_origin` matches the
    // `top_level_site` of `storage_key`, in most cases.
    // ...
    // Consider adding a DCHECK here once the last of those conditions is
    // resolved.
#endif  // Only checked in debug builds!
}
```

This function is called during service worker script updates to ensure the new script URL is consistent with the worker's StorageKey. In release builds:
1. The origin consistency check is completely skipped
2. The top-frame-origin consistency check isn't implemented at all (even in debug)
3. A compromised renderer could potentially update a service worker with a cross-origin script URL

## Attack Scenario

1. Compromised renderer registers or updates a service worker
2. It provides a script URL from origin A but a StorageKey for origin B
3. In release builds, this mismatch is not caught by `CheckOnUpdateUrls`
4. The service worker might gain access to origin B's storage while running origin A's script
5. Or a cross-origin script could be fetched in the context of a different origin's StorageKey

### Combined with top-frame-origin gap
The TODO at line 60-75 explicitly states the top_frame_origin is NOT verified against the StorageKey's top_level_site. This means:
1. A service worker could be registered with a StorageKey that claims a different top-level site
2. This would affect storage partitioning — the worker could access the wrong partition

## Impact

- **Requires compromised renderer**: Normal renderers can't forge Mojo messages
- **Origin confusion**: URL and StorageKey origin mismatch not caught in release
- **Storage partitioning bypass**: top_frame_origin not verified against top_level_site
- **Defense-in-depth failure**: Fundamental security invariant not enforced

## VRP Value

**Medium** — Origin-to-StorageKey consistency for service workers is only validated in debug builds. While exploiting this requires a compromised renderer, service workers have significant privileges (intercepting all fetches for their scope, persistent background execution) making this a meaningful defense-in-depth gap.
