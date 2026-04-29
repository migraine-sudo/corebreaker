# Finding 166: Data URL Workers Don't Use Opaque Origins (kDataUrlWorkerOpaqueOrigin Disabled)

## Summary

The `kDataUrlWorkerOpaqueOrigin` feature is DISABLED by default. When disabled, data: URL workers inherit their parent's origin rather than receiving an opaque origin. Additionally, blob URL validation allows opaque origin/storage key mismatches. This means data: URL workers can access same-origin resources and blob URLs from their parent context, which violates the principle that data: URLs should be treated as unique origins.

## Affected Files

- `third_party/blink/common/features.cc:481` — Feature DISABLED_BY_DEFAULT
- `content/browser/worker_host/dedicated_worker_host.cc:919-922` — Blob URL mismatch allowed when disabled
- `content/browser/worker_host/shared_worker_host.cc:772` — Same pattern for shared workers
- `content/public/browser/content_browser_client.cc:541` — ContentBrowserClient integration

## Details

```cpp
// features.cc:481
BASE_FEATURE(kDataUrlWorkerOpaqueOrigin, base::FEATURE_DISABLED_BY_DEFAULT);

// dedicated_worker_host.cc:919-922
base::FeatureList::IsEnabled(blink::features::kDataUrlWorkerOpaqueOrigin)
    ? storage::BlobURLValidityCheckBehavior::DEFAULT
    : storage::BlobURLValidityCheckBehavior::
          ALLOW_OPAQUE_ORIGIN_STORAGE_KEY_MISMATCH;
```

When the flag is disabled (current default):
- Data: URL workers inherit the creating page's origin
- Blob URL validity checks allow storage key mismatches for opaque origins
- The worker can access same-origin resources (IndexedDB, Cache API, etc.) as its parent

When the flag is enabled:
- Data: URL workers receive opaque origins
- Blob URL validity checks enforce strict storage key matching
- The worker is properly isolated from same-origin resources

## Attack Scenario

1. Page at `https://example.com` creates a dedicated worker with `new Worker("data:text/javascript,...")`
2. The data: URL worker inherits `https://example.com` as its origin instead of getting an opaque origin
3. Inside the worker, scripts can access IndexedDB, Cache API, and other storage for `https://example.com`
4. If the data: URL was constructed from user-controlled content, this allows XSS-like access to storage

### Blob URL Exfiltration

1. Page creates a blob URL: `URL.createObjectURL(new Blob([secret_data]))`
2. A data: URL worker can access this blob URL even with storage key mismatches
3. The mismatch allowance means blob URLs leak across contexts where they shouldn't

## Impact

- **No compromised renderer required**: Standard web API usage
- **Origin confusion**: Data: URL workers treated as same-origin with parent
- **Storage access**: Workers can access parent's IndexedDB, caches
- **Spec violation**: Data: URLs should have unique/opaque origins per spec

## VRP Value

**Medium** — The spec says data: URLs should have opaque origins. Chrome not enforcing this for workers creates a gap where data: URL workers have more privileges than they should. This is a known spec compliance gap being addressed by the feature flag.
