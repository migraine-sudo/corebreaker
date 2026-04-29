# Finding 066: Data URL Workers Have Non-Opaque Origins (kDataUrlWorkerOpaqueOrigin Disabled)

## Summary

Per the web platform spec, workers created from `data:` URLs should have opaque origins. However, the `kDataUrlWorkerOpaqueOrigin` feature flag is DISABLED by default, meaning data: URL workers inherit their creator's origin (non-opaque). This also weakens blob URL validation by allowing storage key mismatches for these workers.

## Affected Files

- `third_party/blink/common/features.cc:481` — `kDataUrlWorkerOpaqueOrigin` DISABLED_BY_DEFAULT
- `content/browser/worker_host/dedicated_worker_host.cc:919-922` — Blob URL validation weakened
- `content/browser/worker_host/shared_worker_host.cc:772-775` — Same weakening for shared workers

## Details

```cpp
// features.cc:481
BASE_FEATURE(kDataUrlWorkerOpaqueOrigin, base::FEATURE_DISABLED_BY_DEFAULT);

// dedicated_worker_host.cc:919-922
base::FeatureList::IsEnabled(blink::features::kDataUrlWorkerOpaqueOrigin)
    ? storage::BlobURLValidityCheckBehavior::DEFAULT
    : storage::BlobURLValidityCheckBehavior::
          ALLOW_OPAQUE_ORIGIN_STORAGE_KEY_MISMATCH);
```

When the flag is disabled (default):
1. Data URL workers get their creator's origin instead of an opaque origin
2. Blob URL validity checks allow storage key mismatches (`ALLOW_OPAQUE_ORIGIN_STORAGE_KEY_MISMATCH`)

## Attack Scenario

### Cross-origin storage access via data URL worker

1. `https://example.com` creates a worker from `data:application/javascript,...`
2. Per spec, this worker should have an opaque origin with no storage access
3. With the flag disabled, the worker inherits `https://example.com`'s origin
4. The worker can access the same storage (cookies, localStorage, IndexedDB) as the creator
5. The weakened blob URL validation allows the worker to resolve blob URLs with mismatched storage keys
6. This could be used to access blob URLs from a different storage partition

### Blob URL cross-partition access

1. Site A creates a blob URL in one storage partition
2. A data URL worker (with non-opaque origin due to disabled flag) in a different partition resolves the blob URL
3. The `ALLOW_OPAQUE_ORIGIN_STORAGE_KEY_MISMATCH` check allows this cross-partition access
4. The worker reads the blob data from the wrong partition

## Impact

- **No compromised renderer required**: Standard web API usage
- **Spec violation**: Data URL workers should have opaque origins
- **Cross-partition blob access**: Weakened validation may allow blob URL resolution across storage partitions
- **Both dedicated and shared workers affected**: Same pattern in both worker types

## VRP Value

**Medium** — Spec deviation that weakens origin isolation for data URL workers. The practical exploitation depends on whether blob URL cross-partition access is actually achievable through the weakened check.
