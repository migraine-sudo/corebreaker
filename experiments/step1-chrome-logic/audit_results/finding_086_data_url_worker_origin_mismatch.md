# Finding 086: Data URL Worker Non-Opaque Origin (kDataUrlWorkerOpaqueOrigin Disabled)

## Summary

The `kDataUrlWorkerOpaqueOrigin` feature flag is DISABLED by default. When disabled, data: URL SharedWorkers and DedicatedWorkers do not get an opaque origin. This causes blob URL validity checks to use `ALLOW_OPAQUE_ORIGIN_STORAGE_KEY_MISMATCH`, weakening origin isolation for workers created from data: URLs.

## Affected Files

- `third_party/blink/common/features.cc:481` — `kDataUrlWorkerOpaqueOrigin` DISABLED_BY_DEFAULT
- `content/browser/worker_host/shared_worker_host.cc:772-775` — Blob URL check relaxation
- `content/browser/worker_host/dedicated_worker_host.cc:919-922` — Same pattern

## Details

```cpp
// shared_worker_host.cc:772-775
base::FeatureList::IsEnabled(blink::features::kDataUrlWorkerOpaqueOrigin)
    ? storage::BlobURLValidityCheckBehavior::DEFAULT
    : storage::BlobURLValidityCheckBehavior::
          ALLOW_OPAQUE_ORIGIN_STORAGE_KEY_MISMATCH
// When flag disabled: opaque origin storage key mismatches are ALLOWED
```

Per spec (https://html.spec.whatwg.org/#workers), data: URL workers should have opaque origins. With the flag disabled:
- data: URL workers inherit the parent's non-opaque origin
- Blob URL validation is relaxed to allow storage key mismatches

## Attack Scenario

1. Page creates a SharedWorker from a `data:` URL
2. The worker inherits the page's origin instead of getting an opaque origin
3. Worker can access Blob URLs that should be isolated by origin
4. The relaxed `ALLOW_OPAQUE_ORIGIN_STORAGE_KEY_MISMATCH` allows cross-origin blob URL access

## Impact

- **No compromised renderer required**: Standard worker creation
- **Origin isolation violation**: data: URL workers should be opaque per spec
- **Blob URL access**: Relaxed validation allows accessing blobs across origin boundaries
- **Spec non-compliance**: HTML spec requires opaque origin for data: URL workers

## VRP Value

**Low-Medium** — Spec non-compliance with potential origin isolation implications. The impact depends on how blob URL storage keys are used in cross-origin scenarios.
