# Finding 093: Extension Storage get() Size Limit Disabled by Default

## Summary

The `kEnforceStorageGetSizeLimit` feature flag is DISABLED by default. Without it, `chrome.storage.local.get()` can return arbitrarily large data blobs in a single IPC call, enabling DoS via browser process memory exhaustion.

## Affected Files

- `extensions/browser/api/storage/storage_api.cc:41` — kEnforceStorageGetSizeLimit DISABLED_BY_DEFAULT
- `extensions/browser/api/storage/storage_api.cc:269-276` — Size check gated behind flag

## Details

```cpp
// storage_api.cc:41
BASE_FEATURE(kEnforceStorageGetSizeLimit, base::FEATURE_DISABLED_BY_DEFAULT);

// storage_api.cc:269-276
if (base::FeatureList::IsEnabled(kEnforceStorageGetSizeLimit) &&
    data_size > kMaxSingleGetSizeBytes) {
  // reject...
}
// When flag disabled: no size limit on get() response
```

## Attack Scenario

1. Malicious extension fills `chrome.storage.local` with large values (up to QUOTA_BYTES)
2. Calls `chrome.storage.local.get(null)` to retrieve everything at once
3. Without the 25 MB limit, hundreds of MBs transferred in single IPC
4. Browser process memory spikes, causing lag or OOM crash

## Impact

- **No compromised renderer required**: Standard extension API
- **DoS**: Browser memory exhaustion
- **Size limit exists but not enforced**: Feature flag disabled

## VRP Value

**Low-Medium** — DoS via resource exhaustion. The limit exists in code but is not enforced.
