# Finding 201: Extension Storage Get Size Limit Not Enforced by Default

## Summary
The `kEnforceStorageGetSizeLimit` feature flag is `FEATURE_DISABLED_BY_DEFAULT`, meaning the 25 MB size limit for a single `storage.get()` response is not enforced. Without this limit, an extension can perform a `storage.get()` call that returns arbitrarily large data, which is then serialized and transmitted over IPC. This can be used as a denial-of-service vector against the browser process by causing excessive memory allocation and IPC message sizes.

## Affected Files
- `extensions/browser/api/storage/storage_api.cc` (lines 41, 245, 269-276)

## Details

```cpp
BASE_FEATURE(kEnforceStorageGetSizeLimit, base::FEATURE_DISABLED_BY_DEFAULT);

// ...

constexpr size_t kMaxSingleGetSizeBytes = 25 * 1024 * 1024;

// In StorageStorageAreaGetFunction::OnGetOperationFinished:
if (base::FeatureList::IsEnabled(kEnforceStorageGetSizeLimit) &&
    data_size > kMaxSingleGetSizeBytes) {
  Respond(Error(base::StringPrintf(
      "The total data size of %zu bytes exceeds the maximum limit of %zu "
      "bytes for a single get() operation. Please use getKeys() and "
      "retrieve items in smaller batches.",
      data_size, kMaxSingleGetSizeBytes)));
  return;
}
```

Because the feature is disabled by default:
1. The `storage.get()` response is not size-limited
2. An extension can store large amounts of data (up to the per-area storage quota) and retrieve it all in a single `get()` call
3. The response is serialized as a `base::DictValue`, sent through IPC to the renderer process
4. Large IPC messages can cause memory pressure in both the browser process (serialization) and the renderer process (deserialization)

The `storage.local` area has a quota of `QUOTA_BYTES = 10,485,760` (10 MB) for non-unlimited-storage extensions, and unlimited for extensions with the `unlimitedStorage` permission. This means:
- Without `unlimitedStorage`: Up to ~10 MB per `get()` call
- With `unlimitedStorage`: Unbounded data per `get()` call
- The disabled size limit would have capped this at 25 MB

## Attack Scenario
1. A malicious extension has the `storage` and `unlimitedStorage` permissions.
2. The extension writes many large values to `storage.local` (e.g., 100 MB of data).
3. The extension calls `storage.local.get(null)` to retrieve all data at once.
4. Without the size limit enforcement, the browser process serializes the entire 100 MB+ response.
5. The browser process experiences significant memory pressure during serialization.
6. The IPC message is sent to the renderer, causing memory pressure there too.
7. If repeated rapidly, this can cause the browser to become unresponsive (DoS).

Note: This is a browser-level DoS, not a sandbox escape. However, the `unlimitedStorage` permission is commonly granted to extensions (it's a non-dangerous permission that doesn't require special approval in the Chrome Web Store).

## Impact
Low. This is primarily a denial-of-service vector against the browser process. The disabled feature flag prevents any size enforcement on `storage.get()` responses, but the attack requires a malicious extension to already be installed.

## VRP Value
Low
