# Finding 032: SharedStorageWorkletHost Bypasses Blob URL Partitioning Checks

## Summary

`SharedStorageWorkletHost::AddModuleOnWorklet()` calls `BlobUrlRegistry::GetBlobFromUrl()` directly, bypassing all cross-partition blob URL fetch checks implemented in `BlobURLStoreImpl`. A renderer can call `sharedStorage.worklet.addModule('blob:<first-party-origin>/<uuid>')` to load a blob URL from a different storage partition, defeating `kBlockCrossPartitionBlobUrlFetching`.

## Affected Files

- `content/browser/shared_storage/shared_storage_worklet_host.cc:400-409` — Direct `GetBlobFromUrl()` call without partitioning checks
- `storage/browser/blob/blob_url_store_impl.cc:201-238` — `ResolveAsBlobURLToken()` has partitioning checks that are bypassed
- `storage/browser/blob/blob_url_registry.cc:187-199` — `GetBlobFromUrl()` returns blob for any caller regardless of origin

## Details

### The bypass (shared_storage_worklet_host.cc:400-409)

```cpp
if (script_source_url.SchemeIsBlob()) {
    storage::BlobURLLoaderFactory::Create(
        static_cast<StoragePartitionImpl*>(
            document_service_->render_frame_host()
                .GetProcess()
                ->GetStoragePartition())
            ->GetBlobUrlRegistry()
            ->GetBlobFromUrl(script_source_url),  // NO partitioning check
        script_source_url,
        frame_url_loader_factory.InitWithNewPipeAndPassReceiver());
}
```

`GetBlobFromUrl()` looks up the blob URL in the registry and returns the blob to any caller, regardless of their StorageKey. This contrasts with the normal `BlobURLStoreImpl::ResolveAsBlobURLToken()` path which enforces partitioning:

### Normal path with checks (blob_url_store_impl.cc:201-238)

```cpp
void BlobURLStoreImpl::ResolveAsBlobURLToken(
    const GURL& url, ..., bool is_top_level_navigation) {
  if (!is_top_level_navigation) {
    const BlobUrlRegistry::MappingStatus mapping_status =
        registry_->IsUrlMapped(url, storage_key_);
    // Cross-partition checks enforced here
    if (mapping_status == BlobUrlRegistry::MappingStatus::kDifferentStorageKey) {
      if (base::FeatureList::IsEnabled(kBlockCrossPartitionBlobUrlFetching)) {
        // BLOCKED
      }
    }
  }
}
```

The SharedStorageWorkletHost completely skips this check infrastructure.

## Attack Scenario

1. First-party page (`example.com`) creates a blob URL containing sensitive data:
   ```javascript
   const blob = new Blob(['secret data'], {type: 'application/javascript'});
   const blobUrl = URL.createObjectURL(blob);
   // blobUrl = "blob:https://example.com/abc-123-..."
   ```

2. A third-party iframe (`evil.com`) embedded on `example.com` learns the blob URL (via timing side-channel, shared origin, or explicit postMessage)

3. The third-party iframe calls:
   ```javascript
   await sharedStorage.worklet.addModule(blobUrl);
   ```

4. `SharedStorageWorkletHost` calls `GetBlobFromUrl(blobUrl)` directly — no StorageKey/partition check. The blob is loaded into the worklet, even though it belongs to a different partition.

5. The worklet module now executes the blob's content in the shared storage worklet context.

## Impact

- **No compromised renderer needed**: Standard JavaScript API usage
- **Cross-partition data access**: Blob URL partitioning (kBlockCrossPartitionBlobUrlFetching) bypassed
- **Requires**: Knowledge of the blob URL (unguessable UUID)
- **Privacy Sandbox impact**: SharedStorage worklets have privacy-sensitive data access

## VRP Value

**Medium** — The blob URL unguessability provides a defense layer, but the architectural bypass of partitioning checks is a defense-in-depth failure. This is particularly concerning because:
1. SharedStorage worklets interact with Privacy Sandbox data
2. `kBlockCrossPartitionBlobUrlFetching` was specifically added to prevent cross-partition blob access
3. The fix is straightforward: validate StorageKey before calling `GetBlobFromUrl()`
