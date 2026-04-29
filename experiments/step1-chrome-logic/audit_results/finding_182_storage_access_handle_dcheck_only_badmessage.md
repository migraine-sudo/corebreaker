# Finding 182: StorageAccessHandle Bad Message Only Reported in DCHECK Builds

## Summary

When a renderer attempts to bind a `StorageAccessHandle` without having third-party cookie access (potentially a compromised renderer trying to access unpartitioned storage), the bad_message report that should terminate the renderer is guarded by `DCHECK_IS_ON()`. In release builds, the binding is rejected but the renderer is NOT terminated.

## Affected Files

- `content/browser/storage_access/storage_access_handle.cc:56-59` — DCHECK-only bad message

## Details

```cpp
// storage_access_handle.cc:51-63
void StorageAccessHandle::Create(
    RenderFrameHost* host,
    mojo::PendingReceiver<blink::mojom::StorageAccessHandle> receiver) {
  CHECK(host);
  if (!host->IsFullCookieAccessAllowed()) {
#if DCHECK_IS_ON()
    mojo::ReportBadMessage(
        "Binding a StorageAccessHandle requires third-party cookie access.");
#endif
    return;
  }
  new StorageAccessHandle(*host, std::move(receiver));
}
```

In release builds:
1. The check `IsFullCookieAccessAllowed()` correctly prevents binding
2. BUT the renderer is not reported as sending a bad message
3. The renderer can continue running and potentially make more unauthorized requests
4. The `return` drops the receiver, causing a pipe disconnect — but the renderer can retry

A compromised renderer could repeatedly attempt to bind StorageAccessHandle, probing for timing side-channels or racing against permission grants.

## Attack Scenario

1. Compromised renderer in a third-party iframe repeatedly calls Mojo to create StorageAccessHandle
2. In release builds, each attempt silently fails (no badmessage kill)
3. The renderer probes timing of `IsFullCookieAccessAllowed()` changes
4. When legitimate Storage Access is granted to another frame in the same site, the compromised renderer detects it via timing
5. Alternatively, the renderer races: if it sends the bind request just as a legitimate permission grant occurs, it might succeed

## Impact

- **Requires compromised renderer**: Must forge Mojo messages
- **Defense-in-depth failure**: Browser should terminate misbehaving renderers
- **Timing side-channel**: Can probe storage access permission state
- **Not critical**: The `return` still prevents actual binding in release

## VRP Value

**Low-Medium** — Defense-in-depth issue requiring compromised renderer. The bad_message in DCHECK-only builds prevents renderer termination in production. The Storage Access API grants access to powerful unpartitioned storage (IndexedDB, Cache, FileSystem), making the gate important.
