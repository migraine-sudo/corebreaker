# Finding 042: StorageAccessHandle ReportBadMessage Gated Behind DCHECK_IS_ON — Renderer Not Killed in Release

## Summary

In `StorageAccessHandle::Create()`, the `mojo::ReportBadMessage()` call that should kill a compromised renderer for requesting storage access without authorization is wrapped in `#if DCHECK_IS_ON()`. In release/official builds, DCHECK_IS_ON is false — the bad message is never reported. The renderer's IPC request is silently dropped, but the renderer process is not terminated and can continue attacking other APIs.

## Affected Files

- `content/browser/storage_access/storage_access_handle.cc:55-61` — DCHECK-gated ReportBadMessage

## Details

```cpp
// storage_access_handle.cc:55-61
if (!host->IsFullCookieAccessAllowed()) {
#if DCHECK_IS_ON()
  mojo::ReportBadMessage(
      "Binding a StorageAccessHandle requires third-party cookie access.");
#endif
  return;
}
```

### Normal behavior (Debug/DCHECK builds)

When a renderer requests a `StorageAccessHandle` binding without having been granted storage access:
1. `IsFullCookieAccessAllowed()` returns false
2. `mojo::ReportBadMessage()` is called
3. The renderer process is terminated for IPC policy violation
4. The compromised renderer can no longer attack other APIs

### Release build behavior

When the same thing happens in a release build:
1. `IsFullCookieAccessAllowed()` returns false
2. The `#if DCHECK_IS_ON()` block is compiled out — `ReportBadMessage` is never called
3. The function returns — the bind request is silently dropped
4. **The renderer process survives** and can continue making malicious IPC calls

### Contrast with proper handling in same codebase

In `StorageAccessGrantPermissionContext::DecidePermission()`, `ReportBadMessage` is called unconditionally:
```cpp
// storage_access_grant_permission_context.cc:327
receiver.ReportBadMessage("...preconditions violated...");
```

This inconsistency confirms the DCHECK guard in `StorageAccessHandle::Create` is likely a bug, not an intentional design choice.

## Attack Scenario

1. A compromised renderer repeatedly sends `StorageAccessHandle` binding requests
2. In release Chrome, each request is silently dropped but the renderer is not killed
3. The compromised renderer can continue attacking other Mojo interfaces
4. This contrasts with the expected behavior: `ReportBadMessage` should terminate the renderer, limiting the blast radius of any renderer compromise

## Impact

- **Compromised renderer tolerance**: The renderer is not terminated for IPC policy violations
- **Defense-in-depth failure**: The purpose of `ReportBadMessage` is to limit the blast radius of a compromised renderer by killing it on the first IPC violation
- **Release-only**: Debug/Canary builds correctly kill the renderer, making this harder to catch in testing

## VRP Value

**Low-Medium** — Requires a compromised renderer to trigger. The direct impact is that the renderer is not terminated, not that storage access is granted. But as a defense-in-depth failure, it allows a compromised renderer to persist longer and attempt more attacks. The inconsistency with other `ReportBadMessage` calls in the same codebase suggests this is unintentional.
