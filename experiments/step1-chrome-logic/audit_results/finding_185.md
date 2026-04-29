# Finding 185: Extension Storage Access Level Check Relies on Renderer-Supplied context_type

## Summary
The `SettingsFunction::IsAccessToStorageAllowed` function checks whether the caller is in a `kPrivilegedExtension` context type when the storage area's access level is set to `kTrustedContexts`. However, `source_context_type()` returns the value from `mojom::RequestParams::context_type` which is renderer-supplied. Combined with Finding 182 (where invalid context types are not treated as bad messages), a content script or other untrusted context could claim to be a `kPrivilegedExtension` context and gain access to storage areas restricted to trusted contexts only.

## Affected Files
- `extensions/browser/api/storage/storage_api.cc` (lines 161-175)
- `extensions/browser/api/storage/storage_utils.cc` (lines 110-140)
- `extensions/browser/extension_function_dispatcher.cc` (lines 298-311, 584)

## Details

In `storage_api.cc`:
```cpp
bool SettingsFunction::IsAccessToStorageAllowed(
    StorageAreaNamespace storage_area) {
  api::storage::AccessLevel access_level = storage_utils::GetAccessLevelForArea(
      extension()->id(), *browser_context(), storage_area);

  if (access_level == api::storage::AccessLevel::kTrustedContexts) {
    // Only a privileged extension context is considered trusted.
    return source_context_type() == mojom::ContextType::kPrivilegedExtension;
  }

  // All contexts are allowed.
  DCHECK_EQ(api::storage::AccessLevel::kTrustedAndUntrustedContexts,
            access_level);
  return true;
}
```

The `source_context_type()` comes from:
```cpp
function->set_source_context_type(context_type);  // dispatcher.cc:584
```

Which is `params->context_type` from the renderer.

The `CanProcessHostContextType` check at line 298 provides some defense, but as noted in Finding 182, it does NOT kill the renderer on failure and the check may have legitimate false negatives. For the storage access check, the defense relies on `CanProcessHostContextType` having already correctly validated that the renderer's claimed context type is accurate.

In the renderer-side validation at `storage_utils.cc:110-140`, the more robust `CanRendererAccessExtensionStorage` function uses `IsPrivilegedExtensionProcess` which checks the process map directly. However, the browser-side `IsAccessToStorageAllowed` in the `SettingsFunction` uses the renderer-supplied `source_context_type()` instead.

## Attack Scenario
1. An extension sets its session storage access level to `kTrustedContexts` to restrict access to only its privileged extension pages (not content scripts).
2. The extension's content script running in a compromised renderer sends a `storage.session.get()` API call.
3. The renderer sets `context_type = kPrivilegedExtension` in the IPC.
4. `CanProcessHostContextType` correctly rejects this (content script process can't host privileged contexts) and returns an error... but does NOT kill the renderer (Finding 182).
5. However, if `CanProcessHostContextType` has a false negative (e.g., during extension load/unload race), the request proceeds.
6. `IsAccessToStorageAllowed` checks `source_context_type() == kPrivilegedExtension`, which is true.
7. The content script gains access to session storage data restricted to trusted contexts.

Note: The renderer-side `CanRendererAccessExtensionStorage` provides an additional check at the Mojo interface level, which makes exploitation harder. But the browser-side check is the authoritative one.

## Impact
Low-Medium. The `CanProcessHostContextType` check provides a first line of defense, and the renderer-side Mojo check provides additional protection. But the use of a renderer-supplied context type for the actual storage access decision is a defense-in-depth weakness, especially given that `CanProcessHostContextType` failures are not treated as bad messages.

## VRP Value
Low
