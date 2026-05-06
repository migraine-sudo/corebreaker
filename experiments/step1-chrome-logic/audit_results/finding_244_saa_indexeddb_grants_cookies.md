# Finding 244: requestStorageAccess({indexedDB: true}) Grants Unpartitioned Cookie Access

## Summary

When a cross-site iframe calls `document.requestStorageAccess({indexedDB: true})` requesting ONLY IndexedDB (not cookies), the browser-side permission grant callback unconditionally calls `SetStorageAccessApiStatus(kAccessViaAPI)`, which adds `kStorageAccessGrantEligible` to the document's cookie setting overrides. If the RestrictedCookieManager is subsequently bound (lazy binding on first `document.cookie` access), it receives this override as a base override, granting unpartitioned cookie access.

## Root Cause

**File:** `chrome/browser/storage_access_api/storage_access_grant_permission_context.cc:280-286`

```cpp
if (permission_result.status == blink::mojom::PermissionStatus::GRANTED) {
  content::RenderFrameHost* rfh = content::RenderFrameHost::FromID(frame_host_id);
  if (rfh) {
    rfh->SetStorageAccessApiStatus(net::StorageAccessApiStatus::kAccessViaAPI);
  }
}
```

This callback fires for ALL SAA permission grants unconditionally — regardless of whether cookies were among the requested storage types.

**Renderer-side is correct (document_storage_access.cc:215-218):**
```cpp
/*request_unpartitioned_cookie_access=*/storage_access_types->all() ||
    storage_access_types->cookies(),
```

And at line 376-378, the renderer only sets the status when cookies were requested:
```cpp
if (request_unpartitioned_cookie_access) {
    GetSupplementable()->dom_window_->SetStorageAccessApiStatus(kAccessViaAPI);
}
```

## Invariant Violation

The `RestrictedCookieManager` constructor at `services/network/restricted_cookie_manager.cc:435-436` has a DCHECK:
```cpp
DCHECK(!cookie_setting_overrides_.Has(
    net::CookieSettingOverride::kStorageAccessGrantEligible));
```

This DCHECK fires in debug builds but is a no-op in release Chrome. In release, the RCM is constructed with the invalid override in its base.

## Impact Chain

1. iframe calls `requestStorageAccess({indexedDB: true})` → granted via FPS or user consent
2. Browser sets `kStorageAccessGrantEligible` on `document_associated_data_->cookie_setting_overrides()`
3. Browser also persists `ContentSettingsType::STORAGE_ACCESS` content setting
4. iframe accesses `document.cookie` → lazy RCM binding
5. `RenderFrameHostImpl::BindRestrictedCookieManager()` passes `GetCookieSettingOverrides()` which now includes the override
6. Network service RCM has `kStorageAccessGrantEligible` as base override
7. Even though renderer passes `kNone` per-call, base override grants eligibility
8. `IsAllowedByStorageAccessGrant()` sees both override AND content setting → allows unpartitioned cookies

## Security Severity

**Medium (Privacy violation)**

- Violates principle of least privilege in the "Beyond Cookies" SAA feature
- Allows cookie access without requesting it
- FPS auto-grant means no user interaction required in some cases
- Enables cross-site tracking via cookies when only storage access was authorized

## References

- `chrome/browser/storage_access_api/storage_access_grant_permission_context.cc:280-286`
- `third_party/blink/renderer/modules/storage_access/document_storage_access.cc:196-233, 355-390`
- `content/browser/renderer_host/render_frame_host_impl.cc:8460-8473, 15105-15109, 19706-19714`
- `services/network/restricted_cookie_manager.cc:396-443, 1186-1207`
- `components/content_settings/core/common/cookie_settings_base.cc:573-601`
