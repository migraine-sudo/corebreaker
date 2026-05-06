# Round 3: Storage Access API (SAA) Partitioning Audit

## Audit Scope

Reviewed the Storage Access API implementation across browser, network service,
and renderer for logic bugs exploitable without a compromised renderer, on
Chrome stable with default flags. Focused on grant scope expansion, BFCache
interaction, popup heuristic abuse, `requestStorageAccessFor` TOCTOU, and
Service Worker cookie leakage.

## Key Files Reviewed

- `chrome/browser/storage_access_api/storage_access_grant_permission_context.cc`
- `chrome/browser/top_level_storage_access_api/top_level_storage_access_permission_context.cc`
- `content/browser/storage_access/storage_access_handle.cc`
- `content/browser/storage_access/storage_access_handle.h`
- `third_party/blink/renderer/modules/storage_access/document_storage_access.cc`
- `third_party/blink/renderer/modules/storage_access/global_storage_access_handle.cc`
- `services/network/restricted_cookie_manager.cc`
- `services/network/cookie_settings.cc`
- `services/network/url_loader.cc`
- `services/network/url_loader_util.cc`
- `components/content_settings/core/common/cookie_settings_base.cc`
- `net/cookies/cookie_util.cc`
- `content/browser/renderer_host/render_frame_host_impl.cc`
- `content/browser/renderer_host/back_forward_cache_impl.cc`
- `content/browser/renderer_host/navigation_request.cc`
- `content/browser/renderer_host/document_associated_data.h`
- `content/browser/worker_host/shared_worker_service_impl.cc`
- `content/browser/worker_host/shared_worker_connector_impl.cc`

---

## Finding SAA-01: StorageAccessHandle Persists After Grant Revocation

**Severity: Medium**
**Confidence: High**
**Type: Logic Bug / Authorization Bypass**
**Requires: No compromised renderer**

### Description

When a third-party iframe successfully calls `document.requestStorageAccess()`
with a `StorageAccessTypes` parameter, the browser creates a
`content::StorageAccessHandle` (a `DocumentService`) that provides Mojo
bindings for unpartitioned IndexedDB, Locks, CacheStorage, BlobStorage,
BroadcastChannel, SharedWorker, and OPFS.

The access check in `StorageAccessHandle::Create()` at
`content/browser/storage_access/storage_access_handle.cc:55` is:

```cpp
if (!host->IsFullCookieAccessAllowed()) {
#if DCHECK_IS_ON()
    mojo::ReportBadMessage(
        "Binding a StorageAccessHandle requires third-party cookie access.");
#endif
    return;
}
```

This check happens **only once** at handle creation time. After the handle is
bound, the underlying Mojo services (IndexedDB, Locks, CacheStorage, etc.) are
connected to first-party `StorageKey` variants via
`blink::StorageKey::CreateFirstParty(origin)`. These bound services remain
active for the document lifetime.

If the SAA grant is revoked after the handle is created (e.g., the user clears
site data or the grant expires), the `StorageAccessHandle` and all its bound
sub-services continue to function with unpartitioned access. There is no
subscription to permission changes and no mechanism to invalidate the handle.

The `StorageAccessHandle` binds:
- **IndexedDB** (unpartitioned via first-party key)
- **Lock Manager** (unpartitioned)
- **CacheStorage** (unpartitioned)
- **OPFS** (unpartitioned via `GetSandboxedFileSystem`)
- **BlobURLStore** (first-party key)
- **BroadcastChannel** (first-party key, enabling cross-context communication)
- **SharedWorker** (first-party key via `SharedWorkerConnectorImpl`)

### Impact

After grant revocation, the iframe retains full unpartitioned storage access
for the remainder of the document's lifetime. For long-lived pages (e.g.,
webmail clients), this window could last hours.

### Reproduction Scenario

1. Site A embeds iframe from Site B
2. Iframe calls `document.requestStorageAccess({indexedDB: true, cookies: true})`
3. User grants permission -> `StorageAccessHandle` created
4. User navigates to Site B in a new tab and clears data / revokes permission
5. Back to the original tab: iframe's `StorageAccessHandle.indexedDB` still
   provides unpartitioned IDB access

### Mitigation Note

The `DCHECK_IS_ON()` guard around the bad message report at line 56-59 means
in release builds, even the initial check failure is silent (no
`ReportBadMessage`). However, the `return` still prevents binding. The concern
here is about the lack of ongoing re-validation after initial binding.

---

## Finding SAA-02: BFCache Allows Pages With SAA Grants to be Cached

**Severity: Medium**
**Confidence: High**
**Type: Logic Bug / State Confusion**
**Requires: No compromised renderer**

### Description

The `kRequestedStorageAccessGrant` tracked feature is explicitly listed in the
`GetAllowedWebSchedulerTrackedFeatures()` set at
`content/browser/renderer_host/back_forward_cache_impl.cc:242`:

```cpp
WebSchedulerTrackedFeatures GetAllowedWebSchedulerTrackedFeatures() {
    return {
        // ...
        WebSchedulerTrackedFeature::kRequestedStorageAccessGrant,
        // ...
    };
}
```

This means pages with active SAA grants **are allowed to enter BFCache**.

The SAA grant state is stored per-document in
`DocumentAssociatedData::cookie_setting_overrides_` (specifically the
`kStorageAccessGrantEligible` bit). When a page enters BFCache, this state is
preserved. When the page is restored from BFCache, the grant state is
transparently restored with no re-validation.

The issue is: while the page is in BFCache, the underlying
`STORAGE_ACCESS` content setting (the permission grant) may have changed:
- The user could have revoked the grant in settings
- The grant could have expired (grants have configurable lifetimes:
  `kStorageAccessAPIExplicitPermissionLifetime`,
  `kStorageAccessAPIImplicitPermissionLifetime`,
  `kStorageAccessAPIRelatedWebsiteSetsLifetime`)
- The content settings could have been cleared via "Clear browsing data"

Upon BFCache restoration, the `cookie_setting_overrides_` still contain
`kStorageAccessGrantEligible`, so the `RestrictedCookieManager` in the network
service will receive this override. When the network service checks via
`CookieSettingsBase::IsAllowedByStorageAccessGrant()`, it verifies the
`kStorageAccessGrantEligible` override AND checks the `STORAGE_ACCESS`
content setting. If the content setting was cleared, the cookie access would
actually be denied at the network layer. However:

1. The `StorageAccessHandle` (if bound before BFCache) has already-bound
   unpartitioned storage services that do NOT go through the network service's
   cookie settings check (IndexedDB, Locks, CacheStorage are direct bindings
   to first-party storage keys)
2. The renderer-side `document.cookie` path goes through the `CookieJar` which
   is invalidated on grant changes, but BFCached pages don't receive content
   setting change notifications

### Impact

After BFCache restoration, an iframe may retain unpartitioned access to
IndexedDB, CacheStorage, Locks, OPFS, BroadcastChannel, and SharedWorker
even if the SAA grant was revoked while in cache. Cookie access (via
document.cookie or fetch) is more likely to be correctly gated since it goes
through the network service's content settings check.

### Note

There are no browsertests for the SAA+BFCache interaction (confirmed by
searching for "BFCache" in the `chrome/browser/storage_access_api/` and
`content/browser/storage_access/` directories), suggesting this interaction
may be under-tested.

---

## Finding SAA-03: requestStorageAccessFor Only Gated by Related Website Sets

**Severity: Low**
**Confidence: High**
**Type: Design Observation**
**Requires: No compromised renderer**

### Description

`document.requestStorageAccessFor(origin)` (`requestStorageAccessFor` / rSAFor)
in `TopLevelStorageAccessPermissionContext::CheckForAutoGrantOrAutoDenial()` at
`chrome/browser/top_level_storage_access_api/top_level_storage_access_permission_context.cc:117-156`
has the following logic:

1. If the requesting site and target origin are in the same Related Website Set
   (RWS) -> auto-grant (unless the target is a service domain or cookies are
   explicitly blocked)
2. If NOT in the same RWS -> auto-deny with
   `kDeniedByFirstPartySet`

There is **no user prompt path** for `requestStorageAccessFor`. It is strictly
RWS-gated. This is by design per the specification, but it means:

- Any site in a Related Website Set can silently grant unpartitioned cookie
  access for any other site in the same set to all cross-origin subframes
  matching that origin
- The `NotifyPermissionSet` handler at line 189 confirms: it only calls
  `NotifyPermissionSetInternal` with either `kGrantedByFirstPartySet` or
  `kDeniedByFirstPartySet`

The permission grant pattern used is:
```
requesting_origin: the target origin (the iframe's origin)
embedding_origin: the top-level page's origin
```

The grant is persisted to both `TOP_LEVEL_STORAGE_ACCESS` and
`STORAGE_ACCESS` content settings at lines 247-258, using a
`FromURLToSchemefulSitePattern` for the secondary pattern. This means the
grant applies to the entire schemeful site of the embedder, not just the
specific origin.

### Risk

If a site is added to a Related Website Set controlled by an entity that also
controls other sites in the set, those other sites can silently enable
unpartitioned cookie access for the first site's iframes without any user
interaction beyond the initial page load (a user gesture is still required for
the `requestStorageAccessFor` call itself).

---

## Finding SAA-04: Default Storage Partition Limitation in Grant Propagation

**Severity: Low**
**Confidence: High**
**Type: Logic Bug / Inconsistency**
**Requires: No compromised renderer (enterprise/extension contexts)**

### Description

Both `StorageAccessGrantPermissionContext::NotifyPermissionSetInternal()` and
`TopLevelStorageAccessPermissionContext::NotifyPermissionSetInternal()` push
content settings to the network service via:

```cpp
browser_context()
    ->GetDefaultStoragePartition()
    ->GetCookieManagerForBrowserProcess()
    ->SetContentSettings(...)
```

This only updates the **default** storage partition. If a context uses a
non-default storage partition (e.g., Chrome Apps, extensions with isolated
storage, or certain enterprise configurations), the SAA content settings will
not be propagated to that partition's cookie manager.

The code at `storage_access_grant_permission_context.cc:759-768` and
`top_level_storage_access_permission_context.cc:278-289` both exclusively use
`GetDefaultStoragePartition()`.

### Impact

In contexts using non-default storage partitions, SAA grants would not take
effect for network requests routed through those partitions. This is primarily
an inconsistency rather than a security bypass, but could lead to confusing
behavior in extension or enterprise contexts.

---

## Finding SAA-05: SAA Grant Scope via Content Settings Pattern is Site-level

**Severity: Low-Medium (by design, but carries risk)**
**Confidence: High**
**Type: Design Observation / Potential Scope Expansion**
**Requires: No compromised renderer**

### Description

When an SAA grant is persisted in
`StorageAccessGrantPermissionContext::NotifyPermissionSetInternal()` at line
738-741:

```cpp
settings_map->SetContentSettingDefaultScope(
    request_data.requesting_origin, request_data.embedding_origin,
    ContentSettingsType::STORAGE_ACCESS, content_setting,
    ComputeConstraints(outcome, settings_map->Now()));
```

`SetContentSettingDefaultScope` uses
`ContentSettingsPattern::FromURLNoWildcard()` for the primary pattern (the
embedded origin) and `ContentSettingsPattern::FromURLToSchemefulSitePattern()`
for the secondary pattern (the top-level embedder).

For `requestStorageAccessFor()` the pattern is even broader at
`top_level_storage_access_permission_context.cc:254-258`:

```cpp
settings_map->SetContentSettingCustomScope(
    ContentSettingsPattern::FromURLNoWildcard(request_data.requesting_origin),
    ContentSettingsPattern::FromURLToSchemefulSitePattern(
        request_data.embedding_origin),
    ContentSettingsType::STORAGE_ACCESS, CONTENT_SETTING_ALLOW, constraints);
```

The secondary pattern uses `FromURLToSchemefulSitePattern` which means the
grant applies when embedded under any origin within the same schemeful site as
the original embedder. For example, if `app.example.com` is the embedder and
gets a grant for `tracker.com`, then `blog.example.com` embedding the same
`tracker.com` iframe would also match the grant.

### Mitigation

The sibling iframe protection in `ShouldAddInitialStorageAccessApiOverride()`
at `net/cookies/cookie_util.cc:1192-1198` correctly requires that
`request_initiator.IsSameOriginWith(url)` for the
`kStorageAccessGrantEligible` override to be applied. This means a cross-origin
sibling iframe cannot piggyback on another iframe's SAA grant at the network
request level.

However, the content settings grant itself (checked via `GetContentSetting`)
is site-scoped on the secondary pattern, which means the grant is available if
the override is present.

---

## Finding SAA-06: Redirect Strips SAA Override Correctly

**Severity: Not a bug**
**Confidence: High**

Cross-origin redirects correctly strip the `kStorageAccessGrantEligible` and
`kStorageAccessGrantEligibleViaHeader` overrides at
`services/network/url_loader.cc:1034-1038`. This prevents SAA grants from
following cross-origin redirects. The check at
`net/cookie_util.cc:1196-1197` also requires same-origin between request
initiator and URL.

---

## Finding SAA-07: FedCM Auto-Grant Bypasses User Gesture Requirement

**Severity: Low**
**Confidence: High**
**Type: Design Observation**
**Requires: Previous FedCM interaction**

### Description

In `StorageAccessGrantPermissionContext::DecidePermission()` at line 426-438,
the FedCM auto-grant path (`IsAutograntViaFedCmAllowed`) is checked BEFORE the
user gesture requirement at line 440. If FedCM conditions are met (the
`identity-credentials-get` permissions policy is enabled, there's a
`HasSharingPermission` for the site pair, and auto-reauthn is not mediated),
the SAA request resolves successfully without requiring a user gesture.

```cpp
// FedCM check runs BEFORE user gesture check
if (FederatedIdentityPermissionContext* fedcm_context =
        IsAutograntViaFedCmAllowed(...); fedcm_context) {
    // Grants without user gesture!
    return;
}
// User gesture check happens AFTER
if (!request_data->user_gesture || !rfh->HasTransientUserActivation()) {
    // Denied
}
```

This means an iframe that has previously completed a FedCM flow can
subsequently call `requestStorageAccess()` programmatically (without user
interaction) and receive unpartitioned cookie access.

### Impact

A third-party iframe that has previously completed a FedCM sign-in flow can
silently obtain SAA grants without user gesture. This is arguably by design
(the FedCM interaction serves as the trust signal), but could be unexpected if
the FedCM flow was completed long ago and the user doesn't expect the third
party to still have this capability.

---

## Finding SAA-08: SharedWorker via StorageAccessHandle Gets Full Unpartitioned Access

**Severity: Medium**
**Confidence: High**
**Type: Logic Bug / Scope Expansion**
**Requires: No compromised renderer**

### Description

When a third-party iframe with an SAA grant creates a SharedWorker through the
`StorageAccessHandle`, the worker receives a first-party `StorageKey` via the
`storage_key_override` mechanism:

1. `StorageAccessHandle::BindSharedWorker()` at
   `content/browser/storage_access/storage_access_handle.cc:214-221` creates
   a `SharedWorkerConnectorImpl` with
   `blink::StorageKey::CreateFirstParty(origin)`

2. In `SharedWorkerServiceImpl::ConnectToWorker()` at
   `content/browser/worker_host/shared_worker_service_impl.cc:162-166`, when
   `storage_key_override` is present, it's used as the worker's storage key

3. The worker gets `StorageAccessApiStatus::kAccessViaAPI` at lines 462-465:
   ```cpp
   net::StorageAccessApiStatus storage_access_api_status =
       storage_key_override.has_value()
           ? net::StorageAccessApiStatus::kAccessViaAPI
           : net::StorageAccessApiStatus::kNone;
   ```

4. This status is propagated to `WorkerScriptFetcher::CreateAndStart()` at
   line 497, where it's set on the resource request at
   `worker_script_fetcher.cc:348`

The SharedWorker thus operates with a first-party StorageKey AND the SAA
override, giving it full unpartitioned access. Crucially, SharedWorkers can be
shared across multiple documents -- if the worker is created by one SAA-granted
iframe, it persists even after that iframe navigates away, as long as any
client is connected.

### Impact

A SharedWorker created via `StorageAccessHandle` can outlive the SAA grant that
created it, continuing to make requests with unpartitioned cookie access. If
another same-origin iframe (even without its own SAA grant) connects to the
same SharedWorker, it could indirectly benefit from the unpartitioned access
through message passing.

---

## Finding SAA-09: Service Worker Fetch Does Not Inherit SAA Grant

**Severity: Not a bug (correct behavior)**
**Confidence: High**

Service Worker code paths in `content/browser/service_worker/` do not reference
`StorageAccessApiStatus` or `kStorageAccessGrantEligible`. The Service Worker
fetch handler operates in a partitioned context, and SAA grants are correctly
NOT propagated to SW-initiated fetches. Only direct subresource fetches from
the SAA-granted frame carry the `kStorageAccessGrantEligible` override.

The only worker type that inherits SAA status is the dedicated worker (via
`DedicatedWorkerHostFactoryImpl`) and shared workers (when created via
`StorageAccessHandle`).

---

## Summary Matrix

| # | Finding | Severity | Confidence | VRP Eligible |
|---|---------|----------|------------|-------------|
| SAA-01 | StorageAccessHandle persists after grant revocation | Medium | High | Possible |
| SAA-02 | BFCache allows pages with SAA grants, no re-validation on restore | Medium | High | Possible |
| SAA-03 | rSAFor only gated by RWS, no user prompt | Low | High | No (by design) |
| SAA-04 | Grant only pushed to default StoragePartition | Low | High | Unlikely |
| SAA-05 | Grant content setting pattern is site-scoped | Low-Med | High | Unlikely (by design) |
| SAA-06 | Redirect strips SAA correctly | N/A | High | N/A |
| SAA-07 | FedCM auto-grant bypasses user gesture | Low | High | Unlikely (by design) |
| SAA-08 | SharedWorker via SAH gets unpartitioned access, outlives grant | Medium | High | Possible |
| SAA-09 | Service Worker correctly does NOT inherit SAA | N/A | High | N/A |

## Recommended Follow-up

1. **SAA-01 + SAA-02**: Build a PoC demonstrating unpartitioned IndexedDB access
   persisting after grant revocation via both the handle-revocation path and the
   BFCache-restore path.
2. **SAA-08**: Build a PoC showing SharedWorker created via StorageAccessHandle
   outliving the iframe that created it and continuing to serve unpartitioned data.
3. Investigate whether `ProfileNetworkContextService::OnContentSettingChanged`
   can race with the explicit `SetContentSettings` calls (the TODO at
   crbug.com/40638427 referenced in both grant contexts).
