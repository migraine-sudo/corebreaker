# Finding 181: Extension User Permission Removal Check is DCHECK-Only, Hard Removal of User-Permitted Sites Not Enforced in Release

## Summary
In `PermissionsUpdater::RevokeOptionalPermissions`, the check preventing hard-removal of user-permitted sites is gated behind `DCHECK_IS_ON()`. In release builds, the check is stripped, meaning an extension can call `permissions.remove()` to hard-remove permissions for sites that were granted via the user-permitted sites mechanism, permanently revoking them from the user's perspective.

## Affected Files
- `extensions/browser/permissions/permissions_updater.cc` (lines 327-341)

## Details

```cpp
void PermissionsUpdater::RevokeOptionalPermissions(
    const Extension& extension,
    const PermissionSet& permissions,
    RemoveType remove_type,
    base::OnceClosure completion_callback) {
  // ...
  if (remove_type == RemoveType::kHard) {
    permissions_store_mask |= PermissionsStore::kGrantedPermissions |
                              PermissionsStore::kRuntimeGrantedPermissions;

    // We don't allow the hard-removal of user-permitted sites on a per-
    // extension basis. Instead, these permissions must be removed by removing
    // the user-permitted site entry.
#if DCHECK_IS_ON()
    URLPatternSet user_permitted_sites =
        GetUserPermittedPatternSet(*browser_context_);
    PermissionSet user_permitted_set(
        APIPermissionSet(), ManifestPermissionSet(),
        user_permitted_sites.Clone(), user_permitted_sites.Clone());
    std::unique_ptr<const PermissionSet> user_permitted_being_removed =
        PermissionSet::CreateIntersection(
            permissions, user_permitted_set,
            URLPatternSet::IntersectionBehavior::kDetailed);
    DCHECK(user_permitted_being_removed->effective_hosts().is_empty())
        << "Attempting to hard-remove optional permission to user-permitted "
           "sites: "
        << user_permitted_being_removed->effective_hosts();
#endif
  }
```

The entire block between `#if DCHECK_IS_ON()` and `#endif` is compiled out in release builds. This means:

1. In debug builds: If an extension tries to hard-remove a user-permitted site, a DCHECK fires.
2. In release builds: The removal proceeds silently, permanently removing the user-permitted site permission.

The comment states: "We don't allow the hard-removal of user-permitted sites on a per-extension basis." But this policy is not enforced in release builds.

## Attack Scenario
1. A user grants permission to `https://bank.example.com` via the user-permitted sites mechanism (e.g., from the extensions toolbar).
2. A malicious extension that has optional permissions for `<all_urls>` calls `chrome.permissions.remove({origins: ['https://bank.example.com/*']})` with hard removal semantics.
3. In release builds, the DCHECK is stripped, so the removal succeeds.
4. The user-permitted site permission for `bank.example.com` is permanently removed from the granted set.
5. The user doesn't realize the permission was removed until another extension that relies on the user-permitted site stops working.
6. The malicious extension has effectively manipulated the permission state for other extensions by removing user-permitted sites.

## Impact
Medium. The DCHECK-only enforcement means that the intended security invariant (user-permitted sites cannot be hard-removed per-extension) is not maintained in production. A malicious extension could manipulate the permission state, though the direct security impact depends on how user-permitted sites interact with other extensions.

## VRP Value
Medium
