# Finding 179: Enterprise Policy Permission Removal Persists to Prefs, Prevents Re-Grant on Policy Change

## Summary
When enterprise policy removes permissions from an extension via `PermissionsUpdater::RemovePermissionsByPolicy`, the removal is persisted to the extension's active permissions in preferences via `SetDesiredActivePermissions`. This means that when the enterprise policy is later changed (e.g., the restriction is removed), the permissions are NOT automatically restored because the preference was permanently modified. There is an explicit TODO from a Chromium developer acknowledging this is wrong: "TODO(devlin): This seems wrong. Since these permissions are being removed by enterprise policy, we should not update the active permissions set in preferences."

## Affected Files
- `extensions/browser/permissions/permissions_updater.cc` (lines 514-519)

## Details

```cpp
void PermissionsUpdater::RemovePermissionsByPolicy(
    const Extension* extension,
    const PermissionSet& to_remove) {
  // ...
  // TODO(devlin): This seems wrong. Since these permissions are being removed
  // by enterprise policy, we should not update the active permissions set in
  // preferences. That way, if the enterprise policy is changed, the removed
  // permissions would be re-added.
  ExtensionPrefs::Get(browser_context_)
      ->SetDesiredActivePermissions(extension->id(), *total);

  SetPermissions(extension, std::move(total),
                 /*withhold_optional_permissions=*/true);
  // ...
}
```

The correct behavior would be to:
1. Only modify the in-memory permission set (not prefs) when policy removes permissions.
2. Keep the prefs as the "desired" state so that when the policy restriction is lifted, the original permissions can be restored.
3. Instead, the current code permanently modifies the preferences, making the policy-based removal permanent even after the policy changes.

## Attack Scenario
1. An enterprise admin sets a policy that blocks an extension from accessing `*.intranet.corp` sites.
2. The `RemovePermissionsByPolicy` function strips the `*.intranet.corp` permission from the active set AND from the preferences.
3. The admin later changes the policy to allow the extension access to `*.intranet.corp`.
4. Because the preference was modified, the extension's desired permissions no longer include `*.intranet.corp`.
5. The extension does not regain its permissions automatically, even though:
   - The policy no longer restricts it.
   - The user originally granted the permission.
   - The extension's manifest still declares the permission.
6. The user has to manually re-enable the permission or reinstall the extension.

Alternatively (security angle):
1. A malicious enterprise admin temporarily sets and then removes a policy.
2. This permanently strips permissions from security extensions (e.g., password managers, security scanners).
3. The policy change appears temporary, but the permission removal is permanent.
4. Security extensions silently lose capabilities after the policy is reverted.

## Impact
Medium. This is a correctness bug with security implications. Enterprise-managed extensions can have their permissions permanently degraded by a transient policy change, which impacts the security guarantees of enterprise extension management. The TODO from the Chromium developer confirms this is an acknowledged issue.

## VRP Value
Low
