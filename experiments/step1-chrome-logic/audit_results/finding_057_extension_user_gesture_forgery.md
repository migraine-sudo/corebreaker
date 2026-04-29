# Finding 057: Extension API user_gesture Parameter Accepted Without Browser Validation (crbug.com/40055124)

## Summary

The `user_gesture` parameter in extension API function calls is accepted from the renderer IPC without any browser-side validation. Multiple security-sensitive operations gate on this value, including `permissions.request()` which allows extensions to escalate their permissions. A malicious extension can forge `user_gesture=true` to bypass user consent dialogs.

## Affected Files

- `extensions/browser/extension_function_dispatcher.cc:103,578` — user_gesture accepted from renderer unvalidated
- `chrome/browser/extensions/api/permissions/permissions_api.cc:317` — permissions.request() gates on user_gesture

## Details

### Unvalidated parameter

```cpp
// extension_function_dispatcher.cc:103
// TODO(crbug.com/40055124): Validate params.user_gesture.

// extension_function_dispatcher.cc:578
function->set_user_gesture(params_without_args.user_gesture);
```

The `user_gesture` field comes directly from the renderer via Mojo IPC. The TODO explicitly acknowledges this should be validated but it isn't.

### Security-sensitive operations gating on user_gesture

- **`permissions.request()`** — Requires gesture to request new permissions from the user
- **`management.uninstall()`** — Requires gesture for uninstall confirmation UI
- **`management.setEnabled()`** — Requires gesture to enable/disable extensions
- **`management.installReplacementWebApp()`** — Requires gesture for app installation
- **`identity.getAuthToken()`** — Uses gesture to determine interactive authentication mode
- **`permissions.addSiteAccess()`** / **`permissions.removeSiteAccess()`** — Require gesture
- **`document_scan`** — Requires gesture for device access

## Attack Scenario

### Silent permission escalation

1. A malicious extension is installed with minimal permissions (e.g., only `activeTab`)
2. The extension's content script or service worker calls `chrome.permissions.request({permissions: ['tabs', 'history', 'cookies']})` with a forged `user_gesture=true`
3. Because the browser trusts the renderer-supplied `user_gesture`, the permission prompt either shows without an actual user click or may be auto-granted in certain contexts
4. The extension silently gains `tabs`, `history`, and `cookies` permissions
5. The extension can now read all browsing history and cookies

### Silent extension management

1. Malicious extension calls `chrome.management.uninstall(securityExtensionId)` with forged gesture
2. A competing security extension is uninstalled with the user only seeing a confirmation dialog they didn't initiate
3. Or: `chrome.management.setEnabled(extensionId, false)` disables a security extension

## Impact

- **No compromised renderer required**: A standard (malicious) extension's content script runs in the renderer and controls IPC parameters
- **Permission escalation**: Extensions can silently request elevated permissions
- **Extension management manipulation**: Can uninstall or disable other extensions
- **OAuth token theft**: Can trigger interactive auth flows without genuine user interaction
- **Known unfixed issue**: crbug.com/40055124

## VRP Value

**High** — This is the highest-value extension-related finding. A malicious extension (which only needs to pass Chrome Web Store review with minimal permissions) can escalate its own permissions silently. No compromised renderer needed — any extension's content script or service worker can control the IPC parameters.
