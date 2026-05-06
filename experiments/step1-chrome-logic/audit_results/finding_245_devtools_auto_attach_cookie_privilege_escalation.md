# Finding 245: DevTools Auto-Attached Session Unconditionally Grants MayAccessAllCookies

## Summary

In `content/browser/devtools/protocol/target_handler.cc`, the `TargetHandler::Session` inner class (which acts as `DevToolsAgentHostClient` for auto-attached child sessions) overrides `MayAccessAllCookies()` to unconditionally return `true` (line 618). Unlike all other permission methods in the same class (which delegate to `GetRootClient()`), this one does not check the root client's permission. When a Chrome extension with `debugger` permission uses `Target.setAutoAttach` to attach to child targets (service workers, iframes, etc.), the child session's `NetworkHandler` receives a client reference where `MayAccessAllCookies()` is `true`, even though the extension's own `ExtensionDevToolsClientHost::MayAccessAllCookies()` returns `false`.

## Root Cause

**File:** `content/browser/devtools/protocol/target_handler.cc:618`

```cpp
// All other permission methods delegate to root:
bool MayAttachToURL(const GURL& url, bool is_webui) override {
    return GetRootClient()->MayAttachToURL(url, is_webui);  // Delegates
}
bool IsTrusted() override { return GetRootClient()->IsTrusted(); }  // Delegates
bool MayReadLocalFiles() override { return GetRootClient()->MayReadLocalFiles(); }  // Delegates
bool MayWriteLocalFiles() override { return GetRootClient()->MayWriteLocalFiles(); }  // Delegates
bool AllowUnsafeOperations() override { return GetRootClient()->AllowUnsafeOperations(); }  // Delegates

// But MayAccessAllCookies does NOT:
bool MayAccessAllCookies() override { return true; }  // BUG: Should delegate
```

**Extension client correctly returns false:**
```cpp
// chrome/browser/extensions/api/debugger/debugger_api.cc:670-672
bool ExtensionDevToolsClientHost::MayAccessAllCookies() {
  return false;
}
```

**Base class explicitly documents intent:**
```cpp
// content/public/browser/devtools_agent_host_client.cc:44-47
// debugger, pipe handler, etc.) should override this to return true.
// Debugger extension clients should keep the default (false).
bool DevToolsAgentHostClient::MayAccessAllCookies() {
  return false;
}
```

## Impact

**File:** `content/browser/devtools/protocol/network_handler.cc:2494-2515`

```cpp
void NetworkHandler::ClearCookies(..., DevToolsAgentHostClient& client, ...) {
  auto* cookie_manager = storage_partition->GetCookieManagerForBrowserProcess();
  if (client.MayAccessAllCookies()) {
    // Unrestricted clients can clear all cookies atomically.
    cookie_manager->DeleteCookies(
        network::mojom::CookieDeletionFilter::New(), ...);  // Deletes ALL cookies!
  } else {
    // Restricted clients must filter by URL permissions before deletion.
    cookie_manager->GetAllCookies(...);  // Per-cookie filtering
  }
}
```

When `Network.clearBrowserCookies` is called on the auto-attached child session:
- `client.MayAccessAllCookies()` → `true` (the bug)
- Takes the fast path that atomically deletes ALL cookies for ALL domains
- Bypasses the per-cookie domain filtering that normally restricts extensions

## Exploitation Scenario

### Prerequisites
- A Chrome extension with `debugger` permission (common in developer tools, ad blockers that modify network behavior, testing tools)
- The extension has limited `host_permissions` (e.g., only `*://*.example.com/*`)

### Attack Steps

1. Extension attaches to a tab via `chrome.debugger.attach(target, "1.3")`
2. Extension sends `Target.setAutoAttach({autoAttach: true, flatten: true, waitForDebuggerOnStart: false})`
3. When a child target auto-attaches (e.g., the page loads a service worker or cross-origin iframe):
   - A `TargetHandler::Session` is created as the client for the child session
   - Its `MayAccessAllCookies()` returns `true`
4. Extension sends `Network.clearBrowserCookies` to the child session (via the flattened protocol, using the child's session ID)
5. The `NetworkHandler` on the child session checks `client_.MayAccessAllCookies()` → `true`
6. **All cookies for ALL domains are atomically deleted**, regardless of the extension's host_permissions

### Result
An extension that should only be able to affect cookies for `example.com` can destroy all cookies for every domain in the browser profile (Gmail, banking sites, social media sessions, etc.).

## Security Severity

**Medium (Privilege Escalation)**

- Violates the extension permission model's principle of least privilege
- Extensions with `debugger` permission for limited domains can affect ALL domains' cookies
- Destructive action (cookie clearing) causes user-visible harm (all sessions logged out)
- No user interaction required beyond the initial debugger attach consent (infobar)
- Policy-installed extensions (`--force-installed`) bypass the infobar entirely

## Suggested Fix

```cpp
// Option A: Delegate to root client (consistent with all other methods)
bool MayAccessAllCookies() override { 
    return GetRootClient()->MayAccessAllCookies(); 
}

// Option B: If there's a reason auto-attached sessions need broader access
// for trusted clients only:
bool MayAccessAllCookies() override { 
    return GetRootClient()->IsTrusted() || GetRootClient()->MayAccessAllCookies();
}
```

Option A is clearly correct — it maintains consistency with the pattern used for all other permission methods and matches the documented intent.

## References

- `content/browser/devtools/protocol/target_handler.cc:618` — Bug location
- `content/browser/devtools/protocol/network_handler.cc:2494-2515` — ClearCookies impact
- `chrome/browser/extensions/api/debugger/debugger_api.cc:670-672` — Extension returns false
- `content/public/browser/devtools_agent_host_client.cc:44-47` — Documented intent
- `content/browser/devtools/devtools_session.h:221` — Network domain available to untrusted clients
- `content/browser/devtools/devtools_session.h:224` — Target domain available to untrusted clients
