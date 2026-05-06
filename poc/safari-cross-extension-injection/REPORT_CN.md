# Apple Security Bounty 报告：跨扩展脚本注入（缺失扩展 URL 权限检查）

## 1. 概述

Safari 的 WebKit Web Extensions 权限系统允许拥有 `<all_urls>` + `scripting` 权限的扩展在**其他扩展**的页面中执行任意 JavaScript。这是因为 `<all_urls>` 匹配了 `webkit-extension://` URL，而系统中不存在阻止跨扩展脚本注入的检查。

Chrome 在 `permissions_data.cc:164-168` 中明确阻止了此攻击：当 `document_url.SchemeIs(kExtensionScheme) && document_url.GetHost() != extension_id_` 时拒绝访问。WebKit **没有**等效检查。

后果：一个恶意扩展（如"深色模式 Pro"）可以读取密码管理器扩展、加密钱包扩展或任何在 `browser.storage` 中存储敏感数据的扩展的所有数据。

## 2. 安全边界分析

### 2.1 扩展隔离边界

扩展是相互隔离的安全上下文。每个扩展：
- 拥有独立的 origin（`webkit-extension://<UUID>`）
- 拥有独立的存储（`browser.storage.local`）
- 拥有独立的 API 权限
- **不应该**能访问其他扩展的数据或 API

这是一个基本安全假设：用户信任密码管理器的数据对其他扩展不可访问。

### 2.2 `<all_urls>` 应该匹配什么

**Chrome 中**，`<all_urls>` 匹配：
- `http://*/*`、`https://*/*`、`ftp://*/*`、`file:///*`
- **不匹配** `chrome-extension://*/*`（明确排除）

**Safari/WebKit 中**，`<all_urls>` 匹配：
- 以上全部
- **同时匹配 `webkit-extension://*/*`**（未排除）

### 2.3 缺失的检查

Chrome 的防御（`permissions_data.cc:164-168`）：
```cpp
if (document_url.SchemeIs(kExtensionScheme) &&
    document_url.GetHost() != extension_id_ &&
    !allow_on_extension_urls) {
    *error = manifest_errors::kCannotAccessExtensionUrl;
    return true;  // 已阻止
}
```

WebKit 的 `permissionState(URL)`（`WebExtensionContext.cpp:846-968`）：
- 第 851 行：`isURLForThisExtension(url)` 对自身页面授予隐式访问 ✓
- **没有等效阻止**其他扩展 URL 的逻辑
- `<all_urls>` 模式通过 `supportedSchemes()` 匹配 `webkit-extension://other-uuid/...`

### 2.4 漏洞前后的能力对比

**无此漏洞**（Chrome 行为）：
- 扩展 A 可以向网页注入脚本（`http://`、`https://`）
- 扩展 A **无法**向扩展 B 的页面注入脚本
- 扩展 A **无法**读取扩展 B 的存储
- 每个扩展的数据相互隔离

**存在此漏洞**（Safari 行为）：
- 扩展 A 可以通过 `scripting.executeScript` 向扩展 B 的页面注入脚本
- 注入的脚本在扩展 B 的 main world 中运行
- 完全访问扩展 B 的 `browser.storage`、`browser.runtime` 等
- 可以读取扩展 B 存储的**所有**数据（密码、密钥、令牌）

## 3. 根因分析

### 3.1 `supportedSchemes()` 包含了扩展 Scheme

文件：`WebExtensionMatchPattern.cpp` 第 62-65 行
```cpp
static OptionSet<Scheme> supportedSchemes() {
    return { Scheme::HTTP, Scheme::HTTPS, Scheme::File, 
             Scheme::FTP, Scheme::Extension };  // <-- 包含了扩展 scheme！
}
```

这意味着 `<all_urls>` 创建的匹配模式会匹配 `webkit-extension://` URL。

### 3.2 `permissionState()` 缺少跨扩展阻断

文件：`WebExtensionContext.cpp` 第 846-968 行

权限检查流程：
1. `isURLForThisExtension(url)` → 对自身页面返回 `PermissionState::GrantedImplicitly` ✓
2. 对**其他扩展**的 URL → 继续执行已授予权限的模式匹配
3. 如果 `<all_urls>` 已授予 → 匹配 `webkit-extension://other-uuid/*` → 返回 `PermissionState::GrantedExplicitly`
4. **没有检查** URL 是否属于不同的扩展

### 3.3 `scripting.executeScript` 信任权限状态

文件：`WebExtensionContextAPIScriptingCocoa.mm` 第 142-155 行

```cpp
// 只检查 hasPermission(url) — 没有跨扩展阻断
if (!hasPermission(tab->url())) {
    // 权限拒绝
}
// 如果权限已授予（通过 <all_urls>），注入继续执行
```

### 3.4 Main World 注入 = 完整 API 访问

文件：`WebExtensionContextAPIScriptingCocoa.mm` 第 155 行

当指定 `world: "MAIN"` 时，注入的脚本在目标扩展的 JavaScript 上下文中执行，完全访问 `browser.*` API——就像它是扩展 B 自己的代码一样。

## 4. 攻击链

```
┌─────────────────────┐        ┌─────────────────────┐
│  扩展 A              │        │  扩展 B              │
│  "深色模式 Pro"       │        │  "安全保险箱"         │
│                      │        │  （密码管理器）       │
│  权限：              │        │                      │
│  - <all_urls>        │        │  存储：              │
│  - scripting         │        │  - bank.com: 用户/密码│
│  - tabs              │        │  - gmail: 用户/密码   │
└──────────┬───────────┘        └──────────┬───────────┘
           │                                │
           │ 1. tabs.query({})              │
           │    → 找到 URL 为               │
           │    webkit-extension://B/popup  │
           │    的标签页                     │
           │                                │
           │ 2. scripting.executeScript({   │
           │      target: {tabId},          │
           │      world: "MAIN",            │
           │      func: stealData           │
           │    })                           │
           │                                │
           │ 3. 注入代码以扩展 B 的身份运行：│
           │    browser.storage.local       │
           │      .get(null)                │
           │      → 返回所有密码            │
           │                                │
           │ 4. 数据传送到攻击者服务器       │
           └────────────────────────────────┘
```

## 5. 影响评估

### 5.1 直接影响

| 影响 | 描述 |
|------|------|
| 密码窃取 | 读取密码管理器扩展中的所有凭据 |
| 加密钱包窃取 | 读取钱包扩展中的助记词、私钥 |
| API 令牌窃取 | 读取扩展存储的 OAuth 令牌、API 密钥 |
| 扩展伪装 | 以受害扩展的身份执行操作 |
| 通用扩展入侵 | 影响任何存储敏感数据的扩展 |

### 5.2 真实攻击场景

**场景 1：密码管理器利用**
- 受害者使用 1Password/Bitwarden/LastPass Safari 扩展
- 攻击者的"工具"扩展读取所有已存储的密码
- 初始安装后无需用户交互

**场景 2：加密钱包清空**
- 受害者使用 MetaMask 或类似钱包扩展
- 攻击者读取扩展存储中的助记词/私钥
- 将所有资产转移到攻击者钱包

**场景 3：开发者工具利用**
- 受害者使用存储 OAuth 令牌的 GitHub/GitLab 扩展
- 攻击者使用窃取的令牌访问私有仓库
- 供应链攻击向量

### 5.3 规模

- 影响任何拥有 `<all_urls>` + `scripting` 的扩展（许多合法扩展具有此权限）
- 许多扩展在 `browser.storage.local` 中存储敏感数据
- 密码管理器、钱包扩展、开发者工具、VPN 扩展均受影响
- 恶意扩展只需这些常见权限即可从**所有**其他扩展窃取数据

### 5.4 严重性评判

| 因素 | 评估 |
|------|------|
| 攻击复杂度 | 低 — 标准扩展 API，无需漏洞利用 |
| 所需权限 | 低 — `<all_urls>` + `scripting`（常见，用户批准） |
| 用户交互 | 无（扩展安装批准后） |
| 范围 | 已变更 — 突破扩展间隔离边界 |
| 机密性 | 严重 — 所有扩展存储的秘密暴露 |
| 完整性 | 高 — 可修改受害扩展的数据 |
| 可用性 | 无 |

**CVSS 3.1 估计**：9.1（严重）

## 6. 受影响版本

Safari 的扩展系统自 Safari 15.4（2022年3月）起支持 `scripting.executeScript`。`<all_urls>` 匹配模式从初始实现起就包含了扩展 scheme。

- Safari 15.4+（所有支持 scripting API 的版本）
- 所有平台：macOS、iOS、iPadOS、visionOS

## 7. 复现步骤

### 前置条件
- 安装了 Xcode 的 macOS
- Safari 已启用"允许未签名扩展"

### 步骤

1. **构建并安装受害扩展：**
```bash
cd poc/safari-cross-extension-injection/victim-extension
xcrun safari-web-extension-converter . --project-location ../xcode-victim
# 在 Xcode 中构建并运行
```

2. **构建并安装攻击扩展：**
```bash
cd poc/safari-cross-extension-injection/attacker-extension
xcrun safari-web-extension-converter . --project-location ../xcode-attacker
# 在 Xcode 中构建并运行
```

3. 在 Safari > 设置 > 扩展中**启用两个扩展**

4. **打开受害扩展的弹窗**（创建扩展页面标签页）

5. **打开攻击扩展的弹窗**并点击"Scan & Steal Extension Data"

6. **结果：**攻击扩展显示受害扩展存储的所有凭据

### 预期行为（Chrome）：
- `scripting.executeScript` 目标为 `chrome-extension://` URL → 权限拒绝错误

### 实际行为（Safari）：
- `scripting.executeScript` 目标为 `webkit-extension://` URL → 代码在受害者上下文中执行

## 8. 建议修复方案

### 修复 A：在 `permissionState()` 中阻断跨扩展 URL 访问（主要）

在 `WebExtensionContext.cpp` 第 852 行之后添加：

```cpp
// 阻止访问其他扩展的页面
if (isURLForAnyExtension(url) && !isURLForThisExtension(url))
    return PermissionState::DeniedImplicitly;
```

### 修复 B：从 `<all_urls>` 中排除扩展 Scheme（纵深防御）

在 `WebExtensionMatchPattern.cpp` 中修改 `supportedSchemes()`：

```cpp
static OptionSet<Scheme> supportedSchemes() {
    return { Scheme::HTTP, Scheme::HTTPS, Scheme::File, Scheme::FTP };
    // 移除 Scheme::Extension — <all_urls> 不应匹配扩展页面
}
```

### 修复 C：在 `scripting.executeScript` 中添加显式检查（纵深防御）

在 `WebExtensionContextAPIScriptingCocoa.mm` 中，执行前添加：

```cpp
if (isURLForAnyExtension(tab->url()) && !isURLForThisExtension(tab->url())) {
    completionHandler(toWebExtensionError(@"scripting_executeScript", nil, 
        @"Cannot inject script into another extension's page"));
    return;
}
```

**应同时应用三个修复**以实现纵深防御。

## 9. 发现方法

### 9.1 发现路径

1. **广泛扫描** `WebExtensionContext.messages.in` 中所有弱验证器的消息
2. 在 `tabs.sendMessage` 第 486 行识别 `isURLForAnyExtension` — 只检查 scheme，不检查扩展身份
3. 追问："这种模式是否存在于其他权限检查中？"
4. 发现：`permissionState()` 没有跨扩展阻断 → `<all_urls>` 匹配其他扩展
5. 验证：`scripting.executeScript` → `hasPermission` → `permissionState` → 授予访问
6. 确认 Chrome 在 `permissions_data.cc:164-168` 的显式防御

### 9.2 发现来源：Chrome 审计 → Safari 漏洞

此发现源于 FuzzMind 项目对 Chrome 扩展安全的审计工作：

1. Chrome 审计期间发现 `permissions_data.cc:164-168` 的跨扩展阻断逻辑
2. 问："WebKit 是否有等效保护？"
3. 代码审计确认 WebKit 没有等效检查
4. 构建 PoC 验证攻击可行性

**方法论核心**：Chrome 已知的安全加固 = WebKit 的漏洞信号。Chrome 的防御代码本身就是"这里曾经有/可能有问题"的标志。

### 9.3 模式：URL Scheme 所有权隐式信任

Bug 模式为：代码检查"这是一个扩展 URL 吗？"而不检查"这是**我的**扩展的 URL 吗？"正确使用 `isURLForThisExtension` 的函数工作正常。使用 `isURLForAnyExtension` 或无扩展特定检查的函数存在漏洞。

## 10. 与 DNR CSP 绕过的对比

| 属性 | DNR CSP 绕过 | 跨扩展注入 |
|------|-------------|-----------|
| 所需权限 | declarativeNetRequest（最小） | <all_urls> + scripting（常见） |
| 目标 | 网页 | 其他扩展 |
| 影响 | CSP 绕过 → 网站 XSS | 完整扩展数据窃取 |
| 严重性 | 高（8.1） | 严重（9.1） |
| 需要 | 扩展安装 | 扩展安装 |
| 隐蔽性 | 高（看起来像广告拦截器） | 中（需要 scripting 权限） |
| Chrome 防御 | kAllowedTransformSchemes | permissions_data.cc 跨扩展阻断 |
| WebKit 缺陷 | 无 scheme 验证 | 无跨扩展权限阻断 |
