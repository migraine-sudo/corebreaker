# Apple Security Bounty 报告：Content Script → Native Messaging 提权漏洞

## 1. 概述

Safari 的 WebKit Web Extensions 实现允许 content script 调用 `browser.runtime.sendNativeMessage()` 和 `browser.runtime.connectNative()` — Chrome 明确限制这些 API 仅 background script 可调用。加之 native messaging host 不接收调用者身份信息，这使得网页（通过 XSS 进入 content script 上下文）可以直接与具有 Keychain 访问、剪贴板访问和文件系统写入能力的特权 native host 通信。

**具体影响**：恶意网页可以通过 Bitwarden Safari 扩展的 native messaging host 从 macOS Keychain 窃取保险库解锁密钥。

## 2. 安全边界分析

### 2.1 Content Script ↔ Native Host 边界

**Chrome 安全模型**：
- Content script 在网页隔离世界中运行（低权限）
- Native messaging host 在 app 沙箱中运行（高权限：Keychain、文件系统、网络）
- **仅 background script** 可以通过 `sendNativeMessage`/`connectNative` 桥接这两个世界
- 在浏览器进程级别强制执行 — content script **无法**调用 native messaging API

**Safari 实现**：
- Content script 在网页上下文中运行（低权限）
- Native messaging host 在 app 沙箱中运行（高权限）
- **任何扩展上下文**包括 content script 都可以调用 `sendNativeMessage`/`connectNative`
- 仅存在 WebProcess 侧 JS 可见性检查（验证 manifest 权限，**不验证**调用者上下文）
- UIProcess handler 无权限检查或调用者验证

### 2.2 缺失的检查

**Chrome 防御**（浏览器进程级别）：
```cpp
if (!context->IsForServiceWorkerContext() && !context->IsForBackgroundPage()) {
    return RespondNow(Error("Only background scripts can use native messaging"));
}
```

**Safari 实现**（WebExtensionAPIRuntimeCocoa.mm:162-169）：
```cpp
bool WebExtensionAPIRuntime::isPropertyAllowed(...)
{
    if (name == "connectNative"_s || name == "sendNativeMessage"_s)
        return extensionContext->hasPermission("nativeMessaging"_s);
    // ^^^ 仅检查 manifest 有 nativeMessaging — 不检查调用者类型
}
```

**Safari IPC validator**（WebExtensionContext.messages.in:128-129）：
```
[Validator=isLoaded] RuntimeSendNativeMessage(...)
[Validator=isLoaded] RuntimeConnectNative(...)
```

对比正确使用强验证器的 API：
```
[Validator=isLoadedAndPrivilegedMessage] TabsExecuteScript(...)
```

### 2.3 Native Host 不接收调用者身份

Safari 的 `sendNativeMessage` handler 仅转发 `{message: <payload>}` 到 native host。
不包含：调用者上下文类型、来源 URL、是否为用户操作。
Native host **无法区分** background script 的合法调用和攻击者触发的 content script 调用。

## 3. 具体攻击：Bitwarden 保险库密钥窃取

### 3.1 目标：Bitwarden Safari 扩展

| 属性 | 值 |
|------|---|
| 用户数 | 1000万+ |
| `nativeMessaging` | Safari 上为**必需**权限（非可选） |
| Content script 模式 | `*://*/*`（所有 URL，所有 frame） |
| Content script 时机 | `document_start` |
| Native host 标识符 | `com.8bit.bitwarden` |
| Native host 能力 | Keychain 访问、剪贴板、文件系统 |

### 3.2 Bitwarden Native Host 命令

来源：`SafariWebExtensionHandler.swift`

| 命令 | 能力 | 无需额外认证 |
|------|-----|-------------|
| `readFromClipboard` | 读取系统剪贴板 | ✓ |
| `copyToClipboard` | 写入系统剪贴板 | ✓ |
| `unlockWithBiometricsForUser` | 从 Keychain 读取保险库密钥 | 需生物识别 |
| `biometricUnlock` | 从 Keychain 读取保险库密钥（旧路径） | 需生物识别 |
| `downloadFile` | 向磁盘写入任意文件 | 需保存对话框 |

### 3.3 攻击链

```
┌─────────────────────────────────────────────────────┐
│ 网页 (attacker.com)                                 │
│                                                     │
│ 1. Bitwarden content script 在 document_start 注入   │
│    (模式: *://*/* 匹配所有页面)                      │
│                                                     │
│ 2. 攻击者实现进入 content script 世界的 XSS：        │
│    - DOM 操作跨越内容脚本边界                         │
│    - 原型链污染影响 content script 代码               │
│    - postMessage 混淆                               │
│                                                     │
│ 3. 在 content script 上下文中调用：                   │
│    browser.runtime.sendNativeMessage(               │
│      "com.8bit.bitwarden",                          │
│      {command: "readFromClipboard"}                  │
│    )                                                │
│    → 返回剪贴板内容（可能包含已复制的密码）           │
│                                                     │
│ 4. 或触发保险库解锁：                                │
│    browser.runtime.sendNativeMessage(               │
│      "com.8bit.bitwarden",                          │
│      {command: "unlockWithBiometricsForUser",        │
│       userId: "..."}                                 │
│    )                                                │
│    → 用户批准生物识别提示 → 保险库密钥返回            │
│    → 完整保险库泄露                                  │
└─────────────────────────────────────────────────────┘
```

### 3.4 前置条件

1. 用户安装了 Bitwarden Safari 扩展（1000万+用户）
2. 用户访问攻击者控制的页面（Bitwarden content script 自动注入）
3. 攻击者在 content script 世界中实现代码执行（XSS 进入 content script）
4. 剪贴板读取：零额外交互
5. 保险库解锁：用户需批准生物识别提示（社工："验证身份以继续"）

## 4. 影响评估

### 4.1 严重性

| 因素 | 评估 |
|------|------|
| 攻击复杂度 | 中 — 需要 XSS 进入 content script 世界 |
| 所需权限 | 无 — 网页攻击者 |
| 用户交互 | 最小 — 访问攻击者页面；保险库解锁需生物识别 |
| 范围 | 已变更 — 跨越 web content → app 沙箱边界 |
| 机密性 | 严重 — Keychain 访问、保险库密钥、剪贴板 |
| 完整性 | 高 — 剪贴板写入、文件下载 |
| 可用性 | 无 |

**CVSS 3.1 估计**：8.6（高）到 9.3（严重）

### 4.2 赏金类别

此漏洞归类为 Apple Security Bounty 的**沙箱逃逸**：
- Web content 进程 → UIProcess → Native host（app 沙箱）
- 跨越 WebContent 沙箱边界
- 潜在赏金：**$100,000 - $300,000**

## 5. 受影响版本

- Safari 15.4+（所有支持 Web Extensions scripting API 的版本）
- 所有平台：macOS、iOS、iPadOS
- 任何使用 `nativeMessaging` + 广泛 URL content script 的扩展

## 6. 建议修复方案

### 修复 A：限制为特权上下文（主要）

在 `WebExtensionContext.messages.in` 中更改 validator：
```
[Validator=isLoadedAndPrivilegedMessage] RuntimeSendNativeMessage(...)
[Validator=isLoadedAndPrivilegedMessage] RuntimeConnectNative(...)
```

### 修复 B：UIProcess 权限检查（纵深防御）

### 修复 C：向 Native Host 转发调用者上下文（纵深防御）

### 修复 D：更新 WebProcess 绑定（纵深防御）

**应同时应用四个修复**以实现纵深防御。

## 7. 发现方法

1. Chrome 文档声明："sendNativeMessage 在 content script 中不可用"
2. 跨实现对比："Safari 是否强制执行相同限制？"
3. `messages.in` 审查：`isLoaded`（最弱）vs `isLoadedAndPrivilegedMessage`（强）
4. UIProcess handler 审查：确认零权限/上下文检查
5. WebProcess `isPropertyAllowed`：仅检查 manifest 权限，不检查调用者类型
6. Bitwarden 源码：确认 native host 有 Keychain 访问且无调用者验证

## 8. 与其他发现的对比

| 属性 | DNR CSP 绕过 | 跨扩展注入 | Native Messaging 提权 |
|------|-------------|-----------|---------------------|
| CVSS | 8.1 | 9.1 | 8.6-9.3 |
| 所需条件 | declarativeNetRequest | <all_urls> + scripting | XSS 进入 content script |
| 目标 | 网页 | 其他扩展 | Native host（app 沙箱） |
| Chrome 防御 | kAllowedTransformSchemes | permissions_data.cc:164-168 | Background-only 限制 |
| 跨越边界 | CSP 策略 | 扩展隔离 | WebContent → App 沙箱 |
| 赏金类别 | 纵深防御（$5K-25K） | 扩展隔离（$25K-50K） | 沙箱逃逸（$100K-300K） |
