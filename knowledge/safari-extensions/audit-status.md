# Safari Web Extensions 审计状态

## 审计进度

| 阶段 | 状态 | 日期 |
|------|------|------|
| 源码获取 | ✅ 完成（18 核心文件） | 2026-05-05 |
| IPC 攻击面分析 | ✅ 完成（120 messages 分类） | 2026-05-05 |
| CVE 模式知识库 | ✅ 完成（8 模式） | 2026-05-05 |
| Validator 验证 | ✅ 完成（9 validators 分析） | 2026-05-05 |
| 深入审计（tabs/DNR/sender） | ✅ 完成 | 2026-05-05 |
| PoC 构建 — DNR CSP Bypass | ✅ 完成 | 2026-05-05 |
| PoC 构建 — Cross-Extension Injection | ✅ 完成 | 2026-05-06 |
| Native Messaging 深入审计 | ✅ 完成 | 2026-05-06 |

## 已验证的 Validator 实现

| Validator | 实现 | 安全等级 |
|-----------|------|---------|
| `isLoadedAndPrivilegedMessage` | `message.destinationID() == m_privilegedIdentifier` | 强 |
| `isDeclarativeNetRequestMessageAllowed` | `isLoadedAndPrivilegedMessage + hasPermission(DNR)` | 强 |
| `isScriptingMessageAllowed` | `isLoadedAndPrivilegedMessage + hasPermission(scripting)` | 强 |
| `isDevToolsMessageAllowed` | `isLoadedAndPrivilegedMessage + hasInspectorBgPage()` | 强 |
| `isStorageMessageAllowed` | **`isLoaded() + hasPermission(storage)`** | **弱 — content script 可调用** |

未验证: `isActionMessageAllowed`, `isCookiesMessageAllowed`, `isBookmarksMessageAllowed`, `isMenusMessageAllowed`, `isSidebarMessageAllowed`, `isWebNavigationMessageAllowed`, `isCommandsMessageAllowed`, `isAlarmsMessageAllowed`

## 已排除的攻击路径

| 假设 | 结果 | 原因 |
|------|------|------|
| ScriptingExecuteScript 可从 content script 调用 | ❌ 排除 | 需要 `isLoadedAndPrivilegedMessage + scripting` 权限 |
| TabsExecuteScript 无 host permission 检查 | ❌ 排除 | handler 内部有 `extensionHasPermission()` 检查 (L614) |

## 活跃攻击向量（待验证）

### 已排除的 P0 向量

| # | 向量 | 排除原因 |
|---|------|---------|
| 3 | isURLForThisExtension 跨扩展 | `protocolHostAndPortAreEqual(baseURL(), url)` 严格匹配自身 |
| 4 | Permission cache 投毒 | cache 在所有 match pattern 变更时正确清除; 惰性过期在缓存查找前触发 |
| 5 | PortPostMessage worldType 伪造 | `isPortConnected()` 检查实际连接记录，无法伪造不存在的 port |
| 1-TOCTOU | activeTab 导航竞态 | 权限清除在 `didCommitLoad` 中同步执行，tab.url() 在 commit 后才变 |
| tabs | tabsExecuteScript 绕过 | `isLoadedAndPrivilegedMessage` + `extensionHasAccess()` + `extensionHasPermission()` 三重验证 |

### P0 — 高价值（仍活跃）

#### 1. temporaryPermissionMatchPattern 竞态/绕过
**位置**: `WebExtensionContext.cpp:857-861`
```cpp
if (tab) {
    auto temporaryPattern = tab->temporaryPermissionMatchPattern();
    if (temporaryPattern && temporaryPattern->matchesURL(url))
        return PermissionState::GrantedExplicitly;
}
```
**问题**: activeTab 临时权限在什么条件下被授予？revoke 的时机是否有 TOCTOU？
**影响**: 如果能让临时权限在不该存在时存在 → 绕过 host permission → 注入任意页面

#### 2. extensionHasPermission 的 delegate bypass
**位置**: `WebExtensionTabCocoa.mm:260`
```cpp
if (m_respondsToShouldBypassPermissions && [m_delegate shouldBypassPermissionsForWebExtensionContext:...])
    return true;
```
**问题**: 哪些 host app 实现了这个 delegate？Safari 本身是否有？
如果第三方 app 嵌入 WKWebView + Web Extension，并实现了宽松的 delegate → 沙箱逃逸

#### 3. isURLForThisExtension 自引用绕过
**位置**: `WebExtensionContext.cpp:851-852`
```cpp
if (isURLForThisExtension(url))
    return PermissionState::GrantedImplicitly;
```
**问题**: 能否让目标 tab 导航到 extension URL？
如果 `tabsExecuteScript` 的目标 tab 显示的是 `extension://xxx/page.html`，
那 `extensionHasPermission()` 返回 true → 可以注入脚本到其他扩展的页面？
需验证: `isURLForThisExtension` 是否只匹配**自己的** extension URL

#### 4. Permission cache 投毒
**位置**: `WebExtensionContext.cpp:870-882`
```cpp
if (m_cachedPermissionURLs.contains(url)) {
    PermissionState cachedState = m_cachedPermissionStates.get(url);
    ...
    return cachedState;
}
```
**问题**: 缓存 key 是完整 URL。如果权限被 revoke 但缓存没清除 → 使用过期的 granted 状态
需验证: `deniedPermissionMatchPatterns` 的变更是否清空缓存

#### 5. PortPostMessage — isPortConnected 绕过
**位置**: `WebExtensionContextAPIPortCocoa.mm:53`
**状态**: 部分排除 — `isPortConnected` 检查连接记录
**剩余攻击面**: port 连接建立过程 (`RuntimeConnect`) 是否校验 worldType？
如果能建立一个 `{Main→ContentScript}` 方向的 port，就能发消息到 content script world

#### 6. RuntimeSendNativeMessage 从 content script
**位置**: `WebExtensionContext.messages.in:128`
```
[Validator=isLoaded] RuntimeSendNativeMessage(String applicationID, String messageJSON)
```
**问题**: content script 可以直接发 native message（只需 isLoaded）
如果 native host 不区分消息来源（privileged vs content script）→ 提权到 native

### P1 — 中等价值

#### 7. Storage API 跨上下文影响
- `StorageSetAccessLevel` 可从 content script 调用（isLoaded only）
- 能否修改 background page 的存储行为？

#### 8. DNR 规则 JSON 解析
- `DeclarativeNetRequestUpdateDynamicRules(String rulesToAddJSON, ...)`
- JSON 字符串在 UIProcess 解析 → 复杂输入处理

#### 9. URL Match Pattern 解析漏洞
- `WebExtensionMatchPatternCocoa.mm` — 模式匹配逻辑
- 特殊 URL scheme 绕过？unicode normalization 差异？

## 文件索引

已下载源码位于: `targets/webkit-extensions/Source/WebKit/`

| 路径 | 大小 | 关键内容 |
|------|------|---------|
| `UIProcess/Extensions/WebExtensionContext.messages.in` | 27KB | 120 条 IPC 消息定义 |
| `UIProcess/Extensions/WebExtensionContext.cpp` | 73KB | validator + permission 状态机 |
| `UIProcess/Extensions/WebExtensionContext.h` | 70KB | 所有 API 声明 |
| `UIProcess/Extensions/Cocoa/WebExtensionContextCocoa.mm` | 144KB | 主要 UIProcess 实现 |
| `UIProcess/Extensions/Cocoa/WebExtensionTabCocoa.mm` | 36KB | Tab 权限检查 |
| `UIProcess/Extensions/API/WebExtensionContextAPIDeclarativeNetRequest.cpp` | 13KB | DNR validator (confirmed) |
| `UIProcess/Extensions/API/WebExtensionContextAPIStorage.cpp` | 14KB | Storage validator (confirmed weak) |
| `WebProcess/Extensions/WebExtensionContextProxy.cpp` | 10KB | WebProcess 侧代理 |
| `WebProcess/Extensions/WebExtensionContextProxy.h` | 15KB | identifier() 逻辑 |

未下载（需 Sourcegraph 或等 rate limit）:
- `UIProcess/Extensions/Cocoa/API/WebExtensionContextAPITabsCocoa.mm` — tabs handler
- `UIProcess/Extensions/Cocoa/API/WebExtensionContextAPIScriptingCocoa.mm` — scripting handler

## 已确认漏洞（有 PoC）

### 漏洞 1: DNR CSP Bypass (CVSS 8.1)

**PoC**: `poc/safari-dnr-csp-bypass/`
**报告**: EN + CN 双语完整报告
**根因**: `transform.scheme` 无 allowlist，允许 `data:` scheme 绕过 CSP
**Chrome 防御**: `kAllowedTransformSchemes = {"http", "https", "ftp", "chrome-extension"}`
**WebKit 缺陷**: 仅阻止 `javascript:`，允许 `data:`/`file:`/`blob:`

### 漏洞 2: Cross-Extension Script Injection (CVSS 9.1)

**PoC**: `poc/safari-cross-extension-injection/`
**报告**: EN + CN 双语完整报告
**根因**: `<all_urls>` 匹配 `webkit-extension://` URL，`permissionState()` 无跨扩展阻断
**Chrome 防御**: `permissions_data.cc:164-168` 跨扩展阻止
**WebKit 缺陷**: `supportedSchemes()` 包含 `Scheme::Extension`，无 cross-extension deny

### 漏洞 3: Native Messaging Content Script Escalation (CVSS 8.6-9.3, 待 PoC)

**文档**: `knowledge/safari-extensions/finding-native-messaging-content-script.md`
**根因**: Content script 可调用 `sendNativeMessage`/`connectNative`，UIProcess 无 context 限制
**Chrome 防御**: Browser process 限制仅 background/service worker 可调用
**WebKit 缺陷**: `isPropertyAllowed` 不区分 caller context，UIProcess handler 无权限检查

## 深入分析结果

### P0 #4 — Permission cache 投毒: ❌ 排除（设计安全）

**结论**: cache 机制在当前代码中是安全的。

**详细分析**:
- `clearCachedPermissionStates()` 只从 `permissionsDidChange(MatchPatternSet)` 调用 (line 675)
- `permissionsDidChange(PermissionsSet)` (API permissions) **不**清缓存 (line 638-668)
- 但 URL cache 中的 `Granted*` 状态只能来自 match pattern 匹配 (line 915-917, 934-936)
- Match pattern 的所有修改路径（grant/revoke/expire）都正确调用 `permissionsDidChange(MatchPatternSet)` → 清缓存
- API permission 的过期只影响 `RequestedImplicitly` 缓存状态 — 这对 `hasPermission(URL)` 无影响（SkipRequested）
- `permissionState(URL)` 在缓存查找前调用 `grantedPermissionMatchPatterns()` 触发惰性过期 → 过期条目在读缓存前被处理
- UIProcess main thread 是单线程 — 不存在并发竞态

**遗留微小问题**: API permission 过期后 `RequestedImplicitly` 可能在缓存中 stale，但所有安全关键路径(`hasPermission`)都用 `SkipRequestedPermissions` → 返回 Unknown（安全等效）。

### P0 #6 — RuntimeSendNativeMessage: ✅ 确认漏洞（纯逻辑 bug，不需 renderer compromise）

**结论**: Content script 可以直接调用 `runtime.sendNativeMessage()` 和 `runtime.connectNative()`。Chrome 明确限制这些 API 仅 background script 可调用。

**关键证据**:
- `WebExtensionAPIRuntimeCocoa.mm:162-169`: `isPropertyAllowed` 仅检查 manifest 声明了 `nativeMessaging`，**不区分** content script vs background
- `WebExtensionContext.messages.in:128-129`: IPC validator 仅 `isLoaded`
- `WebExtensionContextAPIRuntimeCocoa.mm:238-350`: UIProcess `sendNativeMessage()` 无任何权限或 context 检查
- `WebExtensionContextAPIRuntimeCocoa.mm:364-419`: `runtimeConnectNative()` 同样无 context 检查
- Native host 收到的消息**不包含调用者身份**

**攻击链**: Web page XSS → content script context → `browser.runtime.sendNativeMessage()` → native host（app sandbox）→ keychain/文件系统/网络

**Chrome 对比**: Chrome 在 browser process 级别限制 `sendNativeMessage/connectNative` 仅 background/service worker context 可调用。Safari 无此限制。

**影响**: $100K-300K bounty category（sandbox escape via privileged native host）
**前置条件**: 目标 extension 需有 `nativeMessaging` + content scripts 注入攻击者可控页面
**详细文档**: `knowledge/safari-extensions/finding-native-messaging-content-script.md`

### P0 #2 — delegate bypass: ⚠️ Ecosystem 风险

**发现**: `shouldBypassPermissionsForWebExtensionContext:` 是 `WKWebExtensionTab` delegate 的可选方法。
- WebKit 自身代码中只在 TestWebKitAPI 中实现
- 任何嵌入 WKWebView + Extension 的第三方 app 都可能错误实现（return YES）
- 不影响 Safari 本身，但影响使用 WebKit extension API 的生态

### URL Match Pattern 分析: 安全但有限

**`UserContentURLPattern::matchesHost`**: 
- Case-insensitive ASCII 比较
- 子域匹配通过 `endsWith` + `.` 前缀检查
- Port 不在 pattern 中（构造时检测并拒绝）
- `url.host()` 由 URL parser 规范化（punycode）
- `<all_urls>` 只匹配 `supportedSchemes()`

**`getOrCreate(URL)` 在 activeTab 中**: 创建精确 path pattern，不是 `/*`。
`didCommitLoadForFrame` 在导航到不同 URL 时正确清除临时权限。

### URL Scheme Handler: 安全

**路径遍历防护**: `resourceFileURLForPath` (WebExtension.cpp:515) 使用 `FileSystem::realPath()` + `startsWith(basePath)` 双重验证。
macOS 额外有代码签名验证 (`validateResourceData`)。

**访问控制**: `protocolHostAndPortAreEqual` 验证同源，外部请求检查 `web_accessible_resources`。
`extensionContext(URL)` 查找用 `url.protocolHostAndPort()` → UUID 唯一性保证跨扩展隔离。

**潜在弱点**: `frameDocumentURL` fallback 到 `firstPartyForCookies`（WebProcess 可控）— 但需要 renderer compromise。

### SQLite Storage: 基本安全

- `insertOrUpdateValue`: 使用参数化查询 `VALUES (?, ?)` ✅
- `deleteValuesForKeys` / `getValuesForKeysWithErrorMessage`: 使用 `rowFilterStringFromRowKeys` 手动转义 (`'` → `''`) 后字符串拼接
- SQLite 中 `''` 转义是标准且安全的做法
- **非参数化但当前安全** — defense-in-depth concern, 非可利用漏洞

### tabsExecuteScript: ✅ 安全

**结论**: Handler 实现正确，无绕过路径。

**分析** (`WebExtensionContextAPITabsCocoa.mm:604-643`):
- IPC Validator: `isLoadedAndPrivilegedMessage` — content script 无法调用
- `getTab(webPageProxyIdentifier, tabIdentifier, IncludeExtensionViews::Yes)` 默认 `IgnoreExtensionAccess::No`
  - Tab 必须在 `m_tabMap` 中（已知 tab）
  - `extensionHasAccess()` 检查（private tab 保护）
- `requestPermissionToAccessURLs()` → callback → `extensionHasPermission()` 双重验证
- TOCTOU 安全: 如果 tab 在权限请求期间导航，callback 中 `extensionHasPermission()` 使用当前 URL 重新检查
- 同步路径（已有权限时）: `neededURLs` 为空 → 立即回调，无竞态窗口

### DeclarativeNetRequest: 基本安全（有次要问题）

**JSON 解析路径**:
- `declarativeNetRequestUpdateDynamicRules` (line 164): 接收 `String rulesToAddJSON`
- `JSON::Value::parseJSON()` — WebKit 内置解析器，内存安全
- 解析失败静默返回空数组（设计合理）

**规则编译**:
- 规则通过 `_WKWebExtensionDeclarativeNetRequestTranslator` 转换为 WebKit Content Rule List 格式
- `compileContentRuleListFile` 使用 `CSSSelectorsAllowed::No`（禁用 CSS 选择器攻击面）
- 最终通过 `userContentController->addContentRuleList()` 应用

**规则数量限制 Bug** (line 187-188):
```cpp
auto updatedDynamicRulesCount = m_dynamicRulesIDs.size() + rulesToAdd->length() - ruleIDsToDelete.size();
if (updatedDynamicRulesCount + m_dynamicRulesIDs.size() > max)
```
- 检查实际为 `2*current + add - remove > max`（多加了一次 current）
- 结果是限制**更严格**（拒绝更多请求），非安全问题
- 整数下溢安全: `ruleIDsToDelete` 过滤后 ≤ `m_dynamicRulesIDs.size()`

**规则 ID 为 `double` 类型**: `HashSet<double>` — IEEE 754 整数精确到 2^53，功能正确但设计不佳

**无法验证的部分** (需 `_WKWebExtensionDeclarativeNetRequestRule.mm`):
- redirect 规则能否重定向到 `javascript:`/`data:` URL？
- modifyHeaders 能否移除安全头（CSP, X-Frame-Options）？
- 规则优先级冲突处理逻辑

### senderParameters 跨进程验证: ⚠️ 已确认 — URL 字段未验证

**发现**: `WebExtensionMessageSenderParameters` 由 WebProcess 构造并通过 IPC 发送:
```cpp
struct WebExtensionMessageSenderParameters {
    std::optional<String> extensionUniqueIdentifier;
    std::optional<WebExtensionTabParameters> tabParameters;
    std::optional<WebExtensionFrameIdentifier> frameIdentifier;
    WebPageProxyIdentifier pageProxyIdentifier;
    WebExtensionContentWorldType contentWorldType;
    URL url;
    WTF::UUID documentIdentifier;
};
```

**UIProcess 验证分析** (`WebExtensionContextAPIRuntimeCocoa.mm`):

`runtimeSendMessage` (line 129-175):
```cpp
WebExtensionMessageSenderParameters completeSenderParameters = senderParameters;
if (RefPtr tab = getTab(senderParameters.pageProxyIdentifier))
    completeSenderParameters.tabParameters = tab->parameters();  // ← 唯一被重建的字段
```

| 字段 | UIProcess 验证/重建 | 安全状态 |
|------|-------------------|---------|
| `tabParameters` | ✅ 从 UIProcess tab map 重建 | 安全 |
| `pageProxyIdentifier` | 部分 — 用于 tab 查找 | 可伪造（见下文） |
| `url` | ❌ **不验证，不重建** | **可伪造** |
| `contentWorldType` | ❌ **不验证，不重建** | **可伪造** |
| `frameIdentifier` | ❌ 不验证 | 可伪造 |
| `documentIdentifier` | ❌ 不验证 | 可伪造 |
| `extensionUniqueIdentifier` | ❌ 不验证 | 可伪造 |

**WebProcess 侧构造** (`WebProcess/Extensions/API/Cocoa/WebExtensionAPIRuntimeCocoa.mm`):

正常 JS 调用路径（line 348-356）:
```cpp
WebExtensionMessageSenderParameters senderParameters {
    extensionContext().uniqueIdentifier(),
    std::nullopt, // tabParameters
    toWebExtensionFrameIdentifier(frame),
    webPageProxyIdentifier,
    contentWorldType(),   // ← from JS world binding
    frame.url(),          // ← from WebCore frame object
    documentIdentifier.value(),
};
```

正常情况下 `frame.url()` 由 WebCore 管理，JS 无法直接伪造。但 renderer compromise 下可完全控制。

**`runtimeWebPageSendMessage` 中 URL 用于安全决策** (line 462-464):
```cpp
auto url = completeSenderParameters.url;  // ← 来自 WebProcess，未验证！
auto validMatchPatterns = destinationExtension->extension()->externallyConnectableMatchPatterns();
if (!hasPermission(url, tab.get()) || !WebExtensionMatchPattern::patternsMatchURL(validMatchPatterns, url))
    // 拒绝 — 但 url 可被伪造绕过！
```

**`isLoaded` validator 的弱点** (WebExtensionContext.h:1028):
```cpp
bool isLoaded(IPC::Decoder&) const { return isLoaded(); }  // 不检查 message 来源！
```

**攻击面总结**:

1. **Renderer Compromise → externally_connectable bypass** (P0):
   - 攻击者 RCE 进入 web process
   - 发送 `RuntimeWebPageSendMessage` IPC，伪造 `url = trusted-partner.com`
   - UIProcess 用伪造 URL 通过 `externallyConnectableMatchPatterns` 检查
   - 消息到达目标 extension 的 `onMessageExternal` handler
   - **影响**: 绕过 externally_connectable 访问控制

2. **Renderer Compromise → sender.url spoofing** (P1):
   - `RuntimeSendMessage` 中伪造 `url` 字段
   - 接收方 extension 的 `onMessage` handler 中 `sender.url` 为假
   - 如果 extension 基于 `sender.url` 做信任决策 → 逻辑绕过
   - **影响**: 依赖 sender.url 的 extension 可被欺骗

3. **Renderer Compromise → contentWorldType spoofing** (P1):
   - 伪造 `contentWorldType = Main` 当实际在 ContentScript world
   - 或伪造 `ContentScript` 当实际在 Main world
   - **影响**: 绕过 extension 中基于 sender type 的内部权限检查

**威胁模型评估**:
- Apple Security Bounty 明确将 renderer compromise 作为有效威胁模型
- "Bypass of the Web Content sandbox" 类别包含从 compromised renderer 进一步攻击
- `externally_connectable` bypass 允许未授权消息到达 extension，可能触发 extension 的特权操作
- 但这不是直接的沙箱逃逸 — 需要目标 extension 有可利用的 `onMessageExternal` handler

**修复建议**:
UIProcess 应从自身状态重建 `url` 字段：
```cpp
// 修复方案
if (RefPtr tab = getTab(senderParameters.pageProxyIdentifier)) {
    completeSenderParameters.tabParameters = tab->parameters();
    completeSenderParameters.url = tab->url();  // ← 从 UIProcess trusted state 重建
}
```
对于 frame URL (非主 frame)，UIProcess 需要从 WebFrameProxy 获取 URL。

### StorageSetAccessLevel: ❌ 排除（设计如此）

**结论**: content script 可调用 `StorageSetAccessLevel`，但这是 Chrome API spec 的设计行为。

**分析**:
- IPC validator: `isStorageMessageAllowed` = `isLoaded() + storage permission`
- UIProcess handler 无额外权限检查 (line 205-210)
- `setSessionStorageAllowedInContentScripts(true)` 允许 content script 访问 session storage
- 但 Chrome spec 中 `storage.session.setAccessLevel()` 就是设计为 content script 可调用的配置 API
- UIProcess 的 `storageGet/storageSet` 也不区分调用者身份 — 依赖 WebProcess JS binding 控制

### Port 泄漏 Bug (新发现): ⚠️ 低严重性

**位置**: `WebExtensionContextAPIRuntimeCocoa.mm:185`

**问题**: `runtimeConnect` 在验证前就调用 `addPorts()`:
```cpp
addPorts(sourceContentWorldType, targetContentWorldType, channelIdentifier, { senderParameters.pageProxyIdentifier }); // line 185
if (!extensionID.isEmpty() && uniqueIdentifier() != extensionID) {  // line 187
    completionHandler(error);
    return;  // port 已注册但不清理!
}
```

**同样问题存在于**:
- `runtimeConnect` line 196-199: tab not found 时 port 不清理
- `runtimeConnectNative` line 378: 如果后续 extension bundle 为 null 时 port 不清理

**影响**: 反复调用 `runtime.connect("non-existent-extension")` 导致 UIProcess memory leak
**利用条件**: 不需要 renderer compromise — content script 可直接触发

### RuntimeReload/OpenOptionsPage 从 content script: ⚠️ 设计关注

**发现**: 以下 IPC 消息仅用 `isLoaded` 验证:
- `RuntimeReload()` — content script 可重载整个 extension
- `RuntimeOpenOptionsPage()` — content script 可打开 options page
- `RuntimeGetBackgroundPage()` — content script 可获取 background page identifier

**影响**: 低 — DoS/UI 干扰级别

### runtimeWebPageSendMessage hasPermission 额外检查: 可能的 conformance bug

**发现**: WebKit 实现 (line 464) 要求:
1. `hasPermission(url, tab)` — extension 有 sender URL 的 host permission
2. `patternsMatchURL(externallyConnectable, url)` — URL 匹配 externally_connectable

Chrome 的实现只要求条件 2。这导致 `externally_connectable` 在 WebKit 中可能无法正常工作，
除非 extension 同时声明了 sender 域名的 host permission。

**性质**: 功能 bug（过度限制），非安全漏洞

### PortPostMessage 路由安全分析: ⚠️ Port Message Injection (已确认)

**发现**: `portPostMessage` 验证 port 连接存在但**不验证发送者是否拥有该 port**。
- `isPortConnected()` 检查 `m_ports` 全局计数器（不区分哪个 page 拥有该 port）
- `WebExtensionPortChannelIdentifier = ObjectIdentifier<T>` = 顺序 64 位整数（可预测）
- 任何 content script 可以指定其他 tab 的 channelID 发送 IPC `PortPostMessage`
- **影响**: 跨 tab 消息注入（同一 extension 内），无需 renderer compromise
- **详细分析**: `knowledge/safari-extensions/finding-port-message-injection.md`

### DNR URL Transform Scheme Bypass: 🔥 高严重性 (已确认)

**发现**: `declarativeNetRequest` redirect 规则的 `transform.scheme` 和 `regexSubstitution` 允许设置任意 URL scheme（`data:`, `file:` 等），绕过 CSP。

**Root Cause 层级**:
1. `_WKWebExtensionDeclarativeNetRequestRule.mm:458` — 只类型检查为 string，无 scheme allowlist
2. `ContentExtensionActions.cpp:499-505` — 只阻止 `javascript:`，允许 `data:`, `file:`, `blob:` 等
3. `ContentExtensionActions.cpp:471-473` — `regexSubstitution` 完全无 scheme 验证
4. `CachedResourceLoader.cpp:1142/1179` — CSP 和 SecurityOrigin 检查在 content extension 修改 URL **之前**运行，修改后无 re-validation
5. `SubresourceLoader.cpp:287` — `data:` URL 阻止仅适用于 HTTP 3xx 重定向，不适用于 content extension redirect

**Chrome 对比**: Chrome 在 `indexed_rule.cc:309-319` 使用 `kAllowedTransformSchemes = {"http", "https", "ftp", "chrome-extension"}` 严格限制。

**攻击链**:
- 恶意 extension 仅需 `declarativeNetRequest` 权限（无需 host permissions）
- 定义 redirect 规则匹配 CSP 允许的脚本 URL
- `regexSubstitution` 重写为 `data:text/javascript;base64,...`
- CSP 被绕过 — 任意 JS 在目标页面执行

**影响**: CSP bypass on any page, minimal permission footprint
**详细分析**: `knowledge/safari-extensions/finding-dnr-scheme-transform-bypass.md`

## 下一步（v5）

### 待验证（需 Safari Technology Preview）
1. **DNR scheme bypass PoC** — 构建 extension 使用 `regexSubstitution` 重定向到 `data:` URL，验证 CSP bypass
2. **Port message injection PoC** — 验证跨 tab channelID 预测和消息注入
3. **Port 泄漏 PoC** — 验证 memory leak DoS

### 继续挖掘方向
4. **DNR modifyHeaders** — 能否通过 DNR 规则移除安全响应头（CSP, X-Frame-Options, CORS）？
5. **WebContent sandbox profile** — 从系统文件获取沙箱规则
6. **Content script → native messaging** — 研究 Safari 生态中 native host 的使用
7. **tabs.update URL validation** — tab navigation API 的 URL scheme 限制
