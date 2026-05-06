# Safari Web Extensions IPC Attack Surface

## Architecture Overview

```
WebContent Process (attacker-controlled)          UI Process (privileged)
┌──────────────────────────────┐      IPC       ┌─────────────────────────────┐
│ WebExtensionContextProxy     │ ──────────────→ │ WebExtensionContext         │
│   m_unprivilegedIdentifier   │                │   m_privilegedIdentifier    │
│   m_privilegedIdentifier(?)  │                │   isPrivilegedMessage()     │
│                              │                │   isLoaded()                │
│ Sends IPC with destinationID │                │   Validator checks          │
│ = identifier()               │                │                             │
└──────────────────────────────┘                └─────────────────────────────┘
```

## Privileged Identifier Mechanism

### How it works:
1. UIProcess 为每个 extension context 生成两个 identifier:
   - `unprivilegedIdentifier` — 给所有页面（包括 content scripts）
   - `privilegedIdentifier` — 仅给特权页面（background, popup, tab pages）

2. WebProcess 发送 IPC 时，`destinationID` = `identifier()`:
   ```cpp
   // WebExtensionContextProxy.h:76
   WebExtensionContextIdentifier identifier() const { 
       return m_privilegedIdentifier ? *m_privilegedIdentifier : m_unprivilegedIdentifier; 
   }
   ```

3. UIProcess 验证:
   ```cpp
   // WebExtensionContext.cpp:1622-1627
   bool WebExtensionContext::isPrivilegedMessage(IPC::Decoder& message) const {
       if (!m_privilegedIdentifier)
           return false;
       return m_privilegedIdentifier.value().toRawValue() == message.destinationID();
   }
   ```

### Key Security Decision:
- `dispatchDidLoad()` sends `IncludePrivilegedIdentifier::No` → content scripts 不得 privilegedIdentifier
- 特权页面（background/popup/tab）在创建时应该收到 `IncludePrivilegedIdentifier::Yes`

### ATTACK VECTOR #1: privilegedIdentifier 分发逻辑
**问题**: 需要确认哪些代码路径会传递 `IncludePrivilegedIdentifier::Yes`。
如果有任何从 content script 可达的路径能获取到 privilegedIdentifier，
整个 Tabs/Windows API 的保护就被绕过。

**需要验证的文件**（不在当前下载中，需要额外下载）：
- WebExtensionContext 中设置 background page / popup page 的代码
- `WebExtensionControllerProxy::getOrCreate` 接收参数时的处理

## IPC Message Classification (120 messages total)

### Tier 1: WEAK — `isLoaded` only (19 messages)
**任何已加载 extension 的任何 context（包括 content script）都能发送**

| Message | Security Impact |
|---------|----------------|
| `RuntimeSendMessage` | 触发 background page 的 onMessage，可携带任意 JSON |
| `RuntimeConnect` | 打开到 background page 的持久 port |
| `RuntimeSendNativeMessage` | **直达 native messaging host app** |
| `RuntimeConnectNative` | 打开到 native app 的持久 port |
| `RuntimeWebPageSendMessage` | 网页→扩展消息（externally_connectable） |
| `RuntimeWebPageConnect` | 网页打开到扩展的 port |
| `PortPostMessage` | 跨 content world 发送数据 |
| `PermissionsRequest` | **运行时请求新权限** |
| `PermissionsRemove` | 移除权限（DoS） |
| `RuntimeReload` | 重新加载扩展 |
| `RuntimeGetBackgroundPage` | 获取 background page ID |
| `AddListener` / `RemoveListener` | 注册/移除事件监听 |
| `DidEncounterScriptError` | 报错（信息泄露？） |

### Tier 2: STRONG — `isLoadedAndPrivilegedMessage` (26 messages)
**只有 background page, popup, tab pages 能发送**

| API Group | Messages | Impact |
|-----------|----------|--------|
| Tabs | Create/Update/Duplicate/Get/Query/Remove/ExecuteScript/... | 完全控制浏览器标签页 |
| Windows | Create/Get/GetAll/Update/Remove | 控制窗口 |
| TabsCaptureVisibleTab | 截取可见标签页截图 | 隐私数据 |
| TabsExecuteScript | 向任意标签页注入脚本 | **RCE in renderer** |

### Tier 3: MEDIUM — Per-API permission validators (75 messages)
需要 manifest 中声明对应权限，但 context 不限制（content script 也可发送）

| Validator | Count | Key Risk |
|-----------|-------|----------|
| `isDeclarativeNetRequestMessageAllowed` | 9 | 操纵网络请求规则 |
| `isScriptingMessageAllowed` | 7 | 注入脚本（另一个 executeScript 入口） |
| `isCookiesMessageAllowed` | 5 | 读写 cookies |
| `isStorageMessageAllowed` | 7 | 读写扩展存储 |
| `isBookmarksMessageAllowed` | 11 | 读写书签 |
| `isDevToolsMessageAllowed` | 3 | DevTools 面板 + **eval in inspected page** |

## Top Attack Vectors (Ranked)

### 1. Privileged Identifier Leak/Forge (CRITICAL)
- If content script can obtain the privilegedIdentifier, all Tabs/Windows APIs become accessible
- Attack surface: memory disclosure, race condition during context parameter delivery, identifier prediction

### 2. `RuntimeSendNativeMessage` from Content Script (HIGH)
- Content script CAN send native messages (only `isLoaded` validator)
- If native messaging host trusts all messages from the extension without distinguishing caller context → privilege escalation to native code
- Safari-specific: unlike Chrome, no separate "nativeMessaging" permission check at IPC level?

### 3. `PermissionsRequest` from Content Script (HIGH)
- Content script can call `PermissionsRequest` (weak validator)
- Question: does UIProcess show a prompt? Or can it be auto-granted for optional_permissions?
- Race condition: request permission → use permission before UI catches up?

### 4. `DevToolsInspectedWindowEval` (HIGH)
- Executes arbitrary JS in the inspected page
- Only needs `isDevToolsMessageAllowed` (permission check, not privileged check)
- If a DevTools extension content script context can reach this → execute in any page

### 5. `ScriptingExecuteScript` vs `TabsExecuteScript` inconsistency (MEDIUM-HIGH)
- `ScriptingExecuteScript` uses `isScriptingMessageAllowed` (permission only)
- `TabsExecuteScript` uses `isLoadedAndPrivilegedMessage` (privileged)
- **Both execute scripts!** But different validators. Is the permission check in Scripting API sufficient?

### 6. DeclarativeNetRequest Rule Injection (MEDIUM)
- `DeclarativeNetRequestUpdateDynamicRules` / `UpdateSessionRules` accept JSON
- JSON parsing bugs? Rules that redirect sensitive URLs? Rules that disable other extensions' rules?

### 7. Port Message Content World Confusion (MEDIUM)
- `PortPostMessage` specifies `sourceContentWorldType` AND `targetContentWorldType`
- Attacker controls both fields from WebProcess side
- Can content script claim to be from Main world? Can it target a world it shouldn't access?

## Files for Deep Audit

| Priority | File | Why |
|----------|------|-----|
| P0 | `WebExtensionContext.cpp:1615-1627` | privilegedIdentifier generation & validation |
| P0 | Callers of `parameters(IncludePrivilegedIdentifier::Yes)` | Who gets the privileged ID |
| P0 | `WebExtensionContextProxy.h:76` | `identifier()` selection logic |
| P1 | Native messaging handler (not downloaded yet) | Trust boundary with host app |
| P1 | `ScriptingExecuteScript` handler | World parameter validation |
| P1 | `PortPostMessage` handler | Content world type validation |
| P2 | DNR rule JSON parser | Complex input parsing |
| P2 | `PermissionsRequest` handler | Auto-grant logic |
