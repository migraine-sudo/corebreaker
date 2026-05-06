# Extension Audit Rounds 4-6 Summary

## 审计目标
Chrome Extension 相关攻击面，深入审计 Round 1 排除后的备选方向

---

## Round 4: Side Panel API Dispatch Boundary — EXCLUDED

**位置:** `chrome/browser/extensions/side_panel_helper.h/cc` (Copyright 2026)

**假设:** `SidePanelHelper` 创建 `ExtensionFunctionDispatcher` 为 side panel WebContents 提供 dispatch 能力。如果恶意页面能注入到 side panel，则获得扩展权限。

**排除原因:** 攻击面不存在
1. `SidePanelHelper` 仅为 `SidePanelWebUIView` 创建（`side_panel_web_ui_view.cc:75`）
2. 只服务 `chrome://` 内容（WebUI），不服务 extension side panels
3. Extension side panels 通过 `ExtensionViewHost` + `extensions/browser/extension_host.cc` 管理
4. `SidePanelHelper` 只提供 `GetExtensionWindowController()` 方法，不暴露特权 API
5. 要利用需要先注入到 WebUI 进程 → 违反 Gate 3

---

## Round 5: externally_connectable + Extension Messaging — EXCLUDED

**位置:** `extensions/browser/api/messaging/message_service.cc:515-567`, `message_service_bindings.cc:80-161`

**假设:** Web page 通过 `externally_connectable` 向扩展发消息时，可能绕过 sender 验证或冒充其他来源。

**排除原因:** 3+ 层独立防御
1. **Browser-side sender URL 验证:** `GetLastCommittedURL()` 不可伪造（browser process 维护）
2. **IsValidMessagingSource 严格分类验证:**
   - `kExtension`: `CanRendererHostExtensionOrigin` 验证
   - `kContentScript`: `ScriptInjectionTracker::DidProcessRunContentScriptFromExtension` 验证
   - `kWebPage`: 强制 `extension_id` 为空
3. **ProcessMap 验证:** 确认进程确实属于声称的扩展
4. **externally_connectable URL matching:** browser-side使用不可伪造的 URL
5. **Feature flag `kCheckingNoExtensionIdInExtensionIpcs`:** ENABLED_BY_DEFAULT，阻止 web page 冒充扩展

**附加发现:** 新的 `message_serialization` manifest key (2026) 仅影响序列化格式（JSON vs structured clone），不影响安全验证。

---

## Round 6: DNR modifyHeaders Security Header Removal — EXCLUDED

**位置:** `extensions/browser/api/declarative_net_request/ruleset_manager.cc`, `indexed_rule.cc:516-558`

**假设:** DNR `modifyHeaders` response header REMOVE 操作无 header name 限制，可能允许绕过 host permission 移除安全头（CSP/HSTS/X-Frame-Options）。

### 深入分析

**Header 修改能力:**
- Request header `APPEND` 有 allowlist（`kDNRRequestHeaderAppendAllowList`）
- Response header `REMOVE/SET/APPEND` **无任何 header name 限制**
- 可以移除 CSP, HSTS, X-Frame-Options, CORS headers 等所有安全头
- 可以添加/设置任意 response header (包括 `Access-Control-Allow-Origin: *`)

**Host Permission 模型:**
- `declarativeNetRequest` 权限 → `HostPermissionsAlwaysRequired::kFalse`
  - Rules 评估不需要 host permissions（`DO_NOT_CHECK_HOST` 总是通过）
  - 但 modifyHeaders 实际执行需要 host permissions（`GetModifyHeadersActions` line 411 检查）
- `declarativeNetRequestWithHostAccess` 权限 → `HostPermissionsAlwaysRequired::kTrue`
  - Rules 评估和执行都需要 host permissions

**防御层分析:**
1. **Permission 安装时授权:** 用户必须安装扩展并授予 `declarativeNetRequest` + host permissions
2. **Host permission 检查:** `GetModifyHeadersActions` (ruleset_manager.cc:411) 对 `page_access == kDenied` 的请求跳过
3. **Cross-extension 保护:** 其他扩展的 sub-frame 请求不受 DNR 影响 (line 561-571)
4. **Sensitive URL 保护:** WebStore, SafeBrowsing, chrome://, WebUI 请求对扩展隐藏
5. **Runtime host permission 模型:** `REQUIRE_HOST_PERMISSION_FOR_URL_AND_INITIATOR` 确保只对已授权 URL 生效

**排除原因:** 设计正确
1. 无 header name 限制是**有意设计**，与 MV2 webRequest blocking 能力等价
2. Host permission 模型正确阻止对未授权 URL 的修改
3. 需要用户安装扩展 + 授予权限 → 违反 Gate 3（需安装恶意扩展）
4. Sub-resource "initiator grants access" 行为是有意的 webRequest 兼容设计（有明确注释和 bug 追踪）

**调查过的潜在绕过路径（均失败）:**
- DNR 影响 CORS 预检: 需要 host permission for target URL → blocked
- Cross-extension DNR 干扰: `ShouldEvaluateRulesetForRequest` line 561-571 明确阻止
- Service Worker fetch 交互: DNR 无 SW 特殊处理，走相同 host permission 路径
- Tab-specific permission escalation: `GetPageAccess(url, tab_id)` 正确检查

---

## 综合结论

Extension 子系统 6 个审计方向全部排除。核心发现：

### Chrome Extension 安全模型的健壮性
1. **多层独立防御:** 每个子系统都有 2-4 层独立的安全检查
2. **Browser-side 权威验证:** 所有关键安全决策在 browser process 执行，不信任 renderer
3. **Permission 模型一致性:** 无论通过 webRequest 还是 DNR，host permission 检查逻辑一致
4. **Cross-component 隔离:** Extension 间互不影响（ProcessMap, cross-extension protection）

### 为什么这些方向不可行
| 方向 | 核心阻碍 |
|------|----------|
| Navigation throttle | 4层防御，webview 仅 platform_app |
| Offscreen document | kOffscreenExtension 正确限制 API 访问 |
| SW permission race | Renderer-level update 不依赖 worker 活跃 |
| Side Panel dispatch | SidePanelHelper 仅服务 WebUI |
| Messaging sender | Browser-side GetLastCommittedURL 不可伪造 |
| DNR modifyHeaders | Host permission 正确守门 |

---

## 下一步建议

放弃 Extension 核心子系统（安全模型过于成熟）。建议转向：

1. **Extension + Privacy Sandbox 交互** — extension 对 Fenced Frame/Protected Audience 请求的 DNR 规则行为（新交叉域）
2. **Extension + WebNN/AI API** — permission delegation 到 AI worklets（2026 新代码）
3. **Extension install 时序** — CRX 下载 + 验证之间的 TOCTOU（CVE-2024-0333 表明此类仍在出）
4. **完全换方向** — 回到主审计计划 (CLAUDE.md Priority List)：
   - SAA "Beyond Cookies" StorageAccessHandle
   - ServiceWorker Static Router
   - Speculation Rules / Prerender activation
