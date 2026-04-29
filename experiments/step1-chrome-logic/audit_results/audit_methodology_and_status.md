# Chrome 逻辑漏洞审计 — 方法论与状态记录

> 最后更新: 2026-04-27 (Round 13: Service Worker + Interest Group + Navigation Controller + CPSP)

## 一、审计方法论

### 核心思路

**从已修复的安全 CL 中提取漏洞 pattern → 在 Chromium 源码中搜索同类未修复问题**

三层流程：
1. **Pattern 提取**: 从 Gerrit 抓最近合入的安全修复 CL，分析 diff 提取 bug 模式
2. **系统性搜索**: 对每个 pattern 转化为 grep 命令，在 shallow clone 的源码中批量搜索
3. **逐个验证**: 分析上下文、评估可利用性、写 VRP 报告

### 已提取的 13 个 Pattern

| # | 模式 | 搜索性 | 优先级 | 审计状态 |
|---|------|--------|--------|---------|
| 1 | DCHECK-only 保护安全属性 | 高(grep) | 最高 | **已完成** — Finding 001 |
| 2 | 新 API 方法缺少已有权限检查 | 高(grep) | 最高 | **已完成** — Finding 004 |
| 3 | Android Intent sender 未验证 | 高(grep) | 高 | 待执行 |
| 4 | 错误字符串依赖（DevTools） | 中 | 高 | 待执行(源码不在 clone 中) |
| 5 | Frame tree 遍历不完整 | 中 | 中 | 未执行 |
| 6 | 回调 reentrant 竞态 | 低 | 中 | 未执行 |
| 7 | renderer 3PCD 策略绕过 | 中 | 中 | 未执行 |
| 8 | UI 快捷键绕过策略 | 低 | 低 | 未执行 |
| 9 | 下载恢复 hash 不同步 | 中 | 高 | 已查看，修复已合入 |
| 10 | Autofill refill 绕过 reauth | 中 | 高 | 已修复，不可报告 |
| 11 | Worker WebSocket cookie 语义 | 中 | 中 | Flag 默认关闭，已知 |
| 12 | Worker 跨域 script URL | 中 | 中 | 正在修复中 |
| 13 | CORP request vs response URL | 中 | 高 | Flag 默认关闭，已知 |

### 方法论评估

**优点**:
- 系统化、可重复
- Pattern 2（权限一致性）产出了唯一有价值的 Finding 004

**缺点**:
- 产出效率低 — 大量审计，真正可报告的只有 1 个
- 太被动 — Chromium 团队自己也做同样的 pattern 扫描
- 搜索已修复 pattern 的残留，很多已被团队发现并在修
- 缺少动态验证

### 方向调整（2026-04-27）

**转向更新/更冷的代码区域**，理由：
- 新功能代码审计人数少，更容易找到首发漏洞
- Privacy Sandbox、AI API、Direct Sockets 等都是 2024-2026 新加的
- 不再依赖已知 pattern，而是从攻击面出发完整审计

---

## 二、Findings 汇总

### Finding 001: DCHECK password manager 不完整修复

- **文件**: `credential_manager_impl.cc:325`, `password_manager.cc:698,714`
- **问题**: CVE-2026-6312 修了一个 DCHECK→runtime check，漏了 3 个同类
- **可利用性**: 极低（TOCTOU 窗口内条件不可控，IsOffTheRecord 不可变）
- **VRP 报告**: `vrp_report_dcheck_password_incomplete_fix.md`
- **预期评级**: Low
- **详细分析**: `finding_001_dcheck_password_manager.md`, `finding_001_risk_assessment.md`

### Finding 002: 新发现的 4 个漏洞 Pattern

- **来源**: 2026-04-13 ~ 2026-04-27 的安全修复 CL
- **内容**: Autofill refill reauth bypass / Worker WebSocket cookie / Worker 跨域 script / CORP URL 混淆
- **VRP 价值**: 全部已知或正在修复，接近零
- **参考价值**: Pattern 10-13 可用于未来审计
- **详细分析**: `finding_002_new_patterns.md`

### Finding 003: SW Static Router 安全检查系统性缺陷

- **问题**: 3 个安全检查被 feature flag 默认关闭
- **VRP 价值**: 零 — Chromium 团队已知并在逐步启用
- **详细分析**: `finding_003_sw_static_router_security.md`

### Finding 004: AdAuctionServiceImpl Permission Policy Bypass ⭐

- **文件**: `content/browser/interest_group/ad_auction_service_impl.cc:558-591`
- **问题**: `deprecatedReplaceInURN` 和 `deprecatedURNToURL` 缺少 `run-ad-auction` Permission Policy 检查
- **影响**: 任何 cross-origin iframe 可篡改 Fenced Frame URL 映射 / 泄露广告 URL
- **攻击条件**:
  1. 需要知道 URN UUID（随机值，需要通过某种方式获取）
  2. 攻击者 iframe 必须在同一页面上
  3. URL 中必须包含可替换的宏占位符（`${...}` 或 `%%...%%`）
  4. `AllowURNsInIframes` 必须启用（当前默认启用）
- **可利用性**: Low-Medium
- **VRP 报告**: `vrp_report_ad_auction_permission_bypass.md`
- **预期评级**: Medium
- **这是目前最有价值的发现**

### Finding 005: AI API (AIManager) Proofreader/Classifier Permission Policy 缺失

- **文件**: `chrome/browser/ai/ai_manager.cc:672-701` (Proofreader), `:933-974` (Classifier)
- **问题**: `CanCreateProofreader`/`CreateProofreader` 和 `CanCreateClassifier`/`CreateClassifier` 缺少 Permission Policy 检查。代码有明确 TODO: `crbug.com/466425250` 和 `crbug.com/499365168`
- **模式**: `IsBlocked()` 无参数调用只检查 pref，不检查 PP；其他 AI 方法都传入 PP feature 参数
- **影响**: 第三方 iframe 可以在 PP 被禁止的情况下使用 Proofreader/Classifier AI 功能
- **可利用性**: Low-Medium（需要 Chrome AI 模型已下载）
- **Chromium 已知**: TODO 注释有 crbug 链接
- **VRP 价值**: Low — 团队已知但未修复
- **详细分析**: `finding_005_ai_api_permission_policy_gap.md`

### Finding 006: Direct Sockets API TCPServerSocket + Worker PP 缺失

- **文件**: `content/browser/direct_sockets/direct_sockets_service_impl.cc:616-657`
- **问题 1**: `OpenTCPServerSocket` 缺少 `RequestPrivateNetworkAccessAndCreateSocket` 检查，其兄弟方法都有。Server socket 必然绑定到本地地址，但跳过了 private network access 权限
- **问题 2**: SharedWorker/ServiceWorker 创建路径跳过 `kDirectSockets`、`kDirectSocketsPrivate`、`kMulticastInDirectSockets` PP 检查（TODO: `crbug.com/393539884`）
- **影响**: IWA 可以不经 private network 权限检查监听本地端口
- **可利用性**: Low（仅限 IWA，攻击者需让受害者安装恶意 IWA）
- **VRP 价值**: Low — IWA 限制 + 部分已知
- **详细分析**: `finding_006_direct_sockets_security.md`

### Finding 007: Digital Credentials API — 缺少 Browser 端 User Activation 检查 ⭐⭐

- **文件**: `content/browser/digital_credentials/digital_identity_request_impl.cc:448-540`
- **问题**: `Get()` 和 `Create()` 方法缺少 browser 端 transient user activation 检查。User activation 验证仅在 renderer 侧（`digital_identity_credential.cc:273`）
- **影响**: Compromised renderer 可以无需用户交互触发 Digital Credential 请求。对于满足 interstitial bypass 条件的请求（年龄验证、DPC），可以完全无 UI 提示地调用 platform wallet
- **可利用性**: Medium（需要 compromised renderer，但这是标准 Chromium 威胁模型）
- **Chromium 已知**: 无 TODO 注释，可能未知
- **VRP 价值**: Medium — 标准的 renderer-only security check 模式漏洞
- **预期评级**: Medium
- **这是目前第二有价值的发现**
- **详细分析**: `finding_007_digital_credentials_user_activation.md`

### Finding 008: Compute Pressure — Worker 绕过 Fenced Frame 限制

- **文件**: `content/browser/worker_host/dedicated_worker_host.cc:987`, `shared_worker_host.cc:784`
- **问题**: Worker 绑定路径不检查 `IsNestedWithinFencedFrame()`，frame 路径有此检查且用 bad_message 终止 renderer
- **影响**: Fenced frame 内的 worker 可能访问 Compute Pressure API，违反 spec
- **可利用性**: Low（需要确认 fenced frame 能创建 worker，信息粗粒度）
- **详细分析**: `finding_008_compute_pressure_fenced_frame_bypass.md`

### Finding 009: Web Install API — Browser 端 user_gesture 硬编码为 true

- **文件**: `chrome/browser/web_applications/web_install_service_impl.cc:587-594`
- **问题**: `RequestPermissionsFromCurrentDocument` 调用时 `user_gesture=true` 硬编码，而非检查 `HasTransientUserActivation()`
- **影响**: Compromised renderer 可以绕过 user activation 检查安装 web app。权限系统将其视为有 gesture 的请求
- **可利用性**: Low（Web Install API 是 origin trial，非默认启用；需要 compromised renderer）
- **VRP 价值**: Low — origin trial 限制 + compromised renderer 前提

### Finding 010: Contacts Picker — Browser 端零验证

- **文件**: `content/browser/contacts/contacts_manager_impl.cc:69-85`
- **问题**: `Select()` 方法完全没有安全检查（无 user activation、无 permission、无 fenced frame check），直接调用 platform provider
- **影响**: Compromised renderer 可以不经用户交互触发系统联系人选择器 UI
- **可利用性**: Low（仅 Android 有 provider；联系人选择器本身需要用户手动选择）
- **VRP 价值**: Low — 平台限制 + 需要 compromised renderer

### Finding 012: WebAuthn Report (Signal) API 缺少 Permission Policy 检查

- **文件**: `content/browser/webauth/webauth_request_security_checker.cc:139-142`
- **问题**: `ValidateAncestorOrigins` 对 `RequestType::kReport` 直接返回 SUCCESS，跳过所有 permission policy 检查。TODO: `crbug.com/347727501`
- **影响**: 跨域 iframe 可以调用 Signal API（SignalAllAcceptedCredentials/UpdateUserPasskeys/PasskeyUnrecognized）。Signal API 可以删除或修改用户的 passkey
- **限制**: RP ID 验证仍在（caller origin 必须是 RP ID 的 registrable suffix），攻击者 iframe 必须来自目标 RP 域
- **可利用性**: Low（RP ID 验证 + 需要在目标域下有 iframe 内的代码执行权）
- **Chromium 已知**: 有 TODO 和 crbug 链接
- **VRP 价值**: Low-Medium — 已知但未修复，spec compliance issue

### Finding 011: _unfencedTop 信任 renderer 提供的 user_gesture

- **文件**: `content/browser/renderer_host/render_frame_host_impl.cc:1037-1053`
- **问题**: `ValidateUnfencedTopNavigation` 中的 user activation 检查依赖 renderer IPC 中的 `params->user_gesture`。代码有明确 TODO: `crbug.com/40091540`
- **影响**: Compromised fenced frame renderer 可以不经用户交互导航 top-level frame
- **可利用性**: Medium（需要 compromised renderer + fenced frame 环境）
- **Chromium 已知**: 有 TODO 注释

### Finding 013: ExtensionNavigationRegistry::CanRedirect Dead-Code Logic Bug ⭐⭐

- **文件**: `extensions/browser/extension_navigation_registry.cc:85-89`
- **问题**: `if (metadata.extension_id == extension.id()) { return true; } return true;` — 无论 extension_id 是否匹配都返回 true
- **影响**: 任何拥有 `webRequest` 或 `declarativeNetRequest` 权限的扩展可以 redirect 到其他扩展的非 web-accessible 资源
- **可利用性**: Medium-High（不需要 compromised renderer）
- **Chromium 已知**: 有 TODO (crbug.com/40060076) 但描述的是"验证 WAR 访问"，不是 return 值 bug
- **VRP 报告**: `vrp_report_extension_navigation_registry_bypass.md`
- **这是审计中最有价值的发现**

### Finding 014: DNR Redirect to Cross-Extension Resources (Amplifies Finding 013)

- **文件**: `extensions/browser/api/declarative_net_request/indexed_rule.cc:368-379`
- **问题**: DNR redirect.url 可以指向 `chrome-extension://other-id/...`，无跨扩展 URL 校验
- **影响**: 与 Finding 013 组合，`declarativeNetRequest` 权限（比 `webRequestBlocking` 更常见）可用于跨扩展资源访问
- **可利用性**: 同 Finding 013

### Finding 023: Gamepad API Browser 端完全缺失 Permission Policy 检查 ⭐⭐⭐

- **文件**: `device/gamepad/gamepad_monitor.cc:25-29`, `device/gamepad/gamepad_haptics_manager.cc:20-25`
- **问题**: `GamepadMonitor::Create()` 和 `GamepadHapticsManager::Create()` 完全忽略 `RenderFrameHost*` 参数。Browser 端零安全检查。事件监听器注册路径 (`DidAddEventListener`) 也无 PP 检查
- **影响**: 
  - 被 PP 禁止的跨域 iframe 可以通过 `addEventListener('gamepadconnected')` 接收 gamepad 输入数据
  - Fenced frame 中的代码可以完全使用 Gamepad API
  - 包括 haptics 振动
- **可利用性**: **High — 不需要 compromised renderer！纯 JavaScript PoC**
- **Chromium 已知**: 无 TODO 注释，可能完全未知
- **VRP 报告**: `vrp_report_gamepad_permission_policy_bypass.md`
- **预期评级**: Medium-High
- **这是审计中最有价值的发现**

### Finding 019: DisplayMediaAccessHandler DLP Bypass ⭐⭐

- **文件**: `chrome/browser/media/webrtc/display_media_access_handler.cc:789-793`
- **问题**: `OnDlpRestrictionChecked()` 中 `RejectRequest()` 后缺少 `return`，导致 `AcceptRequest()` 无条件执行
- **影响**: 排队的第二个 `getDisplayMedia()` 请求被用 DLP 拒绝的 media_id 自动批准
- **可利用性**: Medium（仅 ChromeOS，需要 DLP 策略配置 + 两个排队请求）
- **Chromium 已知**: 无 — 似乎是未被发现的 bug
- **VRP 报告**: `vrp_report_display_media_dlp_bypass.md`
- **这是审计中第二有价值的发现**

---

## 三、已审计区域

### 已完成

| 区域 | 审计方法 | 结果 |
|------|---------|------|
| password_manager DCHECK | grep + 手动分析 | Finding 001 (Low) |
| 15+ Mojo HostImpl 权限一致性 | 逐接口方法对比 | Finding 004 (Medium) |
| IsBlockedByHeaderValue 调用点 | grep 所有调用 | 只有已知 SW 路径有问题 |
| Worker WebSocket/WebTransport | 逐 worker 类型对比 | SharedWorker 有问题(已知) |
| Download hash 状态同步 | 代码审查 | 修复已合入 |
| SerialService/HidService PP | 绑定层检查 | 安全 |
| navigation_request DCHECK | grep | 已知 TODO (crbug/497761255) |
| FencedFrame HTTPS DCHECK | 手动 | 攻击面有限 |
| ServiceWorker static router | 完整审计 | Finding 003 (已知) |
| WebAuthn RP ID 验证 | 快速审查 | 多层验证，安全 |
| **AI API (AIManager)** | 逐方法 PP 检查对比 | **Finding 005** (Low-Medium) |
| **Direct Sockets API** | 完整审计（sub-agent） | **Finding 006** (Low) |
| Browsing Topics API | 完整审计 | 安全（仅 1 方法，检查完整） |
| WebNN/ML API | 绑定层+IDL 审查 | 无 PP（spec 不定义 PP），非 bug |
| WebBluetooth API | 逐方法检查 | 安全（GetBluetoothAllowed 统一检查） |
| FedCM/WebID | 逐方法检查 | 安全（3 处 PP 检查一致） |
| WebAuthn Signal Report | 安全检查审查 | 无 PP (TODO crbug/347727501)，但影响有限 — RP ID 验证仍在 |
| Attribution Reporting | 完整审计（sub-agent） | 安全（集中式 SuitableContext 工厂方法） |
| Private Aggregation | 完整审计（sub-agent） | 安全（仅 browser-side worklet 可绑定） |
| Serial API | DCHECK + 绑定层 | 安全（绑定层有 runtime PP check） |
| **Digital Credentials API** | 完整审计（sub-agent） | **Finding 007** (Medium) ⭐ |
| **Compute Pressure API** | 完整审计（sub-agent） | **Finding 008** (Low-Medium) |
| Device Posture API | 快速审查 | 安全（无敏感数据） |
| File System Access | TODO 审查 | 安全（权限粒度优化 TODO，非漏洞） |
| Child Process Security Policy | TODO 审查 | 深层架构问题，非 VRP 范围 |
| **User Activation 系统性对比** | renderer/browser 交叉对比 | Finding 009-010（需 compromised renderer） |
| **Navigation/Redirect 安全边界** | 完整审计（sub-agent） | Finding 011 + 多个 known TODOs |
| **PostMessage/IPC 来源检查** | 完整审计（sub-agent） | 安全（browser-controlled origin/StorageKey） |
| **StorageAccessHandle** | DCHECK_IS_ON 审查 | Low — debug-only ReportBadMessage |
| **Cookie Partitioning/CHIPS** | 完整审计（sub-agent） | 安全（partition key 计算正确） |
| **Clipboard API** | browser-side check 审查 | 安全（需 compromised renderer 绕过） |
| **WebAuthn/Credential Mgmt** | 完整审计（sub-agent） | **Finding 012** (Low-Medium，已知) |
| **Payment Handler API** | 完整审计（sub-agent） | 安全（origin 正确隔离） |
| **Notification/Push API** | 完整审计（sub-agent） | 安全（origin 绑定在 construction 时） |
| **SharedWorker WebSocket/Transport** | 完整审计（sub-agent） | 安全（worker StorageKey origin） |
| **Prerender/Speculation Rules** | TODO 审查 | 已知 TODO（user activation propagation） |
| **Extension NavigationRegistry** | 完整审计（手动+sub-agent） | **Finding 013** ⭐⭐ dead-code logic bug |
| **Extension DNR redirect** | 完整审计（sub-agent） | **Finding 014** — DNR amplification of Finding 013 |
| **Extension incognito isolation** | 完整审计（sub-agent） | **Finding 015** — shared blocked requests (已知 crbug/40279375) |
| **Extension storage access** | 完整审计（sub-agent） | **Finding 017** — unused validation function (已知) |
| **Extension script injection** | 完整审计（sub-agent） | **Finding 018** — empty-URL subframe bypass (Low) |
| **Service Worker lifecycle** | 完整审计（sub-agent） | DCHECK-only scope/StorageKey validation |
| **Cache Storage** | 完整审计（sub-agent） | 安全（origin check after binding, low risk） |
| **Background Fetch** | 完整审计（sub-agent） | 不完整 CORS（已知 crbug/40515511），无 PP |
| **WebRTC/MediaStream** | 完整审计（sub-agent） | **Finding 019** ⭐⭐ DLP bypass (ChromeOS) |
| **DisplayCapture PP in content layer** | 完整审计（sub-agent） | Missing kDisplayCapture PP in content layer |
| **Blob URL** | 完整审计（sub-agent） | 分区绕过需要知道 UUID |
| **File System Access** | 完整审计（sub-agent） | 安全（权限重新验证正确） |
| **Fenced Frame focus/isolation** | 完整审计 | kFencedFramesEnforceFocus DISABLED_BY_DEFAULT |
| **Dead-code pattern 全局搜索** | 自动化脚本 | 仅找到 Finding 013 + hats_service（非安全） |
| **Gamepad API** | 完整审计（sub-agent+手动验证） | **Finding 023** ⭐⭐⭐ Browser 端完全无 PP 检查，不需要 compromised renderer! |
| **Generic Sensor API** | 完整审计（sub-agent） | 安全（GetSensor 有 PP 检查，IsFeatureEnabled 正确） |
| **WebTransport API** | 完整审计（sub-agent） | 无 PP（与 WebSocket 一致，信息级）；Fenced Frame 无限制（低） |
| **Screen Wake Lock API** | 完整审计（sub-agent） | PP 缺失但权限系统兜底，影响有限 |
| **Idle Detection API** | 完整审计（sub-agent） | 安全（绑定时+方法调用时双重检查） |
| **Screen Orientation API** | 完整审计（sub-agent） | sandbox flag 仅渲染器端检查（低） |
| **Web Locks API** | 完整审计（sub-agent） | 安全（StorageKey 隔离正确） |
| **Storage Access API** | 完整审计（sub-agent） | DCHECK_IS_ON 包裹 ReportBadMessage（已知） |
| **Controlled Frame API** | 快速审查 | 媒体权限缓存在检查前填充（低，仅 IWA） |
| **Permission Service** | 快速审查 | 安全（browser 端 HasTransientUserActivation 正确使用） |
| **Window Management** | 快速审查 | 安全（IsWindowManagementGranted 检查正确） |
| **AdAuction PP inconsistency** | TODO 审查 | 已知 crbug/382786767（PP 不一致问题） |
| **Extension MV3 APIs** | 完整审计（sub-agent） | DNR regexSubstitution DCHECK-only scheme check；userScripts CSP 不验证 |
| **WebGPU/WebCodecs** | 完整审计（sub-agent） | 无 PP feature（设计层面），VideoFrame taint tracking 缺陷 |
| **CDP 安全检查** | 完整审计（sub-agent） | SetBypassCSP 无 trust check，AttachToTarget 无 target 验证（已知 TODO） |
| **Shape Detection API** | 快速审查 | 不接受 RFH，仅处理传入数据，安全 |
| **Vibration API** | 快速审查 | 无 PP feature（设计如此） |
| **PP browser-side 系统性检查** | 全部 108 个 feature | 24 个无 browser-side check，大多设计如此或不需要 |
| **WebID/FedCM delegation** | TODO 审查 | 多个安全 TODO（email verification, SD-JWT validation），功能较新 |

### 未审计 / 待执行

| 区域 | 优先级 | 理由 |
|------|--------|------|
| Android Intent 验证 | 中 | Pattern 3，需要 Java 代码审计 |
| DevTools 前端 | 低 | 源码不在 shallow clone (blob filter) |

---

## 四、工具与环境

- **Chromium 源码**: shallow clone (`--depth=1 --filter=blob:none`)，约 2 GB
  - 路径: `experiments/step1-chrome-logic/chromium-src/`
  - 注意: DevTools 前端、部分大文件可能不在 clone 中
- **Gerrit API**: 通过代理 `127.0.0.1:7890` 访问
  - 已抓取 172 个安全修复 CL
- **搜索工具**: grep + 手动代码审查
- **验证**: 纯静态审计，未在 Chrome 中运行 PoC

---

## 五、下一步计划

### Round 1 完成

1. ~~AI API 完整审计~~ → Finding 005
2. ~~Direct Sockets API 审计~~ → Finding 006
3. ~~Attribution Reporting 审计~~ → 安全
4. ~~Private Aggregation 审计~~ → 安全
5. ~~Compute Pressure 审计~~ → Finding 008
6. ~~Digital Credentials 审计~~ → Finding 007 ⭐
7. ~~Browsing Topics / WebNN / WebBluetooth / FedCM~~ → 安全

### Round 2 完成

8. ~~User Activation 系统性交叉对比~~ → Finding 009-010（多个 renderer-only check，但都需要 compromised renderer）
9. ~~Navigation/Redirect 安全边界~~ → Finding 011 + known TODOs
10. ~~PostMessage/IPC origin checks~~ → 安全
11. ~~StorageAccessHandle DCHECK 审查~~ → Low（debug-only ReportBadMessage）
12. ~~Cookie/CHIPS partitioning~~ → 安全
13. ~~Clipboard API~~ → 需 compromised renderer
14. **待出结果**: WebAuthn/Payment/Notification sub-agents

### Round 3 完成

15. ~~Extension NavigationRegistry + DNR 完整审计~~ → **Finding 013+014** ⭐⭐（最有价值！dead-code logic bug）
16. ~~Extension messaging/storage/injection 审计~~ → Finding 015-018（多数已知）
17. ~~Service Worker / Cache Storage / Background Fetch~~ → DCHECK gaps + 不完整 CORS（已知）
18. ~~WebRTC / MediaStream / Screen Capture~~ → **Finding 019** ⭐⭐（ChromeOS DLP bypass！）
19. ~~Blob URL / File System Access~~ → Blob 分区绕过（需知 UUID），FSA 安全
20. ~~Dead-code pattern 全局搜索~~ → 仅 Finding 013 有安全影响
21. ~~Fenced Frame isolation~~ → 多个 DISABLED_BY_DEFAULT flags
22. ~~Prerender / Prefetch / keep-alive~~ → CSP isolated world gap（已知），其余安全

### Round 4 完成

23. ~~Captured Surface Control API~~ → Finding 021（relative_x/y 无范围验证，需 compromised renderer）
24. ~~Shared Storage API `CreateWorklet()`~~ → **Finding 020**（data_origin opaque 未验证，DCHECK-only）
25. ~~Smart Card API~~ → 安全（isolated context 门控，但无 user activation）
26. ~~Presentation API~~ → Finding 022（user activation 仅 renderer 端检查，需 compromised renderer）
27. ~~TabCaptureRegistry~~ → extension_id 未验证（Low，进程隔离缓解）
28. ~~Chrome UI hardcoded user_gesture~~ → 多数是浏览器内部操作（settings/tabs），非安全问题
29. ~~Extension protocol handlers~~ → 新功能，DISABLED_BY_DEFAULT，auto-accept 无用户确认
30. ~~Extension messaging source validation~~ → kCheckingNoExtensionIdInExtensionIpcs ENABLED_BY_DEFAULT

### Round 5 完成

31. ~~Gamepad API~~ → **Finding 023** ⭐⭐⭐ Browser 端完全无 PP 检查！不需要 compromised renderer！
32. ~~Generic Sensor API~~ → 安全（有 PP 检查）
33. ~~WebTransport API~~ → 无 PP（与 WebSocket 一致，设计决策）
34. ~~Wake Lock / Idle Detection / Screen Orientation / Web Locks~~ → 各有小问题但影响有限
35. ~~Storage Access API~~ → DCHECK_IS_ON ReportBadMessage（已知模式）
36. ~~Controlled Frame / Permission Service / Window Management~~ → 安全
37. ~~AdAuction PP inconsistency 审查~~ → 已知 crbug/382786767
38. ~~Missing-return-after-reject 全局搜索~~ → 仅 Finding 019 有安全影响

### Round 6 完成

39. ~~Battery/Vibration/Font/Keyboard/EME API~~ → Vibration FF bypass(renderer-only), Font/EME PP bypass(需 compromised renderer)
40. ~~DeviceOrientation/Motion event listener~~ → 安全（DidAddEventListener 有 PP 检查）
41. ~~TOCTOU 系统性审计（FSA/WebAuthn/Serial/HID/USB/Payment）~~ → Chromium 有强 TOCTOU 防御（DocumentService/WeakPtr/RequestKey）
42. ~~URL 验证审计（extension/blob/data/javascript/filesystem）~~ → 确认 Finding 013；data: URL 被 BlockedSchemeNavigationThrottle 阻止
43. ~~SW fetch 拦截审计~~ → response_type 未 browser-side 验证（需 compromised renderer）
44. ~~GuestView/WebView 安全审计~~ → GrantCommitOrigin 给 guest（需 compromised renderer），Permission scope 泄露（已知）
45. ~~Dead-code pattern 安全函数搜索~~ → 仅 Finding 013 有安全影响
46. ~~CSP 处理审计~~ → 安全（多层验证）
47. ~~download user_gesture 信任~~ → 来自 renderer，但 BlockedSchemeNavigationThrottle 缓解
48. ~~Gamepad PP Bypass PoC~~ → 已构建（serve_gamepad.py）

### Round 7 进行中

49. ~~Extension Manifest V3 API 安全审计~~ → DNR response header 无 blocklist（by design）；regexSubstitution 只 block javascript:（DCHECK-only for runtime）；userScripts CSP 不验证
50. ~~WebGPU/WebCodecs 审计~~ → 无 PP feature（设计层面），VideoFrame::WouldTaintOrigin 总返回 false（架构缺陷但当前不可利用）
51. ~~CDP 安全审计~~ → SetBypassCSP 无 trust check（Medium，需 debugger API），AttachToTarget 无 target 验证（已知 TODO）
52. ~~Browser-side PP 系统性检查~~ → 24 个 PP feature 无 browser-side 检查，但大多数不需要或设计如此
53. ~~DCHECK_IS_ON ReportBadMessage 审计~~ → 仅 StorageAccessHandle（已知）
54. ~~Missing-return-after-reject 精确搜索~~ → 仅 Finding 019
55. ~~Shape Detection / Vibration / NFC 绑定~~ → Shape Detection 不接受 RFH（但只处理传入数据），Vibration 无 PP feature，NFC 通过 BindRenderFrameHostImpl
56. ~~Mojo origin 验证~~ → 进行中（sub-agent）
57. ~~Fenced Frame API 访问~~ → 进行中（sub-agent）

### 评估总结（Round 7 更新）

**最有价值的发现排名**:
1. **Finding 023** (Gamepad PP Bypass) ⭐⭐⭐ — **Browser 端完全无检查，不需要 compromised renderer，PP bypass 直接可利用！PoC 已构建。**
2. **Finding 013+014** (ExtensionNavigationRegistry dead-code + DNR) ⭐⭐ — 真实逻辑 bug，不需要 compromised renderer，跨扩展资源访问
3. **Finding 019** (DisplayMedia DLP bypass) ⭐⭐ — 真实 missing-return bug，ChromeOS 限定
4. **Finding 004** (AdAuction PP bypass) — 不需要 compromised renderer 的 Medium 发现
5. **Finding 007** (Digital Credentials user activation) — 需要 compromised renderer 但影响大
6. **Finding 020** (Shared Storage opaque origin) — DCHECK-only，标准安全模型违规
7. **Finding 005** (AI API PP gap) — 已知 TODO

**Round 7 新发现**:
- Extension MV3 DNR regexSubstitution：运行时只有 DCHECK 检查 javascript scheme（indexed_rule.cc:381），解析时 regex_substitution 完全不检查 scheme（indexed_rule.cc:406-412）。理论上可 redirect 到 data: URL，但可能被导航层拦截。需要实测验证。
- CDP SetBypassCSP 无 trust check：PageHandler::SetBypassCSP 不检查 is_trusted_，允许 untrusted client 禁用 CSP。但需要 debugger 权限。
- WebGPU/WebCodecs 无 PP feature：跨域 iframe 可无限制使用 GPU/Codec 资源。影响是 DoS 和 fingerprinting。
- Extension userScripts.configureWorld CSP 不验证：可设置任意 CSP 值，不经过 SanitizeContentSecurityPolicy。影响有限（需 developer mode）。

**核心结论**:
- **Finding 023 仍然是最有价值的发现。** Round 7 未发现新的同等级别 bug。
- Chromium 在核心安全区域（导航、CSP、origin 隔离）防御非常完善。
- 剩余的攻击面主要在：(1) 新/边缘 API 的 PP 一致性，(2) Extension API 边界，(3) CDP 权限模型。
- 经过 7 轮系统性审计，280+ 个 Mojo 绑定已审计大部分，高价值低悬果实已基本摘完。

### Round 8: Prerender / Fenced Frame / Sandbox 审计

58. ~~Prerender Mojo 策略~~ → 默认 kDefer（安全），显式 kGrant 的接口均为安全类型（CacheStorage、IDB 等）
59. ~~Prerender 导航限制~~ → 基本完善。WebView allow_partial_mismatch 放宽了 initiator/origin 匹配（Medium on Android），COOP/COEP 不在 prerender 层验证（依赖底层）
60. ~~Fenced Frame API 系统性审计~~ → **发现 Finding 026！** 多个 API（enumerateDevices、getVoices、devicePosture、EyeDropper、MediaSession）在 fenced frame 中无检查，可泄露指纹数据
61. ~~Sandbox flags 强制执行~~ → browsing_context_state.cc:182 TODO crbug.com/740556 "Kill renderer if sandbox flags not subset"，未实现但 OR 运算确保 iframe 属性不可移除（仅 CSP sandbox 可被 compromised renderer 绕过）
62. ~~Fenced Frame sandbox~~ → renderer-only 强制（fenced_frame.cc:386 TODO crbug.com/40233168），但 kFencedFrameForcedSandboxFlags 硬编码在 blink 层
63. ~~Error page sandbox inheritance~~ → navigation_request.cc:5447 TODO crbug.com/40736932，error page 继承 parent sandbox 而非用最严格标志
64. ~~StorageAccess + Prerender~~ → 进行中（sub-agent）
65. ~~WebAuthn report PP bypass~~ → webauth_request_security_checker.cc:140，kReport 跳过 PP 检查（by design，但不一致）
66. ~~IsolatedWebApp throttle~~ → 使用 GetTupleOrPrecursorTupleIfOpaque 做 origin 比较，允许 opaque origin 匹配 precursor（设计决定）
67. ~~支付确认 SPC~~ → kGetPaymentCredentialAssertion 跳过 RP ID 验证（SPC by design）
68. ~~Speculation Rules~~ → SpeculationHostImpl 验证 http(s) scheme，子帧消息被静默丢弃（未 ReportBadMessage）

**Round 8 新发现**:
- **Finding 026**: 多个 API 在 Fenced Frame 中泄露指纹数据（enumerateDevices、getVoices、devicePosture、EyeDropper、MediaSession），不需要任何权限或 compromised renderer。PoC 和 VRP 报告已写。
- Prerender WebView allow_partial_mismatch：Android WebView 上 PAGE_TRANSITION_FROM_API 触发时，跳过 initiator_frame_token、initiator_origin、X- header 比较。在 WebView 应用允许不信任内容调用 loadUrl() 的场景下有风险。
- Prerender COOP/COEP 不在 prerender 层验证：依赖 navigation commit 底层代码强制执行，prerender 层本身没有 COOP/COEP 匹配检查。

### 评估总结（Round 8 更新）

**最有价值的发现排名**:
1. **Finding 023** (Gamepad PP Bypass) ⭐⭐⭐ — Browser 端完全无检查，不需要 compromised renderer
2. **Finding 026** (Fenced Frame Fingerprinting) ⭐⭐ — 多个 API 泄露指纹，不需要 compromised renderer，Privacy Sandbox 核心功能受影响
3. **Finding 013+014** (ExtensionNavigationRegistry dead-code + DNR) ⭐⭐ — 跨扩展资源访问
4. **Finding 019** (DisplayMedia DLP bypass) ⭐⭐ — missing-return bug，ChromeOS 限定
5. **Finding 004** (AdAuction PP bypass)
6. **Finding 007** (Digital Credentials user activation)
7. **Finding 024** (DNR regex scheme bypass)
8. **Finding 025** (CDP SetBypassCSP no trust)

**核心结论（Round 8）**:
- Finding 026 是一个新的有价值发现，影响 Privacy Sandbox 核心隐私保证
- Prerender 安全边界整体完善（默认 kDefer 策略），但 Android WebView 有放宽
- 经过 8 轮系统性审计，剩余高价值攻击面非常有限
- 下一步应聚焦在已有 findings 的实测验证和 VRP 提交

### Round 9: DNR Redirect 深入分析 + 继续挖掘

69. ~~DNR regexSubstitution redirect 完整路径追踪~~ → **Finding 024 升级！** 发现 extension redirect 设置 bypass_redirect_checks=true（web_request_proxying_url_loader_factory.cc:465-469），完全跳过 IsSafeRedirectTarget 检查。data: URL subresource redirect 无任何安全检查。VRP 报告已写。

**Finding 024 升级**:
- `bypass_redirect_checks = true` 对 extension-originated redirects（包括 DNR）
- `IsSafeRedirectTarget` 永远不被调用（即使 data: 在 unsafe 列表中）
- `BlockedSchemeNavigationThrottle` 只检查 main frame，不检查 subresource
- Net 层 `URLRequestJobFactory::IsSafeRedirectTarget` 默认返回 true
- **完整攻击链**: DNR regexSubstitution → data: URL → bypass all checks → script executes with page origin
- VRP 价值从 Low-Medium 升至 **Medium-High**（MV3 安全模型缺陷）

### Round 10: 继续深入挖掘

70. ~~BFCache 安全不变量审计~~ → Cookie change listener 只监控 main frame URL（subframe cookies 不监控）；CCNS level 4 允许 JS cookie 变更后 restore；多个 API（StorageAccess、WebNFC）的 BFCache 兼容性有 TODO
71. ~~WebSocket/WebTransport origin 审计~~ → Worker 绕过 Connection-Allowlist（已知 crbug/492462310）；WebTransport 无 browser-side scheme 验证（net 层兜底）
72. ~~Navigation/History origin 审计~~ → **Finding 027**: kValidateCommitOriginAtCommit DISABLED_BY_DEFAULT（已知，正在修复）；subframe history origin check 限 HTTP(S)
73. ~~FedCM Email Verification 审计~~ → **Finding 028**: SD-JWT 完全无签名验证（TODO 明确标注）；opaque origin 导致 aud="null"；feature DISABLED_BY_DEFAULT
74. ~~Extension Content Script CSP 审计~~ → userScripts.configureWorld() CSP 无验证（by design，需要 developer mode + user opt-in）
75. ~~Password Sharing 审计~~ → **Finding 029**: scheme bypass 跳过 origin 验证；unchecked static_cast；mobile 缺少 cross-domain consent
76. ~~WebRTC ICE fenced frame 审计~~ → **Finding 030** ⭐⭐⭐: kFencedFramesLocalUnpartitionedDataAccess DISABLED_BY_DEFAULT，P2P 和 RTCPeerConnection 在 fenced frame 中完全可用！可泄露本地 IP 并建立跨边界通信信道

### 评估总结（Round 10 更新）

**最有价值的发现排名**:
1. **Finding 023** (Gamepad PP Bypass) ⭐⭐⭐ — Browser 端完全无检查，不需要 compromised renderer
2. **Finding 030** (Fenced Frame WebRTC P2P) ⭐⭐⭐ — **新发现！** Feature flag disabled，P2P 在 fenced frame 完全可用，Privacy Sandbox 隔离完全失效
3. **Finding 026** (Fenced Frame Fingerprinting) ⭐⭐ — 多个 API 泄露指纹
4. **Finding 024** (DNR regexSubstitution data: redirect) ⭐⭐ — bypass_redirect_checks=true，MV3 安全模型缺陷
5. **Finding 013+014** (ExtensionNavigationRegistry dead-code + DNR) ⭐⭐ — 跨扩展资源访问
6. **Finding 019** (DisplayMedia DLP bypass) ⭐⭐ — missing-return bug，ChromeOS 限定
7. **Finding 029** (Password Sharing scheme bypass) — origin 验证绕过
8. **Finding 004** (AdAuction PP bypass)
9. **Finding 007** (Digital Credentials user activation)

### Round 11: Fenced Frame API 系统审计

77. ~~Fenced frame network/timing leak 审计~~ → WebSocket/WebTransport/fetch/XHR 完全无限制（通过 nonce 隔离 storage，但网络层完全开放）；SharedWorker/BroadcastChannel/Web Locks/IndexedDB 通过 nonce-based StorageKey 正确隔离；Performance.now() 给 fenced frame 100us 精度（和普通跨站 iframe 相同）
78. ~~Gamepad API fenced frame 审计~~ → Gamepad 在 fenced frame 中无限制（browser_interface_binders.cc:845-846）

### Round 12: Prefetch/Prerender + Payment/Blob/WebAuthn 审计

79. ~~Prefetch/Prerender 安全审计~~ → kPrerender2DisallowNonTrustworthyHttp 声明但无使用（dead code）；contamination delay 机制设计良好；Prerender cross-origin iframe 控制正确
80. ~~Payment Handler API 审计~~ → StorageKey::CreateFirstParty 绕过 storage partitioning（crbug/40177656 已知未修）；SameDomainOrHost 替代 same-origin 检查 manifest redirect；kEnforceFullDelegation DISABLED_BY_DEFAULT
81. ~~WebAuthn/Passkey 审计~~ → **Finding 031** ⭐⭐⭐: Signal API (Report) 缺少 TLS 检查、permissions policy、actor check 和 focus check！跨源 iframe 可删除/修改 passkey
82. ~~Navigation race condition 审计~~ → 后台进行中
83. ~~Extension messaging 审计~~ → 后台进行中
84. ~~Blob URL 安全审计~~ → 后台进行中
85. ~~ORB/CORB 审计~~ → ORB 在 sniffable body 结束时 fail open（kAllow 而非 kBlock），步骤 10/11/13/15/16 均未实现。这是已知的渐进过渡设计

### Round 13 — Service Worker + Interest Group + Navigation Controller + CPSP (Task #39)

**深度审计四大关键子系统的结果**:

86. **Navigation Race Condition 审计 (10 个发现)**:
   - Finding 034: `kValidateCommitOriginAtCommit` DISABLED — commit 时不验证 origin
   - Finding 035: `kEnforceSameDocumentOriginInvariants` DISABLED — same-doc navigation 可改 origin
   - Finding 036: `CanAccessOrigin` DCHECK-only — release 模式下 site isolation 最后防线不存在
   - Finding 037: Fenced frame 网络切断竞争条件
   - Finding 038: Cross-origin prefetch BuildClientSecurityState 使用前一个 document 的策略

87. **Interest Group / Protected Audiences 审计**:
   - Finding 039: `kFledgeModifyInterestGroupPolicyCheckOnOwner` DISABLED — 跨 origin interest group 权限检查被检测但不执行
   - crbug.com/382786767: 4 处 permission policy 不一致被静默忽略，不杀 renderer
   - `kEnableBandAKAnonEnforcement` DISABLED — B&A k-anonymity 强制执行关闭

88. **ChildProcessSecurityPolicy 审计**:
   - Finding 040: Opaque origin 无 precursor 绕过所有 process lock 检查
   - Sandboxed process kCanCommitNewOrigin 无条件返回 true
   - data: URL 可在任何 process commit
   - file:// origin 匹配忽略 host/path

89. **NavigationController 审计**:
   - Finding 041: History navigation SiteInstance mismatch check NotFatalUntil::M141
   - Entry resurrection: 已删除的 history entry 可被 renderer 恢复
   - DCHECK-only initiator origin 验证

90. **Service Worker 审计**:
   - DCHECK-only origin 验证在 service_worker_object_host.cc
   - `kServiceWorkerBypassSyntheticResponseHeaderCheck` 绕过 CSP 要求（开发测试用）
   - COEP/DIP soft-fail 在 embedded_worker_instance.cc

### 评估总结（Round 13 更新）

**最有价值的发现排名**:
1. **Finding 031** (WebAuthn Signal API) ⭐⭐⭐ — 缺少 TLS 检查、permissions policy（有 TODO 确认）、actor check。跨源 iframe 可静默删除 passkey
2. **Finding 039** (FLEDGE PP Bypass) ⭐⭐⭐ — **新发现！** 跨 origin interest group 权限检查 DISABLED，标准 JS 可利用
3. **Finding 023** (Gamepad PP Bypass) ⭐⭐⭐ — Browser 端完全无检查
4. **Finding 034+035+036** (Origin Validation Triple Failure) ⭐⭐⭐ — **新发现！** 三层 origin 验证全部禁用/DCHECK-only
5. **Finding 030** (Fenced Frame WebRTC P2P) ⭐⭐⭐ — Feature flag disabled
6. **Finding 041** (SiteInstance Mismatch Non-Fatal) ⭐⭐ — **新发现！** NotFatalUntil::M141
7. **Finding 026** (Fenced Frame Fingerprinting) ⭐⭐ — 多个 API 泄露指纹
8. **Finding 024** (DNR regexSubstitution data: redirect) ⭐⭐
9. **Finding 040** (Opaque Origin Process Lock Bypass) ⭐⭐ — **新发现！** 需要 compromised renderer
10. **Finding 037+038** (Race Conditions) ⭐⭐ — Fenced frame 网络切断 + prefetch 策略混淆

### Round 14 — Blink Renderer-side + WebGPU + Storage Access API (Task #40)

91. **Storage Access API 审计**:
   - Finding 042: `StorageAccessHandle::Create` 中 `ReportBadMessage` 被 `#if DCHECK_IS_ON()` 包裹 — release 模式下 compromised renderer 不被杀
   - FedCM auto-grant 在 user activation 检查之前 — 有 FedCM 权限即可无用户交互获得 storage access

92. **WebGPU 审计**:
   - VideoFrame taint check 是 DCHECK-only（line 187 of external_texture_helper.cc）
   - Buffer aliasing 仍由"temporary" CHECK 保护（crbug.com/1326210）
   - 总体安全性良好：SPIR-V 被阻止、timestamp 被量化、feature 分层暴露

93. **CSP bypass via isolated world** (frame_loader.cc:966) — 已知设计，不是 VRP

---

## Round 15-17: CORS/Network + DOM + SW + Sandbox (2026-04-27 ~ 04-28)

### Finding 043: ORB Fails Open — Spec Steps 10-16 Skipped ⭐⭐

- **文件**: `services/network/orb/orb_impl.cc:461-482`
- **问题**: ORB 实现跳过 spec steps 10, 11, 13, 15, 16，最终 step 16 从 kBlock 改为 kAllow
- **影响**: 跨域 opaque 响应数据进入 renderer 进程，Spectre 缓解失效
- **不需要 compromised renderer**: 标准 fetch() with mode:'no-cors'
- **VRP 报告**: `vrp_report_orb_fail_open.md`

### Finding 044: TLS Client Cert Leak with credentials:"omit" ⭐⭐⭐

- **文件**: `services/network/url_loader_util.cc:102-112`, `features.cc:197`
- **问题**: kOmitCorsClientCert DISABLED — credentials:"omit" 仍然发送 TLS 客户端证书
- **影响**: 任何网页可通过 TLS 客户端证书去匿名化用户
- **不需要 compromised renderer**: 标准 JavaScript API
- **VRP 报告**: `vrp_report_cors_client_cert_leak.md`

### Finding 045: WebRTC LNA Bypass ⭐⭐

- **文件**: `services/network/public/cpp/features.cc:251-252`
- **问题**: kLocalNetworkAccessChecksWebRTC DISABLED — HTTP/WS/WT 已启用 LNA，WebRTC 未启用
- **影响**: 任何网页可通过 WebRTC 访问本地/私有网络，绕过 HTTP 级别 LNA 保护
- **不需要 compromised renderer**

### Finding 046: document.open() Origin Aliasing

- **文件**: `document.cc:3840-3847`
- **问题**: document.open() 导致两个窗口共享同一 mutable SecurityOrigin
- **影响**: 跨子域 DOM 访问 via 共享 origin + document.domain 变异

### Finding 047: Capability Delegation Missing PP Check

- **文件**: `dom_window.cc:1079`
- **问题**: postMessage capability delegation 缺少 Permissions Policy 检查
- **影响**: 受限 iframe 可以委托它没有的 capability

### Finding 048: SW Script URL Not Verified

- **文件**: `service_worker_script_loader_factory.cc:208-214`
- **问题**: kServiceWorkerVerifyMainScriptUrl DISABLED — browser 不验证 SW 脚本 URL
- **影响**: 被入侵 renderer 可加载任意脚本作为 SW（持久化攻击）

### Finding 049: SharedWorker Secure Context Trusted from Renderer

- **文件**: `shared_worker_service_impl.cc:216-219`
- **问题**: kSharedWorkerSecureContextDerivationFromBrowser DISABLED
- **影响**: 被入侵 renderer 可伪造安全上下文状态

### Finding 050: SharedWorker WebSocket SameSite Cookie Leak ⭐⭐

- **文件**: `shared_worker_host.cc:710-724`
- **问题**: kRestrictSharedWorkerWebSocketCrossSiteCookies DISABLED
- **影响**: 跨站 SharedWorker WebSocket 发送 SameSite=Strict/Lax cookies
- **不需要 compromised renderer**
- **VRP 报告**: `vrp_report_shared_worker_websocket_cookie_leak.md`

### Finding 051: SW Controller Matching DCHECK-Only (crbug.com/497761255)

- **文件**: `service_worker_client.cc:703-717`
- **问题**: SetControllerRegistration、AddMatchingRegistration 的匹配检查仅 DCHECK
- **影响**: 被入侵 renderer 可将跨 scope/origin SW 设为 controller

### Finding 052: SW Update No Upgrade-Insecure-Requests

- **文件**: `service_worker_single_script_update_checker.cc:165-166`
- **问题**: SW 更新检查不设置 upgrade_if_insecure
- **影响**: MITM 攻击者可在 SW 更新时注入恶意脚本

### Finding 053: COOP Ignores Sandbox Flags

- **文件**: `navigation_request.cc:11482-11496`
- **问题**: COOP 不考虑 sandbox flags，沙箱页面可共享 COI BrowsingInstance
- **影响**: 沙箱帧获得不应有的 SharedArrayBuffer 访问

---

### 总统计

- **总 Finding 数**: 53
- **VRP 报告已写**: 14
- **不需要 compromised renderer 的发现**: 031, 039, 023, 030, 026, 024, 037, 043, 044, 045, 050
- **涉及 disabled feature flag 的发现**: 034, 035, 039, 030, 041, 044, 045, 048, 049, 050

### Updated Finding 排名 (Round 17)

| 排名 | Finding | 评级 | 不需要 CR? |
|------|---------|------|-----------|
| 1 | 044 (TLS Client Cert Leak) | ⭐⭐⭐ | 是 |
| 2 | 031 (WebAuthn Signal API) | ⭐⭐⭐ | 是 |
| 3 | 039 (FLEDGE PP Bypass) | ⭐⭐⭐ | 是 |
| 4 | 023 (Gamepad PP Bypass) | ⭐⭐⭐ | 是 |
| 5 | 050 (SharedWorker WS Cookie Leak) | ⭐⭐ | 是 |
| 6 | 043 (ORB Fail-Open) | ⭐⭐ | 是 |
| 7 | 045 (WebRTC LNA Bypass) | ⭐⭐ | 是 |
| 8 | 034+035+036 (Origin Validation Triple) | ⭐⭐⭐ | 否 |
| 9 | 030 (Fenced Frame WebRTC P2P) | ⭐⭐⭐ | 否 |
| 10 | 041 (SiteInstance Mismatch Non-Fatal) | ⭐⭐ | 否 |

### 下一步

- **VRP 报告提交**: 优先级 044 > 031 > 039 > 050 > 023 > 043 > 045
- **PoC 验证**: 在 Chrome Canary 中验证 (044 最容易测试 — 需要 TLS 客户端证书)
- **继续挖掘**: 扩展 API、Autofill、更多 Blink renderer 内部安全检查
