# Chrome 逻辑漏洞挖掘：避免撞洞的差异化策略

## 日期: 2026-05-01

---

## 一、其他攻击者集中在哪里（高撞洞风险区）

### 1. Renderer → Browser IPC 信任边界
- **典型目标**: Mojo 接口参数验证、`bad_message::ReceivedBadMessage` 缺失
- **为什么热门**: Pwn2Own/ZDI 主力方向，工具链成熟（MojoJS bindings）
- **撞洞风险**: 极高。Google Project Zero、Microsoft MSRC、各大安全公司都在看
- **代表 CVE**: CVE-2024-0519, CVE-2023-4863

### 2. V8 JIT 编译器 type confusion
- **典型目标**: Turbofan/Maglev 的 type feedback 信任、range analysis 错误
- **为什么热门**: 回报极高（$250k+），有学术研究支撑
- **撞洞风险**: 极高。全球顶尖选手都在这里
- **代表**: CVE-2024-2887, CVE-2023-3079

### 3. 经典 Web 安全边界
- **典型目标**: CORS bypass、CSP bypass、SOP violation
- **为什么热门**: Web 安全研究者入门路径，工具/文档丰富
- **撞洞风险**: 高。Bug bounty 平台上大量重复报告
- **特点**: Chrome 在这些地方防御最深，多层冗余

### 4. Navigation 状态机竞争
- **典型目标**: `NavigationRequest` 生命周期中的时序窗口
- **为什么热门**: 历史上产出过多个高价值 CVE
- **撞洞风险**: 中高。但难度也高，能做到的人不多

---

## 二、被忽视的攻击面（低撞洞风险区）

### 🎯 优先级 1: "Beyond Cookies" 新特性的 browser-side 逻辑

**为什么被忽视**:
- 2023-2024 才 ship，代码库新，历史审计少
- 不在传统"安全边界"思维框架内（不是 SOP/CORS/CSP）
- 功能复杂度高但安全研究者不熟悉
- 没有现成的 fuzzing harness

**我们的 Finding 244 就在这里**。具体子领域:
- Storage Access API "Beyond Cookies" 扩展
- Related Website Sets (原 FPS) 自动授权逻辑
- `StorageAccessHandle` 的各种绑定（SharedWorker、BroadcastChannel、IndexedDB）
- Cookie Setting Overrides 在 browser↔network service 之间的传播

**方法论**: 追踪 `kStorageAccessGrantEligible` / `kTopLevelStorageAccessGrantEligible` 等 override 在所有代码路径中的设置/传播/消费，找不一致。

---

### 🎯 优先级 2: DevTools Protocol 权限模型边缘

**为什么被忽视**:
- 大多数安全研究者认为 "debugger 权限 = 已经全能"，不再深究
- 实际上 Chrome 对扩展的 CDP 访问有精细的权限层
- `IsTrusted()` / `MayAccessAllCookies()` / `MayAttachToURL()` / `AllowUnsafeOperations()` 各自独立
- 自动附加子 session 的权限继承是容易出错的地方

**我们的 Finding 245 就在这里**。具体子领域:
- `TargetHandler::Session` 对每个新增权限方法的覆盖完整性
- `BrowserConnectorHostClient` 权限模型
- `DevToolsSession::CreateAndAddHandler` 的 trusted/untrusted 分流
- 新增 CDP domain 时忘记加入 `IsDomainAvailableToUntrustedClient` 列表

**方法论**: 每当 `DevToolsAgentHostClient` 接口新增方法时，检查所有实现类是否正确覆写。重点看 `target_handler.cc` 中 `Session` 和 `BrowserConnectorHostClient` 的实现。

---

### 🎯 优先级 3: Privacy Sandbox 新 API 的跨组件交互

**为什么被忽视**:
- Topics API、Attribution Reporting、Protected Audience 各自独立审计
- 但它们与现有安全机制（cookie、storage、network partition）的交互点少有人看
- 这些 API 频繁迭代，代码变动大，regression 高发

**具体方向**:
- Fenced Frame 内的 `reportEvent()` 数据流 → 能否编码跨站信息
- Protected Audience worklet 的 Mojo 接口信任模型（Finding 242 就在这里）
- Shared Storage worklet 的输出通道（`selectURL` 的 k-anonymity 绕过）
- Attribution Reporting 的 redirect 链处理（已知 insecure redirect 不阻断）

---

### 🎯 优先级 4: 功能特性的 permission propagation 不一致

**为什么被忽视**:
- 不是一个"位置"而是一个"模式"——需要跨组件追踪
- 需要理解 Chrome 的 DocumentAssociatedData、PolicyContainer、BrowsingContextState
- 安全研究者通常 focus on 单个组件而非跨组件数据流

**具体模式**:
- SAA grant 后哪些 API 继承了 unpartitioned 状态（cookie? indexedDB? SharedWorker? CacheStorage?）
- Prerender activation 时哪些安全状态被正确 reset
- Fenced Frame 的 sandbox flags 是否覆盖了所有新增 API
- BFCache restore 时权限/cookie 状态是否 stale

---

### 🎯 优先级 5: "防御层的假设不成立"的代码模式

**为什么被忽视**:
- 需要深度理解每层防御的 precondition
- 大多数审计只看"这层有没有检查"，不看"这层检查的前提是否成立"

**典型模式**:
- **DCHECK-only guard**: Release 中无效（Finding 244 的 RCM DCHECK）
- **Renderer-side check + browser trusts**: renderer 正确，browser 不验证（Finding 244 的 browser-side unconditional callback）
- **Per-call vs base override**: 基础 override 设置错误后，per-call 的 `kNone` 无法覆盖（Finding 244 的 RCM base override）
- **Lazy binding**: 安全状态在 bind 时确定，之后不随权限变化更新

---

## 三、避免撞洞的方法论

### 原则 1: 不找"缺失的检查"，找"检查的不一致"

传统方法: "这个函数没有验证 origin" → 但通常其他层有 backup
我们的方法: "A 组件认为 X=true 时设置 flag，B 组件在 X=false 时也设置了同一 flag" → 不一致 = 真实 bug

### 原则 2: 追踪新 API 的 permission/override 传播到旧代码路径

新 API (SAA Beyond Cookies) 设置了一个 override → 这个 override 流到了旧代码 (RCM) → 旧代码对 override 的假设不成立 → Bug

**Checklist**:
- 新 feature 设置了哪些 `CookieSettingOverride`?
- 这些 override 在哪些地方被读取?
- 读取的地方是否知道新 feature 的存在?
- 有没有"只有 X 情况下才应该设置这个 override"的 invariant 被打破?

### 原则 3: 找 copy-paste 不完整的权限覆写

当一个接口新增方法时:
- 所有现有实现类是否都覆写了?
- 覆写是否遵循同一模式（delegate to root）?
- 有没有遗漏的实现（返回默认值但默认值不正确）?

**工具**: `grep -rn "MethodName" | sort by file` → 比较所有实现是否一致

### 原则 4: 关注 "delayed/lazy" 绑定的安全状态快照

Chrome 大量使用延迟绑定:
- `RestrictedCookieManager` 在首次 cookie 访问时绑定
- `URLLoaderFactory` 在 commit 时创建
- Permission 状态在 grant 时快照

如果 grant 的时间点和绑定的时间点之间，安全语义应该不同 → Bug

### 原则 5: 看 enterprise/debug 代码路径

- Enterprise policy 通常有特殊通道绕过正常检查
- Debug/DevTools 代码权限模型与 web 不同但共用基础设施
- 这些路径测试覆盖低，审计也少

---

## 四、下一步高价值审计目标

| 优先级 | 目标 | 预期类型 | 难度 |
|--------|------|----------|------|
| ⭐⭐⭐ | SAA Beyond Cookies 其他 override 传播路径 | Cookie/Storage 隔离绕过 | 中 |
| ⭐⭐⭐ | DevToolsAgentHostClient 新方法覆写完整性 | 权限提升 | 低 |
| ⭐⭐ | Shared Storage selectURL 的 k-anonymity 检查 | 信息泄露 | 高 |
| ⭐⭐ | Protected Audience 的 worklet→browser 信任边界 | 数据泄露 | 中 |
| ⭐⭐ | NavigationAPI deferPageSwap + redirect timing | 侧信道 | 中 |
| ⭐ | Attribution Reporting insecure redirect 链 | 注入 | 高 |
| ⭐ | Prerender MojoBinderPolicy 对 cross-origin same-site | 权限提升 | 高 |

---

## 五、为什么我们的 finding 不会被撞

### Finding 244
- 需要理解 SAA "Beyond Cookies" 的完整架构（renderer + browser + network service 三层）
- 需要知道 `CookieSettingOverride` 如何在 DocumentAssociatedData → SubresourceLoaderFactoriesConfig → RCM 之间流动
- 需要理解 "lazy RCM binding" 的时序意义
- 这不是一个"缺失的检查"，而是"browser-side 的回调粒度不够 + RCM 的 DCHECK 在 release 中无效"的组合

### Finding 245
- 需要看一个 inner class 的 **6 个方法覆写**并发现第一个和其余 5 个模式不同
- 需要理解 auto-attached session 的 client 不是根客户端
- 需要追踪 `MayAccessAllCookies()` 在 `ClearBrowserCookies` 中的具体作用
- 大多数人看到 "debugger permission" 就停止分析了，认为已经 full-compromise
