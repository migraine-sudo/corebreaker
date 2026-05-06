# Round 8: ServiceWorker Static Router installRouter() — EXCLUDED (no new findings)

## 审计目标
ServiceWorker Static Router `installRouter()`/`addRoutes()` API 的 source/condition type 覆盖完整性，特别关注：
- COEP/DIP 在 cache source 中的强制执行
- `kRaceNetworkAndCache` 的安全检查覆盖
- `not_condition`/`or_condition` 的评估逻辑边界
- 主资源 vs 子资源路径的安全检查对称性
- `running_status` 条件的时序问题
- DIP (Document Isolation Policy) 持久化完整性

## 架构理解

### 核心文件 (10 files)
1. `content/browser/service_worker/service_worker_main_resource_loader.cc` — Navigation 请求的 SW 路由
2. `content/renderer/service_worker/service_worker_subresource_loader.cc` — 子资源请求的 SW 路由
3. `content/common/service_worker/service_worker_router_evaluator.cc` — 条件求值引擎
4. `content/common/service_worker/service_worker_resource_loader.cc` — 共享的 `IsValidStaticRouterResponse()`
5. `content/browser/service_worker/service_worker_cache_storage_matcher.cc` — Cache source 的 COEP/DIP 执行
6. `content/browser/service_worker/service_worker_version.h/cc` — Worker 版本管理、策略存储
7. `content/browser/service_worker/service_worker_registry.cc` — 从 DB 恢复 Worker 策略
8. `content/browser/renderer_host/policy_container_host.cc` — PolicyContainer 构造（DIP 默认化）
9. `content/common/features.cc` — Feature flags (CORP/Opaque check 均 DISABLED)
10. `third_party/blink/renderer/modules/service_worker/service_worker_router_type_converter.cc` — Renderer 侧验证

### 数据流
```
JS: navigator.serviceWorker.register('sw.js')
SW install event: event.addRoutes([{condition: {...}, source: [...]}])
  → Renderer: ConvertV8RouterRuleToBlink() 验证 + 深度检查
    → Browser: ServiceWorkerVersion::AddRoutes()
      → ServiceWorkerRouterEvaluator::Compile() 重新验证
      → 存入 ServiceWorkerRegistration

Navigation/Subresource 请求:
  → Evaluator.Evaluate(request, running_status) → 匹配 rule
  → Switch on source_type:
    kNetwork → Fallback() → 正常网络栈
    kCache → CacheStorageMatcher → 从 CacheStorage 读取
    kRaceNetworkAndCache → 同时启动网络 + CacheStorage，先到先用
    kFetchEvent → 正常 dispatch 给 SW
    kRaceNetworkAndFetchEvent → 同时启动网络 + dispatch
```

### 安全检查列表
1. `IsValidStaticRouterResponse()` — CORP + opaque response 验证 (**behind DISABLED flag**)
2. `kServiceWorkerStaticRouterCORPCheck` — CORP 检查 (DISABLED_BY_DEFAULT)
3. `kServiceWorkerStaticRouterOpaqueCheck` — Opaque 响应阻止 (DISABLED_BY_DEFAULT)
4. CacheStorageMatcher: COEP/DIP from `version_->cross_origin_embedder_policy()/document_isolation_policy()`
5. `ExceedsMaxConditionDepth` — 递归深度限制 (max 10, 两侧验证)
6. `IsValid()` / `IsOrConditionExclusive()` / `IsNotConditionExclusive()` — 条件互斥验证
7. Browser 侧 `ReportBadMessage()` — 对无效路由规则终止 renderer

### 防御层分析
- **层1:** Renderer 侧类型转换验证（深度、互斥、空条件）
- **层2:** Browser 侧 Compile() 重新验证（独立于 renderer）
- **层3:** `IsValidStaticRouterResponse` CORP/opaque 检查 (DISABLED)
- **层4:** CacheStorage 自身的 origin-scoped access control
- **层5:** 网络栈 CORS/CORB 对 kNetwork fallback 的正常执行

---

## 假设分析

### 假设 A: kRaceNetworkAndCache 跳过 IsValidStaticRouterResponse

**位置:** `service_worker_main_resource_loader.cc:915-916`, `service_worker_subresource_loader.cc:1500-1501`

**观察:** Guard 条件仅检查 `matched_source_type == kCache`，但 `kRaceNetworkAndCache` 在 cache 胜出时也服务 cache 响应。由于 `matched_source_type` 保持为 `kRaceNetworkAndCache`，CORP/opaque 验证被完全跳过。

**状态:** **已报告 (R6-05)** — 此 finding 在前一轮已发现并提交 VRP

### 假设 B: DIP 未持久化到 SW 数据库

**位置:** 
- `policy_container_host.cc:176` — 从存储恢复时 DIP 硬编码为 `DocumentIsolationPolicy()` (kNone)
- `service_worker_database.proto` — 无 DIP 字段
- `service_worker_registry.cc:1244-1249` — 使用 `PolicyContainerPolicies(policies, true)` 构造

**观察:** ServiceWorker 的 DIP 在浏览器重启后丢失，恢复为 kNone。这意味着 CacheStorageMatcher 在冷启动时使用错误的 DIP 进行 CORP 检查。

**排除原因:** 三重门控
1. `kServiceWorkerStaticRouterCORPCheck` DISABLED_BY_DEFAULT — CORP 检查不生效 → 无影响
2. 即使启用，DIP enforcement 是 defense-in-depth（正常 fetch 有网络栈 CORP）
3. 需要特定条件组合：site 使用 DIP + SW Static Router cache source + 浏览器重启

→ Gate 5 (FEATURE_DISABLED_BY_DEFAULT 保护的检查 = 无效检查) + defense-in-depth

### 假设 C: not_condition / or_condition 绕过

**位置:** `service_worker_router_evaluator.cc:624-653`

**观察:** `not(not(x))` 等嵌套构造是否能绕过仅对直接条件执行的检查？

**排除原因:** 设计正确
1. 递归深度限制 = 10（Renderer + Browser 双侧验证）
2. 互斥性验证正确（`or` 和 `not` 不能与其他条件共存于同一层级）
3. Mojo 反序列化后 Browser 侧 `Compile()` 独立验证
4. `not(not(x))` == x 是预期行为，有明确测试覆盖
5. 空 `or_condition` 正确返回 false（永不匹配）

### 假设 D: 主资源 vs 子资源路径安全检查不对称

**位置:** Main: `service_worker_main_resource_loader.cc:914-935`, Sub: `service_worker_subresource_loader.cc:1498-1513`

**观察:** 两条路径是否有不同的安全执行？

**排除原因:** 完全对称
- 两条路径使用相同的 `IsValidStaticRouterResponse()` (来自 `ServiceWorkerResourceLoader` 基类)
- 相同的 feature flag 控制
- 相同的 guard 条件 bug（只检查 `kCache`，不检查 `kRaceNetworkAndCache`）— 即 R6-05
- 唯一区别：主资源在 browser process，子资源在 renderer process（但检查逻辑等价）

### 假设 E: running_status TOCTOU (评估时 vs 执行时状态不一致)

**位置:** `service_worker_main_resource_loader.cc:287`

**观察:** `running_status` 在评估时读取。如果评估后 worker 状态改变（如从 kStopped → kStarting），路由决策可能不再正确。

**排除原因:** 设计正确
- `running_status` 条件的典型用法：`{runningStatus: "not-running", source: "network"}` — 当 worker 未运行时走网络
- 即使状态在评估后改变，安全影响为零：最差情况是不必要地启动 worker 或不必要地走网络
- 没有安全相关的状态依赖于 `running_status` 的准确性
- 纯性能优化机制，非安全门控

---

## 综合评估

### 本轮发现
| Finding | 状态 | 原因 |
|---------|------|------|
| kRaceNetworkAndCache 跳过 CORP/opaque check | 已报告 (R6-05) | — |
| DIP 未持久化 | EXCLUDED | 检查本身 DISABLED_BY_DEFAULT |
| not/or 逻辑绕过 | EXCLUDED | 双侧验证、深度限制、测试覆盖 |
| 主/子资源不对称 | EXCLUDED | 完全对称 |
| running_status TOCTOU | EXCLUDED | 非安全门控 |

### 安全模型评价
SW Static Router 的安全模型有一个核心问题：**CORP 和 opaque response 检查均为 DISABLED_BY_DEFAULT**。这意味着当前 Chrome stable 中，static router 的 cache source 可以服务任何缓存的响应（包括 opaque cross-origin 响应）而不受限制。

然而这是已知的 staged rollout（有对应的 crbug），不构成新发现：
- crbug.com/495999481 对应 opaque check
- 注释明确标注 "Enforce CORP check for Service Worker Static Router's cache source"

R6-05 是这个子系统中唯一的真正逻辑 bug（guard 条件不完整），已在前轮报告。

---

## 结论

**EXCLUDED** — 无新可报告 finding：
- 核心安全 bug (R6-05) 已在前轮发现并报告
- DIP 持久化缺失是 defense-in-depth finding，被 DISABLED feature flag 双重保护
- 条件评估逻辑健壮，双侧验证 + 深度限制
- 主/子资源路径完全对称
- running_status 是性能机制，非安全门控

满足 Kill Criteria: "假设生成后发现全部有 2+ 层防御且无法绕过"
