# Round 6 审计 — 优先级排序

## 日期: 2026-05-01

## 审计覆盖
- 4 个并行 Agent + 手动审计
- 覆盖: Navigation state machine, SW/Storage partitioning, Topics API model_version, Cross-origin leaks
- 共发现 19+ findings, 筛选后如下

---

## Tier 1: 最值得报的（普通网页可利用）

### R6-05: SW 静态路由 RaceNetworkAndCache 绕过 OpaqueCheck
- **来源**: SW/Storage Agent
- **位置**: `content/browser/service_worker/service_worker_main_resource_loader.cc:908-916`
- **问题**: opaque response 安全检查仅匹配 `kCache` source type，不匹配 `kRaceNetworkAndCache`。当 race 中 cache 胜出时，opaque response 不受检查直接提供给导航。
- **影响**: 绕过即将启用的 `kServiceWorkerStaticRouterOpaqueCheck`，允许跨域 opaque 响应作为导航结果
- **可利用性**: HIGH — 普通网页注册 SW + 静态路由即可
- **信心**: HIGH — 明确的条件遗漏
- **独立性**: 与之前可能报告的 finding_241 独立（这是 241 修复的绕过路径）

### R6-01: SW 静态路由 Cache Source Opaque+CORP 绕过（两个 flag 默认禁用）
- **来源**: SW/Storage Agent
- **位置**: `content/common/features.cc:703-710`, `service_worker_main_resource_loader.cc:914-935`
- **问题**: `kServiceWorkerStaticRouterOpaqueCheck` 和 `kServiceWorkerStaticRouterCORPCheck` 均默认 DISABLED
- **影响**: 通过 SW 静态路由 cache source 提供跨域 opaque 响应和绕过 CORP 策略
- **可利用性**: HIGH — 注册 SW + cache opaque response + 静态路由
- **信心**: HIGH — 两个安全检查明确默认关闭
- **注**: 可能与之前的 finding_241 重复

---

## Tier 2: 值得深入验证

### R6-06: StorageAccessHandle 创建后无 Grant 撤销监听
- **位置**: `content/browser/storage_access/storage_access_handle.cc:51-63`
- **问题**: SAA Handle 仅在创建时检查权限，之后 grant 被撤销不影响 handle
- **影响**: SAA grant 撤销后，7种存储 API 继续使用第一方 StorageKey
- **可利用性**: MEDIUM — 需要用户先授权再撤销
- **信心**: MEDIUM-HIGH

### N6-01: ValidateCommitOriginAtCommit 默认关闭
- **位置**: `content/public/common/content_features.cc:1128`
- **问题**: 历史导航中 FrameNavigationEntry 可能保留陈旧 origin，PageState 在错误 origin 中恢复
- **可利用性**: MEDIUM — 需要特定重定向场景 + 历史导航
- **信心**: MEDIUM — 代码注释承认问题存在 (crbug/420965165)

### R6-02 + R6-03: SAA SharedWorker/BroadcastChannel 跨分区连接
- **位置**: `content/browser/storage_access/storage_access_handle.cc:200-221`
- **问题**: SAA Handle 的 SharedWorker 和 BroadcastChannel 使用第一方 StorageKey，可连接到第一方上下文的 worker/channel
- **可利用性**: MEDIUM — 需要 SAA grant
- **信心**: MEDIUM — 可能是 SAA by-design

---

## Tier 3: 可能值得报但影响有限

### N6-08: CSP attribute 快照时机 (beforeunload TOCTOU)
- **位置**: `navigation_request.cc:3027-3031`
- **问题**: CSP embedded enforcement 在 beforeunload 之后才快照
- **可利用性**: LOW-MEDIUM — 需要同源页面配合
- **信心**: MEDIUM — 两处 TODO 承认问题

### N6-07: Prerender 激活中 pushState URL 覆盖
- **位置**: `navigation_request.cc:7195-7209`
- **问题**: 预渲染页面通过 pushState 修改 URL，激活时被直接信任
- **可利用性**: LOW — 仅影响同 origin URL
- **信心**: MEDIUM-LOW — 代码自称是 hack

---

## 排除的 Findings

### Finding 254: Topics API model_version (排除)
- model_version 是静态的（按 Chrome 版本更新），不能区分 epoch
- **不可利用**

### Finding 255: Shared Storage selectURL 时序 (排除)
- Chrome 团队已经处理了时序差异 — cross-origin 禁用时返回 fake success
- 两个路径都在同一时间返回 Promise result
- **时序差异太小，不实用**

### N6-02 到 N6-06: Navigation findings (排除)
- 多数需要 compromised renderer
- Blob URL revoke 的 opaque origin 限制了影响

---

## 下一步

1. **R6-05**: 写 PoC + VRP（SW RaceNetworkAndCache OpaqueCheck 绕过）
2. **R6-01**: 如果 finding_241 未被报告，写 PoC + VRP
3. **R6-06**: 验证 SAA Handle grant 撤销行为
4. 等待 cross-origin leak agent 结果
