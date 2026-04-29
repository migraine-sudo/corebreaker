# Finding 002: 新发现的漏洞 Pattern（2026-04 最新修复）

## 概述

从最新 Chromium 安全修复 CL（2026-04-13 ~ 2026-04-27）中提取的 4 个新漏洞 pattern。

---

## Pattern 10: Autofill Refill 绕过 Mandatory Reauth

**CL 7762042** — 2026-04-23

**问题**: Autofill 的 refill 机制允许网站先让用户填非敏感字段（如持卡人姓名），autofill
记录填充上下文后，网站动态注入敏感字段（如卡号），refill 机制自动填充这些字段，
绕过 Mandatory Reauth。

**修复**: 从 `FieldTypeGroup` 粒度检查改为 `FieldType` 粒度检查。对信用卡组，
如果初始填充不包含卡号/CVC，refill 不允许填充卡号/CVC。

**搜索策略**: 搜索其他自动填充/重填机制中缺少敏感字段过滤的地方。
```bash
grep -rn "refill\|re.?fill\|auto.*fill\|populate.*again" components/autofill/ --include="*.cc"
```

**泛化**: 任何基于 "初始操作的权限隐含后续操作权限" 的假设都有风险。

---

## Pattern 11: Worker WebSocket Cookie 语义不一致

**CL 7753799** — 2026-04-21

**问题**: SharedWorker 通过 Storage Access API 获取第一方 StorageKey override 后，
创建 WebSocket 连接时直接从 StorageKey 派生 IsolationInfo，未检查
`DoesRequireCrossSiteRequestForCookies()`。导致第三方上下文的 SharedWorker
WebSocket 可以附带 SameSite=Strict/Lax cookies。

**修复**: 添加 `ComputeIsolationInfoForWebSocket()` 方法，在 worker 需要跨站 cookie
语义时清空 `SiteForCookies`。

**审计发现**: 修复使用 feature flag `kRestrictSharedWorkerWebSocketCrossSiteCookies`
保护，**默认 DISABLED**。当前 Chrome release build 中漏洞仍然存在。

**泛化**: Worker 中的网络连接创建路径可能不继承正确的 cookie/isolation 语义。
DedicatedWorker 和 ServiceWorker 的 WebSocket 路径也需要审计。

---

## Pattern 12: Worker 跨域 Script URL 检查不完整

**CL 7784632** — 2026-04-26

**问题**: SharedWorkerServiceImpl 允许 `chrome-extension://` scheme 的页面创建跨域
SharedWorker（通过 `DoesSchemeAllowCrossOriginSharedWorker` 白名单）。被 compromise
的 renderer 可以利用此从 extension/IWA 上下文窃取资源。

**修复**: 为 chrome-extension:// 和 isolated-app:// scheme 添加强制同源检查，
通过 feature flag `kEnforceSharedWorkerSameOriginCheck` 保护。

**审计发现**: 我们的 Chromium clone 中尚未包含此修复。

---

## Pattern 13: CORP 检查使用请求 URL 而非响应 URL

**CL 7792123** — 2026-04-27（非常新）

**问题**: ServiceWorker 静态路由器的缓存源在做 CORP (Cross-Origin Resource Policy)
检查时使用 `resource_request.url` 而非 `response->url_list.back()`。攻击者可以
使用同源别名 URL 绕过跨域响应的 CORP 限制。

**关键代码对比**:

```cpp
// 错误 — service_worker_resource_loader.cc:99-100
CrossOriginResourcePolicy::IsBlockedByHeaderValue(
    resource_request.url, resource_request.url,  // ← 用了 request URL！
    ...);

// 正确 — cache_storage_dispatcher_host.cc:169-170
CrossOriginResourcePolicy::IsBlockedByHeaderValue(
    response->url_list.back(), response->url_list.front(),  // ← 用了 response URL
    ...);
```

**修复**: 使用 `response->url_list.back()` 和 `response->url_list.front()`。
同样通过 feature flag `kServiceWorkerStaticRouterCORPCheck` 保护（默认 DISABLED）。

**搜索策略**: 找所有调用 `CrossOriginResourcePolicy::IsBlockedByHeaderValue` 的地方，
检查 URL 参数是否正确。

---

## 总结

| Pattern | CL | 严重性 | 是否已修复 | 是否可报告 |
|---------|------|--------|-----------|-----------|
| Autofill refill reauth bypass | 7762042 | Medium | 是 | 否（已修复） |
| SharedWorker WebSocket cookie | 7753799 | Medium | 代码在，flag 默认关 | 可能（flag 关闭） |
| SharedWorker 跨域 script | 7784632 | Medium | 我们 clone 没有 | 否（正在修复） |
| CORP request vs response URL | 7792123 | Medium-High | 代码在，flag 默认关 | 可能（flag 关闭） |

### 最有价值的发现方向

1. **找其他 `IsBlockedByHeaderValue` 的调用点** — 是否有其他地方也用了错误的 URL
2. **找其他 Worker 类型** 中缺少 cookie/isolation 语义检查的网络连接路径
3. **找其他 "refill" / "auto-re-do" 机制** 中缺少敏感字段过滤的问题
