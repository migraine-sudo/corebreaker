# Finding 003: Service Worker Static Router 安全检查系统性缺陷

## 概述

Service Worker Static Router 是一个相对较新的功能，允许在不唤醒 Service Worker 的情况下
直接从 CacheStorage 返回响应。该功能的多个安全检查 **虽然代码已存在，但被 Feature Flag
默认关闭**，导致当前 Chrome release build 中存在可利用的安全漏洞。

## 发现列表

### 1. CORP 检查使用错误的 URL (CL 7792123)

**文件**: `content/common/service_worker/service_worker_resource_loader.cc:99-100`

```cpp
// 错误代码 — 使用 request URL 而非 response URL
if (network::CrossOriginResourcePolicy::IsBlockedByHeaderValue(
    resource_request.url, resource_request.url,  // ← BUG
    resource_request.request_initiator, corp_header_value, ...))
```

**正确代码** (cache_storage_dispatcher_host.cc:169):
```cpp
CrossOriginResourcePolicy::IsBlockedByHeaderValue(
    response->url_list.back(), response->url_list.front(),  // ← 正确
    document_origin, corp_header_value, ...)
```

**Feature Flag**: `kServiceWorkerStaticRouterCORPCheck` — **默认 DISABLED**

**影响**: 攻击者可以通过 SW 静态路由器的 cache source 绕过 CORP 限制，
从跨域缓存中读取设置了 `Cross-Origin-Resource-Policy: same-origin` 的响应。

**攻击场景**:
1. 攻击者控制的网站注册 Service Worker，配置静态路由指向 cache source
2. Cache 中存储了跨域资源的 opaque response（带有 CORP header）
3. 攻击者创建同源别名 URL（例如通过 Service Worker Scope + 路径匹配）
4. CORP 检查使用 request URL（同源），绕过 response URL（跨域）的 CORP 限制

### 2. Opaque Response 检查缺失 (crbug.com/495999481)

**文件**: 
- `content/browser/service_worker/service_worker_main_resource_loader.cc:928-929`
- `content/renderer/service_worker/service_worker_subresource_loader.cc:1508-1509`

**Feature Flag**: `kServiceWorkerStaticRouterOpaqueCheck` — **默认 DISABLED**

**影响**: SW 静态路由器可以返回 opaque response 给 navigation 请求，
这违反了 Fetch 规范（navigation 请求不应收到 opaque response）。
可能导致跨域资源被不正确地加载到 navigation 上下文中。

### 3. 其他 `IsBlockedByHeaderValue` 调用点审计结果

| 调用点 | URL 参数 | 状态 |
|--------|---------|------|
| cache_storage_dispatcher_host.cc:169 | `response->url_list.back/front()` | **正确** |
| cross_origin_resource_policy_checker.cc:48 (Blink) | `response.InternalURLList().back/front()` | **正确** |
| service_worker_resource_loader.cc:99 | `resource_request.url` (重复) | **错误** |

**结论**: 只有 SW static router 路径使用了错误的 URL。

## 可报告性分析

### 问题 1 (CORP bypass)
- **严重性**: Medium-High
- **可利用性**: 需要 SW + CacheStorage + 特定的 URL 配置
- **Feature Flag 状态**: 修复代码已存在但默认关闭 → Chromium 团队已知
- **VRP 可报告性**: 低 — Chromium 团队自己发现并在修复中

### 问题 2 (Opaque response)
- **严重性**: Medium
- **可利用性**: 需要 SW static router + cache source 配置
- **Feature Flag 状态**: 修复代码已存在但默认关闭 → Chromium 团队已知
- **VRP 可报告性**: 低 — 同上

## Worker WebSocket Cookie 语义问题 (关联)

**文件**: `content/browser/worker_host/shared_worker_host.cc:710-724`

**Feature Flag**: `kRestrictSharedWorkerWebSocketCrossSiteCookies` — **默认 DISABLED**

SharedWorker 通过 Storage Access API 获取第一方 StorageKey override 后，
WebSocket 连接仍然附带 SameSite=Strict/Lax cookies。

**对比**: DedicatedWorker 直接继承 ancestor frame 的 IsolationInfo（line 793），不受此影响。
ServiceWorker 使用 `storage_key.ToPartialNetIsolationInfo()` 但没有 Storage Access API
场景，也不受影响。

## 结论

这些发现虽然是真实的安全问题，但 **Chromium 团队已经知道并在逐步修复中**
（通过 Feature Flag 收集数据后将逐步启用）。作为 VRP 报告价值有限。

## 更有价值的审计方向

1. **寻找 Feature Flag 没有覆盖到的变体** — 例如 SW static router 的其他 source type
   （kNetwork, kRaceNetworkAndCache）是否也有类似问题
2. **寻找完全未被发现的问题** — 不在已知修复列表中的新 bug
3. **聚焦 Privacy Sandbox 新功能** — Fenced Frames, Topics, Attribution Reporting 等
   新代码中更容易有未发现的漏洞
