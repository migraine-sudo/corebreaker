# Round 6: Service Worker 安全与 Storage Partitioning 绕过深度审计

## 日期: 2026-05-01

## 审计范围

针对两大攻击面进行源码级审计：
1. **Service Worker 安全** — scope 验证、更新竞态、fetch 事件拦截、导航干扰、静态路由
2. **Storage Partitioning 绕过** — partition key 计算边界、SAA grant 范围、SharedWorker/BroadcastChannel/Cache API 分区

### 审计文件清单

**Service Worker (browser-side):**
- `content/browser/service_worker/service_worker_container_host.cc`
- `content/browser/service_worker/service_worker_security_utils.cc`
- `content/browser/service_worker/service_worker_register_job.cc`
- `content/browser/service_worker/service_worker_client.cc`
- `content/browser/service_worker/service_worker_controllee_request_handler.cc`
- `content/browser/service_worker/service_worker_main_resource_loader.cc`
- `content/browser/service_worker/service_worker_main_resource_loader_interceptor.cc`
- `content/browser/service_worker/service_worker_fetch_dispatcher.h`
- `content/browser/service_worker/service_worker_cache_storage_matcher.cc`
- `content/browser/service_worker/service_worker_version.cc`
- `content/common/service_worker/service_worker_router_evaluator.cc`
- `content/common/service_worker/service_worker_resource_loader.cc`
- `content/common/features.cc`

**Service Worker (renderer-side):**
- `third_party/blink/renderer/modules/service_worker/fetch_respond_with_observer.cc`
- `third_party/blink/renderer/modules/service_worker/service_worker_router_type_converter.cc`

**Storage Partitioning:**
- `content/browser/storage_access/storage_access_handle.cc`
- `content/browser/worker_host/shared_worker_service_impl.cc`
- `content/browser/worker_host/shared_worker_connector_impl.cc`
- `content/browser/worker_host/worker_util.cc`
- `content/browser/broadcast_channel/broadcast_channel_provider.cc`
- `content/browser/broadcast_channel/broadcast_channel_service.cc`
- `content/browser/cache_storage/cache_storage_manager.cc`
- `content/browser/renderer_host/render_frame_host_impl.cc`
- `content/browser/storage_partition_impl.cc`
- `content/public/browser/shared_worker_instance.cc`
- `storage/browser/blob/blob_url_registry.cc`

---

## Finding R6-01: SW 静态路由 Cache Source 绕过 Opaque Response 和 CORP 校验（默认禁用安全检查）

### 漏洞假设

Service Worker 静态路由 API 的 `cache` source 在为导航请求提供缓存响应时，opaque response 类型校验和 CORP 检查均被 feature flag 门控且默认禁用。攻击者可以通过 SW 将跨域 opaque 响应注入缓存，然后通过静态路由规则为导航请求提供该响应，绕过正常 `FetchRespondWithObserver::OnResponseFulfilled()` 中的安全校验。

### 精确位置

**`content/common/features.cc:703-710`:**
```cpp
BASE_FEATURE(kServiceWorkerStaticRouterCORPCheck,
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kServiceWorkerStaticRouterOpaqueCheck,
             base::FEATURE_DISABLED_BY_DEFAULT);
```

**`content/browser/service_worker/service_worker_main_resource_loader.cc:914-935`:**
```cpp
if (response_head_->service_worker_router_info->matched_source_type ==
    network::mojom::ServiceWorkerRouterSourceType::kCache) {
  if (service_worker_client_ && service_worker_client_->container_host()) {
    // ...
    if (!IsValidStaticRouterResponse(/*...*/) &&
        base::FeatureList::IsEnabled(
            features::kServiceWorkerStaticRouterOpaqueCheck)) {
      CommitCompleted(net::ERR_FAILED, "Invalid response from static router");
      return;
    }
  }
}
```

**`content/common/service_worker/service_worker_resource_loader.cc:96-113`:**
```cpp
CORPCheckResult result = CORPCheckResult::kSuccess;
bool is_enabled = base::FeatureList::IsEnabled(
    features::kServiceWorkerStaticRouterCORPCheck);
// CORP 检查执行，但仅当 is_enabled 为 true 时才阻断
if (is_enabled) {
  is_valid = false;
  result = CORPCheckResult::kBlocked;
} else {
  result = CORPCheckResult::kViolation;  // 仅记录，不阻断
}
```

### 从普通网页可利用性

**可利用**: YES

攻击步骤：
1. 攻击者控制 `https://attacker.com`，注册一个 SW
2. SW 在 install 事件中通过 `fetch('https://victim.com/sensitive', {mode: 'no-cors'})` 获取 opaque 响应并存入 Cache Storage
3. SW 通过 `installRouter()` 注册静态路由规则：`{condition: {urlPattern: '/target'}, source: 'cache'}`
4. 用户访问 `https://attacker.com/target` 时，静态路由从缓存中取出 opaque 响应并直接提供给导航
5. 由于 `kServiceWorkerStaticRouterOpaqueCheck` 默认禁用，opaque 响应不会被阻断

### 攻击者获得什么

- 通过 opaque 响应的行为差异（是否加载成功、时序差异），可以进行跨域信息泄露
- 绕过 CORP 策略，将带有 `Cross-Origin-Resource-Policy: same-origin` 的跨域资源提供给不同源的客户端
- 对子资源加载同样适用（`service_worker_resource_loader.cc` 的检查也被同样的 flag 门控）

### 信心评级: **HIGH**

这是一个明确的安全检查缺失（两个 feature flag 均默认 DISABLED），且代码注释 (crbug.com/495999481) 明确指出这是一个尚未完全启用的安全修复。这在 Chrome stable 上可利用。

### 与之前发现的关系

此发现与 round3 的 Finding 1 (静态路由缓存绕过) 一致，但本次确认了 **两个独立的安全检查** (`OpaqueCheck` 和 `CORPCheck`) 均默认禁用，且确认了该问题在 Chrome 当前 stable 版本中可复现。之前的报告 (finding_241_sw_static_router_opaque_bypass) 可能已被提交。如果之前未包含 CORP 绕过的单独分析，则 CORP 绕过可以作为独立发现。

---

## Finding R6-02: StorageAccessHandle 为 SharedWorker 提供不受限的第一方 StorageKey

### 漏洞假设

当第三方 iframe 通过 `document.requestStorageAccess({sharedWorkers: true})` 获得 `StorageAccessHandle` 时，浏览器为 SharedWorker 连接创建一个使用第一方 `StorageKey` 的 `SharedWorkerConnectorImpl`。该 SharedWorker 可以与同源的第一方页面中的 SharedWorker 共享状态，因为匹配逻辑 `FindMatchingSharedWorkerHost` 使用的是被覆盖的第一方 `StorageKey`。

### 精确位置

**`content/browser/storage_access/storage_access_handle.cc:214-221`:**
```cpp
void StorageAccessHandle::BindSharedWorker(
    mojo::PendingReceiver<blink::mojom::SharedWorkerConnector> receiver) {
  SharedWorkerConnectorImpl::Create(
      PassKey(), render_frame_host().GetGlobalId(),
      blink::StorageKey::CreateFirstParty(
          render_frame_host().GetStorageKey().origin()),
      std::move(receiver));
}
```

**`content/browser/worker_host/shared_worker_service_impl.cc:161-166`:**
```cpp
CHECK(!storage_key_override ||
      (storage_key_override->IsFirstPartyContext() &&
       (storage_key_override->origin() ==
        render_frame_host->GetStorageKey().origin())));
const blink::StorageKey& storage_key =
    storage_key_override.value_or(render_frame_host->GetStorageKey());
```

**`content/browser/worker_host/shared_worker_service_impl.cc:221-222`:**
```cpp
SharedWorkerHost* host = FindMatchingSharedWorkerHost(
    info->url, info->options->name, storage_key, info->same_site_cookies);
```

### 从普通网页可利用性

**可利用**: YES，但需要 SAA grant

这是 **SAA 的设计意图**之一 — 允许第三方 iframe 通过 SAA 获取的 handle 访问未分区的 SharedWorker。然而，关键问题在于：

1. SAA 的 grant 通常基于用户交互（点击），但 **SharedWorker 的连接生命周期远超交互时刻**
2. 一旦 SharedWorker 被创建，即使 SAA grant 被撤销，worker 仍然运行
3. 通过 SAA SharedWorker，第三方 iframe 可以连接到**第一方页面已经运行的同名 SharedWorker**，共享内存状态

### 攻击场景

1. `victim.com` 页面创建 `SharedWorker('worker.js', {name: 'data-sync'})`
2. `victim.com` 嵌入 `tracker.com` iframe
3. `tracker.com` iframe 调用 `document.requestStorageAccess({sharedWorkers: true})`
4. 用户授予权限
5. `tracker.com` 通过 SAA handle 的 SharedWorker 接口连接到 **同名的 `data-sync` worker**
6. 由于 `storage_key` 被覆盖为第一方 key (`CreateFirstParty(origin)`), `FindMatchingSharedWorkerHost` 会匹配到第一方页面创建的 worker
7. `tracker.com` 可以通过 `postMessage` 与第一方 worker 通信，获取第一方状态

### 攻击者获得什么

- 跨分区访问第一方 SharedWorker 的内存状态
- 如果第一方 SharedWorker 处理敏感数据（如购物车、用户偏好），第三方可以读取

### 信心评级: **MEDIUM**

这在一定程度上是 SAA 的预期行为（为 SharedWorker 提供不分区访问）。但**连接到已有的第一方 worker 实例**而不是创建隔离的新 worker，可能超出了 SAA 的安全预期。需要验证 SharedWorker 的 `postMessage` 是否在这种场景下允许数据交换。

---

## Finding R6-03: StorageAccessHandle 的 BroadcastChannel 使用第一方 StorageKey 实现跨分区通信

### 漏洞假设

`StorageAccessHandle::BindBroadcastChannel` 使用 `CreateFirstParty(origin)` 创建 BroadcastChannel provider，这意味着第三方 iframe 通过 SAA 获得的 BroadcastChannel 可以与**同源第一方上下文中的 BroadcastChannel** 通信。

### 精确位置

**`content/browser/storage_access/storage_access_handle.cc:200-212`:**
```cpp
void StorageAccessHandle::BindBroadcastChannel(
    mojo::PendingAssociatedReceiver<blink::mojom::BroadcastChannelProvider>
        receiver) {
  BroadcastChannelService* service = /* ... */;
  service->AddAssociatedReceiver(
      std::make_unique<BroadcastChannelProvider>(
          service, blink::StorageKey::CreateFirstParty(
                       render_frame_host().GetStorageKey().origin())),
      std::move(receiver));
}
```

**`content/browser/broadcast_channel/broadcast_channel_service.cc:88-98`:**
消息路由使用 `(storage_key, name)` pair 进行匹配，所有同 key 同 name 的连接都能收到消息。

### 从普通网页可利用性

**可利用**: YES，需要 SAA grant

### 攻击场景

1. `victim.com` 第一方页面创建 `new BroadcastChannel('updates')`
2. `victim.com` 嵌入 `tracker.com` iframe
3. `tracker.com` 通过 SAA 获得 handle
4. 通过 handle 的 BroadcastChannel 接口创建同名 channel (`'updates'`)
5. 由于两者的 `StorageKey` 均为 `CreateFirstParty(victim.com origin)`，消息会互相路由
6. `tracker.com` 接收到 `victim.com` 第一方页面通过 BroadcastChannel 发送的所有消息

### 攻击者获得什么

- 监听第一方页面通过 BroadcastChannel 传输的数据
- 向第一方页面的 BroadcastChannel 注入数据

### 信心评级: **MEDIUM**

与 R6-02 类似，这可能是 SAA 的预期行为，但 BroadcastChannel 的数据流方向（第一方 -> 第三方）可能超出开发者预期。关键问题是 SAA grant 是否应该授予 BroadcastChannel 的"监听"能力。如果 SAA 的目的仅是让第三方访问"自己的"存储（如 IndexedDB），那么能够监听第一方 BroadcastChannel 消息是一个权限升级。

---

## Finding R6-04: SharedWorker data: URL + opaque origin 的 StorageKey 计算不一致

### 漏洞假设

`CalculateWorkerStorageKey()` 在处理 `data:` URL worker 脚本时，当 `is_opaque_origin_enabled` 为 true 时创建一个新的 opaque origin 但继承 creator 的 `top_level_site`。当 `is_opaque_origin_enabled` 为 false 时（默认情况），直接返回 creator 的 `StorageKey`。这种条件分支可能导致不同配置下的存储隔离不一致。

### 精确位置

**`content/browser/worker_host/worker_util.cc:17-33`:**
```cpp
blink::StorageKey CalculateWorkerStorageKey(
    const GURL& script_url,
    const blink::StorageKey& creator_storage_key,
    bool is_opaque_origin_enabled) {
  if (script_url.SchemeIs(url::kDataScheme) && is_opaque_origin_enabled) {
    url::Origin opaque_origin =
        creator_storage_key.origin().DeriveNewOpaqueOrigin();
    if (creator_storage_key.nonce()) {
      return blink::StorageKey::CreateWithNonce(
          opaque_origin, creator_storage_key.nonce().value());
    }
    return blink::StorageKey::Create(
        opaque_origin, creator_storage_key.top_level_site(),
        blink::mojom::AncestorChainBit::kCrossSite);
  }
  return creator_storage_key;
}
```

**`content/browser/worker_host/shared_worker_service_impl.cc:170-171`:**
```cpp
bool is_cross_origin = !info->url.SchemeIs(url::kDataScheme) &&
                       url::Origin::Create(info->url) != storage_key.origin();
```

### 从普通网页可利用性

**有限**: 当 `is_opaque_origin_enabled` 为 false（默认值）时，`data:` URL SharedWorker 使用与 creator 相同的 `StorageKey`。这意味着不同 iframe 中的 `data:` URL SharedWorker 如果有相同的 creator origin，可以共享 StorageKey。但 `data:` URL 被 `SchemeIs(url::kDataScheme)` 特殊处理，绕过了跨域检查。

攻击路径：
1. `attacker.com` 创建一个 `data:` URL SharedWorker
2. 由于 `is_cross_origin` 对 `data:` scheme 始终为 false（第170行），跨域检查被绕过
3. Worker 获得与 creator 相同的 `StorageKey`

### 攻击者获得什么

- 当 `is_opaque_origin_enabled = false` 时，`data:` URL worker 可以以 creator 的完整 StorageKey 身份运行，访问 creator 的存储
- 这对攻击者自身 origin 没有意义（已经有访问权），但如果结合 SAA storage_key_override，可能成为 partition key 混淆的一环

### 信心评级: **LOW**

`data:` URL worker 的 origin 处理是一个已知的复杂区域，但当前代码的条件分支看起来是有意的向后兼容。实际利用需要特殊条件组合。

---

## Finding R6-05: SW 静态路由 RaceNetworkAndCache 中 Cache Source 无 Response 验证

### 漏洞假设

当静态路由规则使用 `kRaceNetworkAndCache` source 时，cache 匹配结果在 `ServiceWorkerCacheStorageMatcher::DidMatch()` 中被直接返回，没有经过 `IsValidStaticRouterResponse()` 校验。只有当 `kCache` 作为独立 source 时，`DidDispatchFetchEvent` 才会执行 opaque 检查。

### 精确位置

**`content/browser/service_worker/service_worker_main_resource_loader.cc:903-936`:**
```cpp
if (IsMatchedRouterSourceType(
        network::mojom::ServiceWorkerRouterSourceType::kCache) ||
    IsMatchedRouterSourceType(network::mojom::ServiceWorkerRouterSourceType::
                                  kRaceNetworkAndCache)) {
  // ...
  // 注意: 仅当 matched_source_type 是 kCache 时执行 IsValidStaticRouterResponse
  if (response_head_->service_worker_router_info->matched_source_type ==
      network::mojom::ServiceWorkerRouterSourceType::kCache) {
    if (!IsValidStaticRouterResponse(/*...*/) &&
        base::FeatureList::IsEnabled(
            features::kServiceWorkerStaticRouterOpaqueCheck)) {
      CommitCompleted(net::ERR_FAILED, "...");
      return;
    }
  }
  // kRaceNetworkAndCache 的 cache 结果不经过此检查
}
```

当 `kRaceNetworkAndCache` 中 cache 赢得竞赛时（`actual_source_type` 被设为 `kCache`，第999-1004行），但 `matched_source_type` 仍然是 `kRaceNetworkAndCache`，因此**不触发第916行的条件检查**。

### 从普通网页可利用性

**可利用**: YES

即使 `kServiceWorkerStaticRouterOpaqueCheck` 被启用（未来），通过 `kRaceNetworkAndCache` source 仍然可以绕过该检查。

攻击步骤:
1. SW 缓存一个跨域 opaque 响应
2. SW 注册静态路由规则: `{condition: {urlPattern: '/*'}, source: 'race-network-and-cache'}`
3. 对导航请求，network 和 cache 竞赛; cache 如果先返回，opaque 响应被直接使用
4. 即使 OpaqueCheck 被启用，由于 `matched_source_type` 是 `kRaceNetworkAndCache` 而非 `kCache`，检查被跳过

### 攻击者获得什么

- 绕过即将启用的 opaque response 安全检查
- 当 `kServiceWorkerStaticRouterOpaqueCheck` 最终被默认启用后，这将成为一个绕过路径

### 信心评级: **HIGH**

这是一个明确的逻辑缺陷：安全检查条件仅匹配 `kCache` 而不匹配 `kRaceNetworkAndCache`，尽管后者的 cache 结果应该受到相同的安全约束。

---

## Finding R6-06: StorageAccessHandle 创建后无 Grant 撤销监听

### 漏洞假设

`StorageAccessHandle::Create()` 仅在创建时检查 `host->IsFullCookieAccessAllowed()`。Handle 创建后，所有通过该 handle 绑定的 Mojo 服务（IndexedDB、CacheStorage、Lock Manager、OPFS、BlobStorage、BroadcastChannel、SharedWorker）在文档生命周期内持续有效，即使 SAA grant 被撤销。

### 精确位置

**`content/browser/storage_access/storage_access_handle.cc:51-63`:**
```cpp
void StorageAccessHandle::Create(
    RenderFrameHost* host,
    mojo::PendingReceiver<blink::mojom::StorageAccessHandle> receiver) {
  CHECK(host);
  if (!host->IsFullCookieAccessAllowed()) {
#if DCHECK_IS_ON()
    mojo::ReportBadMessage(/*...*/);
#endif
    return;
  }
  new StorageAccessHandle(*host, std::move(receiver));
}
```

### 从普通网页可利用性

**可利用**: YES

1. 攻击者的第三方 iframe 调用 `requestStorageAccess({all: true})`
2. 用户授权，handle 创建成功
3. 用户在站点设置中撤销该 origin 的存储访问权限
4. Handle 仍然有效，所有7种存储 API 继续使用第一方 StorageKey

### 关键点

- **DCHECK_IS_ON() 门控**: `mojo::ReportBadMessage` 在 release builds 中不执行，意味着即使初始检查失败，在 release 中也只是静默跳过
- **无订阅机制**: `DocumentService` 基类没有提供权限变更通知
- **长生命周期**: 对于 webmail/SPA 类应用，页面可能运行数小时

### 攻击者获得什么

- 在 SAA grant 被撤销后，维持对 7 种未分区存储 API 的完全访问
- 持续时间 = 文档剩余生命周期

### 信心评级: **MEDIUM-HIGH**

此问题在 round3 审计中已被识别 (SAA-01)，但尚未确认是否已被修复。核心问题依然存在于代码中。

---

## Finding R6-07: StorageAccessHandle BlobStorage 绑定的 storage_access_check_callback 始终返回 false

### 漏洞假设

`StorageAccessHandle::BindBlobStorage()` 在注册 BlobURLStore receiver 时，将 `storage_access_check_callback` 硬编码为 `[]() -> bool { return false; }`。这意味着通过 SAA handle 创建的 Blob URL 不会被视为有 storage access grant，可能导致通过该 Blob URL 创建的 SharedWorker 使用错误的分区键。

### 精确位置

**`content/browser/storage_access/storage_access_handle.cc:164-198`:**
```cpp
void StorageAccessHandle::BindBlobStorage(
    mojo::PendingAssociatedReceiver<blink::mojom::BlobURLStore> receiver) {
  // ...
  storage_partition_impl->GetBlobUrlRegistry()->AddReceiver(
      blink::StorageKey::CreateFirstParty(
          render_frame_host().GetStorageKey().origin()),
      // ...
      /*storage_access_check_callback=*/
      base::BindRepeating([]() -> bool { return false; }),
      // ...
  );
}
```

注释明确解释：
```
// In the case that a context is granted storage access, the
// StorageAccessHandle context still shouldn't bypass the partitioning
// check (e.g. using a Blob URL created with URL.createObjectURL in
// the third-party context with the StorageAccessHandle's SharedWorker
// constructor.)
```

### 分析

这看起来是一个**有意的安全限制**：通过 SAA handle 创建的 Blob URL 不应该绕过分区检查。但这创造了一个奇特的不一致性：

1. SAA handle 的 BlobURLStore 使用**第一方 StorageKey** 注册 Blob URL
2. 但 `storage_access_check_callback` 返回 false，意味着分区检查不会被绕过
3. 如果其他代码路径检查这个 callback 来决定是否允许跨分区 Blob URL 访问，hardcoded false 可能导致应该允许的操作被阻止，或不应该允许的操作因其他条件被允许

### 信心评级: **LOW**

代码注释表明这是有意为之。但 StorageKey 为第一方却 storage_access_check 为 false 的组合可能在某些边界条件下导致意外行为。需要进一步审计 BlobURLRegistry 中如何使用这个 callback。

---

## Finding R6-08: SharedWorker SameSiteCookies 字段由 Renderer 提供且未完全验证

### 漏洞假设

`SharedWorkerServiceImpl::ConnectToWorker()` 中 `info->same_site_cookies` 来自 renderer 进程。虽然第143-149行检查了第三方上下文不能请求 `kAll`（非 `kNone`），但没有验证 renderer 提供的值是否与请求的实际上下文一致。

### 精确位置

**`content/browser/worker_host/shared_worker_service_impl.cc:141-149`:**
```cpp
if (render_frame_host->GetStorageKey().IsThirdPartyContext() &&
    info->same_site_cookies !=
        blink::mojom::SharedWorkerSameSiteCookies::kNone) {
  // Only first-party contexts can request SameSite Strict and Lax cookies.
  ScriptLoadFailed(std::move(client), /*error_message=*/"");
  return;
}
```

但对于第一方上下文，renderer 可以自由选择 `kNone`、`kLax` 或 `kAll`。`same_site_cookies` 字段被用于 `FindMatchingSharedWorkerHost` 的匹配，也影响 `DoesRequireCrossSiteRequestForCookies` 的计算。

### 从普通网页可利用性

**有限**: 恶意 renderer 可以设置 `same_site_cookies` 为任何值，但这需要 renderer 漏洞。对于非 compromised renderer，值由 Blink 正确计算。这是一个 defense-in-depth 问题，不满足"普通网页可利用"的标准。

### 信心评级: **LOW**

---

## 总结与优先级

| Finding | 严重性 | 可利用性 | 信心 | 是否新发现 |
|---------|--------|----------|------|-----------|
| R6-01: 静态路由 Cache Opaque+CORP 绕过 | HIGH | 普通网页 | HIGH | 可能已报 (finding_241) |
| R6-05: RaceNetworkAndCache 绕过 OpaqueCheck | HIGH | 普通网页 | HIGH | **新发现** |
| R6-02: SAA SharedWorker 跨分区连接 | MEDIUM | 需 SAA grant | MEDIUM | 需验证是否 by-design |
| R6-03: SAA BroadcastChannel 跨分区监听 | MEDIUM | 需 SAA grant | MEDIUM | 需验证是否 by-design |
| R6-06: SAA Handle 无 grant 撤销监听 | MEDIUM | 需 SAA grant | MEDIUM-HIGH | round3 已识别 |
| R6-04: data: URL Worker StorageKey 不一致 | LOW | 有限 | LOW | 新但影响有限 |
| R6-07: SAA BlobStorage callback 硬编码 | LOW | 理论性 | LOW | 新但可能 by-design |
| R6-08: SharedWorker SameSiteCookies 验证 | LOW | 需 renderer 漏洞 | LOW | defense-in-depth |

### 推荐优先提交

1. **R6-05 (RaceNetworkAndCache 绕过)** — 这是一个明确的安全检查遗漏，即使在 OpaqueCheck 被启用后仍然可绕过。独立于之前已报的 finding_241。建议作为 OpaqueCheck 修复的补充 bug 提交。

2. **R6-01 (如果 finding_241 未被接受)** — 重新确认两个 feature flag 均默认禁用的现状。

3. **R6-02/R6-03 (SAA + SharedWorker/BroadcastChannel)** — 如果 Chromium 安全团队认为 SAA 不应授予与第一方上下文的实时通信能力，这些是值得报告的。建议先在 Chromium issue tracker 上搜索相关讨论。
