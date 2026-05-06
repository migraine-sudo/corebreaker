# Round 6: 跨域信息泄露侧信道审计

审计时间: 2026-05-01
审计目标: Chromium 新 Web API 中的跨域信息泄露侧信道
审计范围: measureUserAgentSpecificMemory, scheduler.postTask/yield, Resource Timing, BFCache, Speculation Rules, Storage Access API

---

## Finding R6-1: Resource Timing encodedBodySize/decodedBodySize TAO 绕过(条件性)

### 严重程度: 中

### 文件位置
- `third_party/blink/renderer/core/timing/performance_resource_timing.cc` 第 513-519 行
- `third_party/blink/renderer/platform/loader/fetch/resource_timing_utils.cc` 第 128-138 行
- `third_party/blink/renderer/platform/runtime_enabled_features.json5` 第 4834 行

### 漏洞描述

`PerformanceResourceTiming` 中的 `encodedBodySize()` 和 `decodedBodySize()` getter 方法**没有在访问时检查 `allow_timing_details`（即 TAO 检查）**，而几乎所有其他敏感字段（`domainLookupStart`, `connectStart`, `requestStart`, `responseStart`, `transferSize` 等）都在 getter 中进行了 TAO 检查。

```cpp
// performance_resource_timing.cc:513-519 - 无任何访问控制检查
uint64_t PerformanceResourceTiming::encodedBodySize() const {
  return info_->encoded_body_size;
}

uint64_t PerformanceResourceTiming::decodedBodySize() const {
  return info_->decoded_body_size;
}
```

对比 `transferSize()` 的实现（有 TAO 检查）:
```cpp
// performance_resource_timing.cc:505-511
uint64_t PerformanceResourceTiming::transferSize() const {
  if (!info_->allow_timing_details) {  // <-- TAO 检查
    return 0;
  }
  return GetTransferSize(info_->encoded_body_size, info_->cache_state);
}
```

### 数据填充侧的保护

在 `resource_timing_utils.cc` 第 128-138 行，body size 的填充受到特性开关 `ResourceTimingUseCORSForBodySizesEnabled` 控制:

```cpp
bool expose_body_sizes =
    RuntimeEnabledFeatures::ResourceTimingUseCORSForBodySizesEnabled()
        ? allow_response_details       // CORS same-origin 检查
        : info->allow_timing_details;  // TAO 检查

if (expose_body_sizes && response) {
  info->encoded_body_size = response->EncodedBodyLength();
  info->decoded_body_size = response->DecodedBodyLength();
}
```

当前 `ResourceTimingUseCORSForBodySizes` 特性开关状态为 `"test"`（第 4835 行），意味着在生产环境中**默认未启用**。在当前默认配置下，body size 的填充依赖 `allow_timing_details`（TAO），所以如果 TAO 未通过，`encoded_body_size` 和 `decoded_body_size` 在 mojom 结构中默认为 0。

**但是**，对于子框架导航（iframe），在 `document_loader.cc` 第 1371-1378 行存在不同的逻辑:

```cpp
if (!RuntimeEnabledFeatures::ResourceTimingUseCORSForBodySizesEnabled() ||
    (IsSameOriginInitiator() &&
     !document_load_timing_.HasCrossOriginRedirect())) {
  resource_timing_info_for_parent_->encoded_body_size = total_encoded_body_length;
  resource_timing_info_for_parent_->decoded_body_size = total_decoded_body_length;
}
```

当 `ResourceTimingUseCORSForBodySizes` 未启用（默认情况）时，**此代码无条件地填充 body size**（只要 TAO 通过就会创建 `resource_timing_info_for_parent_`，见第 3175 行）。这意味着对于设置了 TAO 但非同源的跨域 iframe 导航，body size 会被暴露。

### 潜在利用场景

当 `ResourceTimingUseCORSForBodySizes` 特性开关最终在生产环境启用时（从 `"test"` 变为 `"stable"`），一个新的风险会出现：

1. 当前 (test 状态): TAO 检查在填充侧保护了 body size
2. 未来 (stable 状态): 将使用 CORS same-origin 检查替代 TAO 检查
3. 无论哪种情况，getter 侧都没有任何保护 -- 完全依赖填充侧

如果填充逻辑有任何 bug 导致 body size 被设置为非零值而不应该被设置，getter 侧无法阻止泄露。这是一个纵深防御缺失。

### 攻击者观察到什么
- 跨域资源的精确字节大小（如果 TAO 通过但不应暴露 body size 的场景）
- 在某些边缘情况下，responseStatus, contentType, contentEncoding 也通过类似的 "仅在填充侧保护" 模式暴露

### 泄露什么信息
- 跨域页面的精确响应体大小
- 结合不同请求参数，可以推断用户状态（登录/未登录状态下页面大小不同）

### 可利用性评估
**中等偏低**。当前在填充侧有 TAO 保护，但 getter 侧的缺失保护是一个架构弱点。当 `ResourceTimingUseCORSForBodySizes` 启用后，保护从 TAO 降级为 CORS same-origin，可能引入新的泄露路径。

### 已知追踪
- 存在特性开关 `ResourceTimingUseCORSForBodySizes` 正在过渡中（status: "test"），说明团队已意识到这个问题
- 这是 spec 层面的变更 (W3C Resource Timing)

---

## Finding R6-2: BFCache NotRestoredReasons 跨域 iframe 存在性/数量泄露

### 严重程度: 低-中

### 文件位置
- `content/browser/renderer_host/back_forward_cache_impl.cc` 第 2304-2332 行
- `third_party/blink/renderer/core/timing/not_restored_reasons.cc` 第 44-60 行
- `third_party/blink/renderer/core/timing/performance_navigation_timing.cc` 第 267-315 行

### 漏洞描述

`NotRestoredReasons` API 在报告 BFCache 未恢复原因时，虽然对跨域 iframe 的具体原因进行了 masking（使用 "masked" 字符串），但仍然暴露了以下跨域信息:

1. **跨域 iframe 的 `src`, `id`, `name` 属性** (第 2328-2331 行):
```cpp
// Report src, id and name for both cross-origin and same-origin frames.
not_restored_reasons->src = src_;
not_restored_reasons->id = id_;
not_restored_reasons->name = name_;
```

注释解释说这些信息 "only sent to the main frame's renderer, which already knew it on the previous visit"，但这里有一个微妙的信息泄露 -- 如果在用户离开页面后到返回之前，嵌入的跨域 iframe 列表发生了变化（例如通过 JavaScript 动态添加或服务端渲染不同内容），那么 NotRestoredReasons 返回的子树结构就会泄露**上次访问时**的 iframe 配置信息。

2. **跨域子树中哪个 iframe 阻止了 BFCache**（当 `kAllowCrossOriginNotRestoredReasons` 启用时）:

```cpp
if (!FlattenTree().CanRestore() && exposed_cross_origin_iframe_index == 0 &&
    base::FeatureList::IsEnabled(kAllowCrossOriginNotRestoredReasons)) {
  // ... 标记 "masked" 到随机选中的跨域 iframe
}
```

虽然使用了随机选择来限制暴露（`exposed_cross_origin_iframe_index`），但跨域 iframe 是否包含 "masked" 原因本身就是一个信息位 -- 它告诉攻击者**某个特定的跨域 iframe 是否阻止了 BFCache 恢复**。

3. **`reasons()` 和 `children()` 的 null vs 空数组差异** (not_restored_reasons.cc 第 44-60 行):

```cpp
const std::optional<HeapVector<Member<NotRestoredReasonDetails>>>
NotRestoredReasons::reasons() const {
  if (!url_) {
    // If url_ is null, this is for cross-origin and reasons should be masked.
    return std::nullopt;
  }
  return reasons_;
}
```

跨域 iframe 返回 `null`，同源 iframe 返回数组（可能为空）。这本身就区分了 iframe 是同源还是跨域 -- 虽然主页面通常已经知道这一点。

### 攻击者观察到什么
- 跨域 iframe 的结构信息（src/id/name）
- 跨域 iframe 是否是 BFCache 恢复失败的原因
- 通过时间差异（BFCache 是否恢复成功 vs 重新加载），推断跨域 iframe 的内部状态

### 泄露什么信息
- 跨域 iframe 使用的 Web API（BroadcastChannel, WebSocket, WebLock 等）的存在性
- 跨域 iframe 是否有 unload handler
- 跨域 iframe 是否使用了 Cache-Control: no-store

### 可利用性评估
**低**。`kAllowCrossOriginNotRestoredReasons` 默认未启用（`FEATURE_DISABLED_BY_DEFAULT`），且 masking 机制通过随机选择限制了暴露。但在启用该特性后，信息泄露更明显。主要风险在于跨域 iframe 的**行为模式**（使用了哪些 Web API）可能被推断。

### 已知追踪
- `kAllowCrossOriginNotRestoredReasons` 特性本身就是为了在安全性和开发者可调试性之间取得平衡
- 注释中的讨论表明团队意识到了此问题

---

## Finding R6-3: hasStorageAccess() 同步 IPC 时间差可探测 Cookie 访问状态

### 严重程度: 低

### 文件位置
- `third_party/blink/renderer/modules/storage_access/document_storage_access.cc` 第 131-180 行
- `third_party/blink/renderer/core/dom/document.cc` 第 6819-6826 行
- `third_party/blink/renderer/core/loader/cookie_jar.cc` 第 263-280 行

### 漏洞描述

`hasStorageAccess()` 的实现在第 151-179 行是**同步**的 -- 它创建一个 resolver 并立即用一个 lambda 表达式的返回值 resolve:

```cpp
auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLBoolean>>(script_state);
auto promise = resolver->Promise();
resolver->Resolve([&]() -> bool {
    // 各种检查...
    return GetSupplementable()->CookiesEnabled();
}());
```

`CookiesEnabled()` 最终调用 `CookieJar::CookiesEnabled()`，这是一个**同步 Mojo IPC 调用**:
```cpp
backend_->CookiesEnabledFor(
    cookie_url, document_->SiteForCookies(), document_->TopFrameOrigin(),
    document_->GetExecutionContext()->GetStorageAccessApiStatus(),
    ShouldApplyDevtoolsOverrides(), &cookies_enabled);
```

这个同步 IPC 有两个时间路径:
1. 如果在 lambda 中的早期检查（opaque origin, credentialless, insecure context）就返回 false，不会触发 IPC
2. 如果通过所有检查到达 `CookiesEnabled()`，会触发同步 IPC

同时，`CookiesEnabledFor()` 的浏览器侧实现会根据 `StorageAccessApiStatus` 参数（即是否已通过 Storage Access API 获得了 cookie 访问权限）返回不同结果，而这个调用的延迟可能因为缓存命中/未命中而有微秒级差异。

### 攻击者观察到什么
- 可以通过嵌入 cross-origin iframe 并让该 iframe 调用 `hasStorageAccess()`，然后通过 `postMessage` 返回结果
- 结果直接告诉攻击者该 iframe 是否有 unpartitioned cookie 访问权限
- 但这不是时间侧信道 -- `hasStorageAccess()` 的设计就是返回 boolean

### 实际上这不是漏洞
`hasStorageAccess()` **被设计为**返回当前文档的存储访问状态，它只能在嵌入的 iframe 自身内调用，返回的是该 iframe **自己的**状态。攻击者无法通过 `hasStorageAccess()` 探测**其他**第三方的访问状态。

### 可利用性评估
**不可利用**。这是 API 的正常行为，不是信息泄露。第三方 iframe 只能查询自己的存储访问状态，而非其他第三方的状态。跨域主页面无法直接调用子 iframe 的 `hasStorageAccess()`。

---

## Finding R6-4: SpeculationData/PreloadData URL 泄露预加载资源信息

### 严重程度: 低

### 文件位置
- `third_party/blink/renderer/core/timing/window_performance.cc` 第 1619-1637 行
- `third_party/blink/renderer/core/timing/preload_data.h` 第 33 行
- `third_party/blink/renderer/core/timing/preload_data.cc` 第 38-48 行

### 漏洞描述

`performance.getSpeculations()` API（2026 年新增，版权标注 2026）暴露了当前页面的预加载记录，包括:

```cpp
SpeculationData* WindowPerformance::getSpeculations() {
  // ...
  const auto& preload_records = window->document()->Fetcher()->GetPreloadRecords();
  for (const auto& [url, info] : preload_records) {
    preloads.push_back(MakeGarbageCollected<PreloadData>(
        url, info.resource_type,
        info.crossorigin.value_or(kCrossOriginAttributeNotSet),
        info.used_time));
  }
}
```

暴露的字段:
- `url()`: 预加载资源的完整 URL
- `as()`: 资源类型（script, style, image 等）
- `crossorigin()`: 跨域属性设置
- `used(script_state)`: 预加载是否被使用以及使用时间

### 安全分析

这个 API 暴露的是**当前页面自己的**预加载记录，而非跨域页面的。攻击者如果能执行 JavaScript，已经可以通过 `<link rel="preload">` 元素本身获取类似信息。

`used()` 的时间戳可能在 `<link rel="preload">` 被另一个页面触发 prefetch 后，泄露是否有其他页面预先预取了该资源（命中了 HTTP 缓存），但这需要:
1. 另一个同源页面使用了 Speculation Rules 预取了该资源
2. 当前页面使用 `<link rel="preload">` 请求了同一个资源

在这种情况下，`used_time` 的差异（极快 vs 正常网络延迟）可以泄露缓存状态。但由于这限于同源资源，风险有限。

### 可利用性评估
**极低**。此 API 仅暴露当前页面自己的预加载记录，且是新 API（可能尚未在稳定版中发布）。

---

## Finding R6-5: BFCache Restoration 时间条目精确时间戳泄露恢复耗时

### 严重程度: 低

### 文件位置
- `third_party/blink/renderer/core/timing/back_forward_cache_restoration.cc` 第 11-23 行
- `third_party/blink/renderer/core/timing/performance.cc` 第 805-823 行

### 漏洞描述

`BackForwardCacheRestoration` performance entry 暴露了三个精确时间戳:
- `startTime`: BFCache 恢复开始时间
- `pageshowEventStart`: pageshow 事件派发开始时间
- `pageshowEventEnd`: pageshow 事件派发结束时间

```cpp
BackForwardCacheRestoration::BackForwardCacheRestoration(
    DOMHighResTimeStamp start_time,
    DOMHighResTimeStamp pageshow_event_start,
    DOMHighResTimeStamp pageshow_event_end, ...)
```

`pageshowEventEnd - pageshowEventStart` 的差值暴露了 pageshow 事件处理器的执行时间。如果同源页面 A 有一个嵌入了跨域 iframe B 的场景:

1. 页面 A + iframe B 进入 BFCache
2. 用户返回 -> 从 BFCache 恢复
3. 恢复过程中，如果 iframe B 的 pageshow handler 执行时间较长（因为需要重新建立 WebSocket 连接等），这个延迟会反映在页面 A 的 restoration 条目中
4. 页面 A 可以通过 `performance.getEntriesByType('back-forward-cache-restoration')` 获取这些时间

### 攻击者观察到什么
- BFCache 恢复的总耗时
- pageshow 事件处理的总耗时

### 泄露什么信息
- 跨域 iframe 的 pageshow 事件处理器复杂度
- 但这些时间受到 TimeClamper 保护（coarse resolution 100us 或 fine resolution 5us）

### 可利用性评估
**极低**。时间戳受到 coarsening 保护，且 BFCache restoration 条目仅报告给恢复的页面本身（同源）。跨域 iframe 的恢复时间可能影响整体恢复耗时，但这与浏览器导航本身的固有特性一致，难以构建可靠的侧信道。

### 已知追踪
- BFCache restoration timing 受 `NavigationId` 特性开关保护（performance.cc 第 372 行）

---

## Finding R6-6: scheduler.yield() 跨帧优先级继承检查可探测帧关系

### 严重程度: 不可利用

### 文件位置
- `third_party/blink/renderer/core/scheduler/dom_scheduler.cc` 第 195-224 行

### 漏洞描述

`scheduler.yield()` 的实现中，`GetSchedulerTaskContextForYield()` 会尝试继承当前任务的调度上下文（包括 abort signal 和 priority signal）:

```cpp
SchedulerTaskContext* DOMScheduler::GetSchedulerTaskContextForYield() {
  auto* inherited_state = TaskAttributionTaskState::GetCurrent(...);
  // ...
  bool can_use_context = task_context->CanPropagateTo(*GetExecutionContext());
  // Record use counters for non-trivial inheritance, i.e. cases where the
  // inheritance can change the scheduling in a meaningful way.
  // ...
  UseCounter::Count(
      GetExecutionContext(),
      can_use_context
          ? WebFeature::kSchedulerYieldNonTrivialInherit
          : WebFeature::kSchedulerYieldNonTrivialInheritCrossFrameIgnored);
}
```

`CanPropagateTo()` 检查防止了跨帧优先级继承。当跨帧继承被忽略时，虽然会记录 UseCounter，但这不会泄露给 JavaScript。任务调度顺序本身不受跨域帧影响（每个帧有自己的调度队列）。

### 可利用性评估
**不可利用**。scheduler API 的设计正确地隔离了跨帧调度上下文。

---

## Finding R6-7: measureUserAgentSpecificMemory() 跨域聚合内存与随机化保护

### 严重程度: 不可利用（设计正确）

### 文件位置
- `third_party/blink/renderer/core/timing/measure_memory/measure_memory_controller.cc` 第 48-58, 130, 225-238, 288-319 行

### 漏洞描述

`measureUserAgentSpecificMemory()` 对跨域 iframe 的处理:

1. **要求 cross-origin isolation** (第 130 行):
```cpp
DCHECK(execution_context->CrossOriginIsolatedCapability());
```
只有在设置了 COOP+COEP 的跨域隔离环境中才能调用。

2. **跨域 URL masking** (第 48, 228-231 行):
```cpp
constexpr const char* kCrossOriginUrl = "cross-origin-url";
// ...
if (attribution->url) {
  result->setUrl(attribution->url);
} else {
  result->setUrl(kCrossOriginUrl);
}
```
跨域 iframe 的 URL 被替换为 "cross-origin-url"。

3. **结果随机化** (第 310 行):
```cpp
std::shuffle(breakdown.begin(), breakdown.end(), RandomBitGenerator{});
```
breakdown 条目的顺序被随机化。

4. **scope 标记** (第 53 行):
```cpp
constexpr const char* kScopeCrossOriginAggregated = "cross-origin-aggregated";
```

### 安全分析

虽然跨域 iframe 的**内存大小**仍然被报告（只是 URL 被 mask），攻击者可以通过以下方式推断跨域 iframe 的内存使用:

- 嵌入一个已知的跨域 iframe
- 调用 `measureUserAgentSpecificMemory()`
- 在 breakdown 中找到 `scope: "cross-origin-aggregated"` 的条目
- 对比有/无该 iframe 时的 total bytes 差异

但这需要 **cross-origin isolation** (COOP+COEP)，大大限制了攻击面。在 COOP+COEP 环境下，跨域 iframe 已经需要 CORP 或 COEP:credentialless，进一步限制了可嵌入的跨域内容。

### 可利用性评估
**不可利用**。cross-origin isolation 要求使得攻击场景极其受限。

---

## 总结

| Finding | 描述 | 严重程度 | 可利用性 |
|---------|------|----------|----------|
| R6-1 | Resource Timing encodedBodySize/decodedBodySize getter 缺少 TAO 检查 | 中 | 中偏低 (填充侧有保护) |
| R6-2 | BFCache NotRestoredReasons 跨域 iframe 信息泄露 | 低-中 | 低 (feature 默认关闭) |
| R6-3 | hasStorageAccess() 时间差 | 低 | 不可利用 |
| R6-4 | SpeculationData/PreloadData URL 暴露 | 低 | 极低 |
| R6-5 | BFCache Restoration 精确时间戳 | 低 | 极低 |
| R6-6 | scheduler.yield() 跨帧优先级继承 | 不可利用 | 不可利用 |
| R6-7 | measureUserAgentSpecificMemory() | 不可利用 | 不可利用 (需要 COI) |

### 建议优先关注

1. **R6-1** 是最值得关注的发现。虽然当前在填充侧有保护，但 getter 侧的纵深防御缺失是一个可以提交的 bug。特别是当 `ResourceTimingUseCORSForBodySizes` 从 test 过渡到 stable 时，需要确保所有路径都正确保护了 body size。此外，`document_loader.cc` 中子框架导航的 body size 填充逻辑（第 1371-1378 行）在特性开关关闭时无条件填充，这可能是一个值得深入研究的路径。

2. **R6-2** 在 `kAllowCrossOriginNotRestoredReasons` 启用后会更有价值。目前特性默认关闭，但随着 BFCache 调试需求增加，该特性可能会被默认启用。
