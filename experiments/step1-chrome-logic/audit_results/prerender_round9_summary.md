# Round 9: Speculation Rules / Prerender Activation — EXCLUDED

## 审计目标
Prerender activation 时安全状态 reset 完整性：哪些状态从 prerender 存活到 activation？是否存在 TOCTOU（prerender 时有效，activation 时无效但仍生效）？

## 架构理解

### 核心文件 (12 files)
1. `content/browser/preloading/prerender/prerender_host.cc` — Activation 协调、StoredPage 转移
2. `content/browser/preloading/prerender/prerender_host_registry.cc` — `CanNavigationActivateHost()` 资格检查
3. `content/browser/renderer_host/render_frame_host_impl.cc` — `RendererDidActivateForPrerendering()`、`RendererWillActivateForPrerenderingOrPreview()`
4. `content/browser/renderer_host/navigation_request.cc` — `CommitPageActivation()`、`MakeDidCommitProvisionalLoadParamsForPrerenderActivation()`
5. `content/browser/renderer_host/render_frame_host_manager.cc` — `ActivatePrerender()`、RFH swap
6. `content/browser/renderer_host/document_associated_data.cc` — `RunPostPrerenderingActivationSteps()`
7. `content/browser/mojo_binder_policy_applier.cc` — 接口延迟绑定 + `PrepareToGrantAll`/`GrantAll`
8. `content/browser/mojo_binder_policy_map_impl.cc` — 接口策略注册（kGrant/kDefer/kCancel/kUnexpected）
9. `content/browser/preloading/prerender/prerender_subframe_navigation_throttle.cc` — 跨域子帧导航延迟
10. `content/browser/renderer_host/page_impl.cc` — `PageImpl::Activate()` IPC 发送
11. `content/browser/renderer_host/stored_page.cc` — 预渲染页面容器
12. `third_party/blink/renderer/core/html/fenced_frame/html_fenced_frame_element.cc` — FencedFrame 延迟创建

### Activation 流程
```
User navigates to prerendered URL
→ PrerenderHostRegistry::CanNavigationActivateHost() — 资格检查
→ PrerenderHostRegistry::ActivateReservedHost() — 预留 host
→ RenderFrameHostManager::ActivatePrerender() — 开始 swap
  → RenderFrameHostManager::RestorePage() — 提取 StoredPage
  → CommitPageActivation() — 构造 commit params
    → MakeDidCommitProvisionalLoadParamsForPrerenderActivation() — 复制安全状态
  → RenderFrameHostManager::CommitPending() — 完成 RFH swap
→ PageImpl::Activate() — 发送 ActivatePrerenderedPage IPC 给所有 RVH
→ RendererWillActivateForPrerenderingOrPreview() — PrepareToGrantAll
  [Renderer fires prerenderingchange event]
→ RendererDidActivateForPrerendering() — GrantAll + 释放 policy applier
→ DocumentAssociatedData::RunPostPrerenderingActivationSteps() — 执行延迟回调
```

### 存活 Activation 的安全状态 (从 Prerender Commit 继承)
| 状态 | 来源 | 是否正确 |
|------|------|---------|
| PolicyContainerHost (CSP/COEP/COOP) | Prerender navigation response headers | 正确 (同 URL 同 server response) |
| PermissionsPolicy header | Prerender navigation response headers | 正确 |
| isolation_info_ / NetworkIsolationKey | Prerender navigation | 正确 (same-origin) |
| insecure_request_policy | Prerender commit replication state | 正确 (显式复制) |
| cookie_setting_overrides (SAA) | Prerender navigation commit | 正确 (SAA 权限有效) |
| local_network_access_request_policy_ | Prerender navigation response | 正确 (同 server) |
| media_device_id_salt_base_ | Prerender creation time | 正确 (per-document) |
| StorageKey | Prerender navigation | 正确 (same-origin) |

### 延迟操作 (Prerender → Activation 执行)
| 操作 | 文件 | 安全检查时机 |
|------|------|------------|
| SharedStorage writes | shared_storage.cc:438+ | Mojo IPC → browser 在执行时验证 |
| ServiceWorker.register() | service_worker_container.cc:486 | Browser 在 register 时验证 scope |
| FencedFrame navigation | html_fenced_frame_element.cc:554 | Browser 在导航时验证 config |
| BroadcastChannel.postMessage | broadcast_channel.cc:114 | 同 origin 限制仍然生效 |
| Protocol handler registration | navigator_content_utils.cc:231 | Browser 验证 URL/scheme |
| Cross-origin subframe nav | prerender_subframe_navigation_throttle.cc:152 | 正常导航流程继续 |

### Mojo 接口策略
| 策略 | 行为 (Enforce mode) | 行为 (PrepareToGrantAll mode) |
|------|--------------------|-----------------------------|
| kGrant | 立即执行 | 立即执行 |
| kDefer (default) | 存入队列，GrantAll 时执行 | 仍然延迟 |
| kCancel | 取消预渲染 | **立即执行** |
| kUnexpected | ReportBadMessage + 取消 | **立即执行** |

kCancel 接口: `GamepadHapticsManager`, `GamepadMonitor` (非安全敏感)
kUnexpected 接口: `ClipboardHost` (same-origin only), `FileUtilitiesHost` (需用户交互)

---

## 假设分析

### 假设 A: DocumentAssociatedData cookie_setting_overrides 存活 activation 后被滥用

**位置:** `render_frame_host_impl.cc:13156-13158`, `document_associated_data.cc:133-136`

**观察:** Prerender navigation commit 时如果 server 发送 `Activate-Storage-Access: load` header，SAA override 会被设置。此 override 存活 activation（DocumentAssociatedData 不重建）。

**排除原因:** 设计正确
1. `Activate-Storage-Access: load` 要求用户已 granted `storage-access` permission
2. Permission grant 在 prerender 和 activation 之间不会变化（per-origin, 非 per-document）
3. SAA 权限本身就是 per-document lifetime（规范规定）
4. 即使 override 存活，它只启用已被用户批准的存储访问

### 假设 B: PrepareToGrantAll 窗口期间 kCancel 接口被利用

**位置:** `mojo_binder_policy_applier.cc:72-83`

**观察:** `PrepareToGrantAll` 和 `GrantAll` 之间，kCancel/kUnexpected 接口被立即 grant。如果恶意 renderer 在此窗口期绑定危险接口，可能获得不应有的能力。

**排除原因:** 
1. kCancel 接口仅有 `GamepadHapticsManager` 和 `GamepadMonitor` — 非安全敏感
2. kUnexpected 接口仅有 `ClipboardHost` 和 `FileUtilitiesHost` — 分别需要 focus 和用户交互
3. 利用需要 compromised renderer 在精确窗口期发起绑定 → Gate 3
4. 即使绑定成功，这些接口不提供安全特权提升

### 假设 C: Cross-origin subframe 导航延迟后恢复不重新验证

**位置:** `prerender_subframe_navigation_throttle.cc:192-198`（DEFER）, `line 152`（Resume）

**观察:** 跨域子帧导航在 prerender 期间被 DEFER，在 activation 后 Resume。Resume 后导航继续（已有 response），不重新运行安全检查。

**排除原因:** 设计正确 + 不可利用
1. 导航的 response 已经在 prerender 期间获取 — 此时安全检查（CSP, X-Frame-Options, COEP 等）已在 `WillProcessResponse` 之前的 throttle 中完成
2. 唯一被跳过的是 prerender 自身的 cross-origin check — 这正是延迟的原因
3. Resume 后，导航从 `WillProcessResponse` 之后继续（response 已验证）
4. 攻击者无法修改已获取的 response（它在 browser process 中）
5. 如果 response 在 prerender 和 activation 之间"过期"，不存在安全影响（同一个 response）

### 假设 D: PermissionsPolicy 从 prerender 存活，activation 时 server 已变更策略

**位置:** `render_frame_host_impl.cc:5391-5392`（UpdateFramePolicyHeaders — 使用 prerender 时的值）

**观察:** PermissionsPolicy header 在 prerender commit 时解析并存储。如果 server 在 prerender 和 activation 之间修改了 Permissions-Policy header，prerendered page 使用旧策略。

**排除原因:** 设计正确（同 BFCache）
1. Same-origin prerender: server 在 milliseconds~seconds 之间修改策略的场景不是攻击者控制的
2. 设计哲学: prerender = "提前加载的真实导航"，安全状态来自 server response
3. 与 Back/Forward Cache 恢复时的行为一致
4. 攻击者无法控制 server 策略变更时间点
5. 不满足原则 1（不一致性）— 因为 prerender 和 fresh navigation 对同一 response 应该有相同处理

### 假设 E: TakeNewDocumentPropertiesFromNavigation 在 activation 时未调用

**位置:** `render_frame_host_impl.cc:16520-16523`（`IsPageActivation` check skips DidCommitNewDocument）

**观察:** `DidCommitNewDocument()` 被 activation 跳过，其中的 `TakeNewDocumentPropertiesFromNavigation()` 设置多个安全属性。这些属性保留 prerender commit 时的值。

**排除原因:** 不构成安全问题
1. Prerender commit 时 `DidCommitNewDocument()` 已被调用 — 所有属性已正确设置
2. Activation 不需要重新设置，因为 RFH 是同一个（只是从 prerender FrameTree swap 到 primary）
3. 属性值来自同一个 server response — 不会因 swap 而失效
4. `local_network_access_request_policy_` 来自 prerender 的 response IP → 正确
5. `reporting_endpoints_` 来自 prerender 的 response header → 正确

### 假设 F: FencedFrame 延迟创建使用过期 config

**位置:** `html_fenced_frame_element.cc:553-558`

**观察:** FencedFrame 在 prerender 中不创建 delegate/不导航。Activation 后 `CreateDelegateAndNavigate` 使用 prerender 时设置的 `config_`。

**排除原因:** Browser 侧验证
1. Config 是 opaque URL，browser 侧维护其有效性
2. 当 FencedFrame 最终导航时，browser 验证 config token
3. 如果 config 已过期（FLEDGE auction 过期），导航会失败
4. Renderer 无法伪造或修改 opaque config
5. 最差情况: FencedFrame 导航失败 → 无安全影响

---

## 综合评估

### 安全模型评价
Prerender activation 的安全模型基于一个核心设计原则:
> **Prerendered page IS a real committed navigation** — 它的安全状态来自服务器响应，不需要在 activation 时重新评估。

这与 Back/Forward Cache 的恢复逻辑一致。关键保证:
1. Same-origin 约束: 攻击者无法 prerender 不同 origin 的页面
2. Server response 不变: prerender 使用的 response 就是 activation 后用的 response
3. Browser-side 验证: 所有延迟操作在执行时重新验证
4. Mojo capability control: 预渲染期间限制接口访问

### 唯一值得注意的设计决策 (非漏洞)
1. `PrepareToGrantAll` 窗口放宽 kCancel/kUnexpected 接口 — 有意为之，避免死锁
2. `mojo::ReportBadMessage()` 可能杀错 renderer — 已知 TODO (crbug.com/40185437)，仅影响 compromised renderer 场景
3. SessionStorage 共享 — per spec (https://wicg.github.io/nav-speculation/prerendering.html)

### 为什么 TOCTOU 不可利用
| 延迟操作 | 为什么安全 |
|----------|-----------|
| Mojo 延迟绑定 | 绑定时 browser 验证 RFH origin/state |
| 跨域子帧导航 | Response 已获取+验证，只是 commit 延迟 |
| SharedStorage | Browser 在执行时验证 origin |
| ServiceWorker.register | Browser 在注册时验证 scope |
| FencedFrame | Browser 在导航时验证 config token |
| Protocol handler | Browser 在注册时验证 URL/scheme |

---

## 结论

**EXCLUDED** — Prerender activation 安全模型设计正确:
1. 核心设计原则（prerender = 真实导航）消除了大部分 TOCTOU 风险
2. Same-origin 约束限制了攻击者能力
3. 延迟操作在执行时都有 browser-side 重新验证
4. Mojo capability control 正确限制了预渲染期间的接口访问
5. 存活 activation 的安全状态均来自同一 server response

满足 Kill Criteria: "假设生成后发现全部有 2+ 层防御且无法绕过"

---

## 值得后续关注的方向 (非当前可利用)
1. **Cross-origin prerender** (kPrerender2CrossOriginIframes) — 当此 feature 正式启用时，activation 的安全模型需要重新审视
2. **Prerender + Service Worker** — 如果 prerender 期间 SW 注册/更新，activation 后的 fetch 行为
3. **Prerender + Shared Storage selectURL** — 跨 prerender 的 k-anonymity timing leak
