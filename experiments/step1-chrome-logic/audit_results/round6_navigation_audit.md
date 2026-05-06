# Round 6: Chrome Navigation State Machine Security Audit

审计目标: Chromium 导航管线 (NavigationRequest) 的逻辑漏洞
审计范围: 从普通网页可触发的安全问题 (无需扩展/调试器/特殊 flag)
审计日期: 2026-05-01

---

## Finding N6-01: ValidateCommitOriginAtCommit 默认关闭 -- FrameNavigationEntry 中陈旧 origin 导致历史导航 PageState 泄露

### 漏洞假设

`kValidateCommitOriginAtCommit` feature flag 在 `content/public/common/content_features.cc:1128` 被设置为 `FEATURE_DISABLED_BY_DEFAULT`。这意味着 `NavigationRequest::CommitNavigation()` 中的 `ValidateCommitOrigin()` 检查 **在默认的 Chrome 版本中完全不执行**。

该检查旨在验证 `FrameNavigationEntry` 的 `committed_origin()` 与实际的 `origin_to_commit` 是否一致。当该检查关闭时:

1. `FrameNavigationEntry` 可能保留一个 **陈旧的** `committed_origin()` (参见代码注释 line 12522-12529: "redirects or other origin-changing cases (e.g., CSP), FrameNavigationEntry may retain a stale committed_origin()")
2. 如果 `committed_origin()` 陈旧但 `page_state` 非空，该 PageState 可能包含另一个 origin 的序列化页面状态
3. 历史导航回到该条目时，陈旧的 `committed_origin()` 和不匹配的 `page_state` 可能导致跨 origin 状态恢复

### 代码位置

- `content/public/common/content_features.cc:1128` -- flag 定义为 DISABLED
- `content/browser/renderer_host/navigation_request.cc:6686` -- 检查受 flag 保护
- `content/browser/renderer_host/navigation_request.cc:12490-12535` -- ValidateCommitOrigin 实现
- `content/browser/renderer_host/navigation_request.cc:12512` -- **弱化检查**: 当任一 origin 是 opaque 时仅比较 precursor tuple

### 可利用性分析

攻击场景:
1. 页面 A (origin-a.com) 导航到页面 B (origin-b.com)，中间经历重定向
2. 重定向过程中 FrameNavigationEntry 保留了 origin-a 的 committed_origin
3. 页面 B 的 PageState 被保存
4. 当历史导航回到该条目时，因为 ValidateCommitOrigin 关闭，不检查 origin 一致性
5. PageState 可能在错误的 origin context 中被恢复

即使该 CHECK 是 `NotFatalUntil::M140`，在当前版本中完全不执行意味着这个窗口是打开的。

### 攻击者可获得

- 可能在历史导航中获取另一个 origin 的序列化页面状态信息
- 潜在的跨 origin 信息泄露

### 置信度: MEDIUM

注: 实际利用取决于 FrameNavigationEntry 何时会保留陈旧 origin -- 代码注释明确承认这是已知问题 (crbug.com/420965165)。


---

## Finding N6-02: kEnforceSameDocumentOriginInvariants 默认关闭 -- 同文档导航中 origin 变更的残余路径

### 漏洞假设

`kEnforceSameDocumentOriginInvariants` 在 `content/common/features.cc:245-246` 被设置为 `FEATURE_DISABLED_BY_DEFAULT`。它还依赖于另一个 flag `kTreatMhtmlInitialDocumentLoadsAsCrossDocument` 同时开启 (line 860-862)。

当该 flag 关闭时，以下安全不变量 **不被强制执行**:

1. `render_frame_host_impl.cc:12024-12028` -- 同文档导航允许改变 origin (本应被 `RFH_SAME_DOC_INSECURE_REQUEST_POLICY_CHANGE` bad_message 杀死)
2. `render_frame_host_impl.cc:16027-16043` -- 同文档导航的 insecure_request_policy 和 insecure_navigations_set 不被验证
3. `render_frame_host_impl.cc:5292-5296` -- `SetLastCommittedOrigin` 在同文档导航中仍会被调用更新 origin
4. `navigator.cc:647-653` -- `SetInsecureRequestPolicy/Set` 在同文档导航中仍会被更新

这意味着一个被攻陷的渲染器可以通过同文档导航 (pushState/replaceState) 来改变 RenderFrameHost 的 committed origin。

### 代码位置

- `content/common/features.cc:245-246` -- FEATURE_DISABLED_BY_DEFAULT
- `content/common/features.cc:859-863` -- IsEnforceSameDocumentOriginInvariantsEnabled() 实现
- `content/browser/renderer_host/render_frame_host_impl.cc:12024-12028` -- 被 flag 保护的 origin 变更检查
- `content/browser/renderer_host/render_frame_host_impl.cc:12061-12064` -- fallback 检查 (仍然存在但不使用 bad_message)
- `content/browser/renderer_host/render_frame_host_impl.cc:5292-5296` -- SetLastCommittedOrigin 的条件更新

### 可利用性分析

虽然 `CanCommitOriginAndUrl()` 仍然会在 `ValidateURLAndOrigin()` 中执行 (line 15821)，且其中有一个不受 flag 控制的同文档 origin 变更检查 (line 12062-12064)，但该 fallback 路径在 flag 关闭时:
- 不发送 bad_message
- 仅返回 `CANNOT_COMMIT_ORIGIN`

然而更关键的是，`insecure_request_policy` 和 `insecure_navigations_set` 的变更在 flag 关闭时 **不被检测**，这意味着:
- 渲染器可以通过同文档导航改变 insecure request policy
- 可能将 upgrade-insecure-requests 策略降级或绕过

### 攻击者可获得

- 绕过 upgrade-insecure-requests CSP 策略
- 在同文档导航中修改安全属性

### 置信度: MEDIUM-LOW

注: 需要被攻陷的渲染器，但这是 site isolation 的防御深度问题。


---

## Finding N6-03: Prerender 激活时不比较 should_check_main_world_csp -- 内容脚本可激活 CSP 限制页面的预渲染

### 漏洞假设

在 `prerender_host.cc:1313-1317` 中，预渲染激活匹配时 **故意跳过** `should_check_main_world_csp` 的比较:

```
// No need to compare should_check_main_world_csp, as if the CSP blocks the
// initial navigation, it cancels prerendering, and we don't reach here for
// matching. So regardless of the activation's capability to bypass the main
// world CSP, the prerendered page is eligible for the activation. This also
// permits content scripts to activate the page.
```

逻辑是: 如果预渲染初始导航没被 CSP 阻止，那么激活时的 CSP 绕过能力无关紧要。

但这忽略了一个场景: CSP 策略在预渲染初始导航和激活之间可能发生变化。例如:
1. 页面 A 预渲染页面 B (此时 CSP 允许)
2. 页面 A 的 CSP 被 meta 标签或 `Content-Security-Policy` 响应头动态更新
3. 现在新的 CSP 应该阻止导航到页面 B
4. 但激活仍然成功，因为不比较 CSP disposition

### 代码位置

- `content/browser/preloading/prerender/prerender_host.cc:1313-1317` -- 明确跳过 CSP 比较
- `content/browser/preloading/prerender/prerender_host.cc:1441-1442` -- 初始导航 CHECK 确认使用 CSP CHECK

### 可利用性分析

这个问题更多是一个设计决策而非漏洞。但在特定场景下 (CSP 动态变化)，预渲染激活可能绕过后续添加的 CSP 限制。

攻击场景较窄: 需要目标页面在预渲染开始后才添加 CSP 限制。

### 攻击者可获得

- 在理论上绕过动态添加的 CSP 策略
- 激活一个在当前 CSP 策略下本应被阻止的预渲染页面

### 置信度: LOW

---

## Finding N6-04: Fenced Frame sandbox 属性在浏览器端被忽略 -- renderer 端单点检查

### 漏洞假设

在 `fenced_frame.cc:383-391` 中:

```cpp
// Observe that the sandbox flags sent from the renderer are currently
// ignored. The `sandbox` attribute on `HTMLFencedFrameElement` may only
// cause embedder-initiated navigations to fail for now---in the renderer.
// TODO(crbug.com/40233168): Handle sandbox flags for fenced frames properly
// in the browser, allowing us to use non-fixed sets of sandbox flags.
inner_root->SetPendingFramePolicy(blink::FramePolicy(
    current_frame_policy.sandbox_flags, frame_policy.container_policy,
    current_frame_policy.required_document_policy,
    frame_policy.deferred_fetch_policy));
```

`sandbox_flags` 来自 `current_frame_policy` (浏览器侧的硬编码值)，而不是来自 `frame_policy` (renderer 传递的值)。这意味着:

1. `<fencedframe sandbox="allow-same-origin">` 的 sandbox 属性 **在浏览器端完全不生效**
2. 只有 `kFencedFrameForcedSandboxFlags` 中硬编码的 flags 被应用
3. sandbox 检查 **仅在渲染器端** 执行

这是一个 renderer-trust 问题: 被攻陷的渲染器可以忽略 sandbox 属性的 renderer 端检查，而浏览器端不会施加额外的 sandbox 限制。

### 代码位置

- `content/browser/fenced_frame/fenced_frame.cc:379-391` -- DidChangeFramePolicy 忽略 sandbox_flags
- `content/browser/fenced_frame/fenced_frame.cc:250-251` -- 初始化时使用硬编码 sandbox flags
- `third_party/blink/public/common/frame/fenced_frame_sandbox_flags.h:14-25` -- kFencedFrameForcedSandboxFlags 定义

### 可利用性分析

`kFencedFrameForcedSandboxFlags` 包含:
- kNavigation, kTopNavigation -- 限制导航
- kDownloads -- 限制下载
- kModals -- 限制弹窗
- kPlugins, kPointerLock, kPresentationController
- kDocumentDomain -- 限制 document.domain
- kStorageAccessByUserActivation

**但不包含** `kOrigin` (在 kFencedFrameMandatoryUnsandboxedFlags 中)。

这意味着如果嵌入者试图通过 sandbox 属性给 fenced frame 添加额外的 `kOrigin` sandbox，浏览器端不会执行该限制。但由于 `kOrigin` 在 `kFencedFrameMandatoryUnsandboxedFlags` 中是必须 unsandboxed 的，所以这更多是一个设计限制。

真正的风险在于: **container_policy** (permissions policy) **不受影响**地从 renderer 传入，这是浏览器信任 renderer 提供的 permissions policy 声明。虽然这些 policy 在 `CheckPermissionsPoliciesForFencedFrames()` 中有额外验证，但 `deferred_fetch_policy` 也直接从 renderer 传入 (line 391) 且缺乏浏览器端验证。

### 攻击者可获得

- 被攻陷的渲染器可能绕过 fenced frame 的 sandbox 属性限制
- 操纵 deferred_fetch_policy 绕过 deferred fetch 限制

### 置信度: MEDIUM-LOW

---

## Finding N6-05: Blob URL 导航中 origin 回退到 precursor_origin -- Blob URL revoke 后的 origin 不确定性

### 漏洞假设

在 `storage/browser/blob/blob_url_registry.cc:127-156` 的 `GetOriginForNavigation` 中:

```cpp
url::Origin url_origin = url::Origin::Create(url);
if (!url_origin.opaque()) {
    return url_origin;  // 从 URL 中提取嵌入的 origin
}
// ...
auto it = url_to_data_.find(url_without_ref);
if (it != url_to_data_.end() && ...) {
    return it->second.origin;  // 从映射表获取
}
return url::Origin::Resolve(url, precursor_origin);  // 回退: 使用 precursor_origin
```

关键路径:
1. Blob URL 格式为 `blob:null/uuid` (opaque origin)
2. 页面创建 blob URL 并开始导航
3. 在导航的 `WILL_PROCESS_RESPONSE` 阶段之前，blob URL 被 revoke
4. `url_to_data_` 中已无映射
5. 回退到 `url::Origin::Resolve(url, precursor_origin)`
6. `precursor_origin` 来自 `common_params().initiator_origin.value_or(url::Origin())`

问题在于:
- 对于 `blob:null/uuid` URL，`url::Origin::Create()` 返回 opaque origin
- 映射被删除后，使用 `precursor_origin` (即 initiator_origin)
- 而 `initiator_origin` 在 renderer-initiated 导航中由渲染器提供
- 这意味着 origin 的确定依赖于导航创建时渲染器报告的 initiator_origin

在 `navigation_request.cc:1749` 中 `blob_url_loader_factory_` 在 `NavigationRequest` 构造时被捕获，所以 blob 内容的加载不受 revocation 影响。但 **origin 的确定** 使用了不同的路径 (`GetOriginForURLLoaderFactoryUnchecked`)，该路径在 `WILL_PROCESS_RESPONSE` 时才调用，此时如果 blob URL 已被 revoke，origin 回退到 initiator_origin。

### 代码位置

- `storage/browser/blob/blob_url_registry.cc:127-156` -- GetOriginForNavigation
- `content/browser/renderer_host/navigation_request.cc:11934-11946` -- blob URL origin 查找
- `content/browser/renderer_host/navigation_request.cc:1324-1343` -- blob_url_loader_factory 在创建时捕获
- `content/browser/renderer_host/navigation_request.cc:1749` -- blob_url_loader_factory_ 存储

### 可利用性分析

攻击场景:
1. 攻击者页面 (attacker.com) 创建一个 blob URL (origin: attacker.com)
2. 开始导航到该 blob URL
3. 立即 revoke 该 blob URL
4. 导航继续 (blob_url_loader_factory_ 仍然有效)
5. 在 origin 计算时，blob URL 的映射已不存在
6. origin 回退到使用 precursor_origin 的 Resolve

实际上对于 `blob:https://attacker.com/uuid` 这种格式，origin 直接从 URL 中提取 (line 135-138)，不受 revocation 影响。只有 `blob:null/uuid` (opaque origin blob) 才会走到映射查找路径。

对于 opaque origin blob，revoke 后回退到 `url::Origin::Resolve(url, precursor_origin)` 返回的是一个 opaque origin (因为 blob:null/uuid 解析为 opaque)，安全影响有限。

### 攻击者可获得

- 在特定时序下，blob URL 导航的 origin 可能与预期不同
- 但由于 opaque origin 的使用，实际安全影响有限

### 置信度: LOW

---

## Finding N6-06: about:srcdoc 跨 origin 导航的残留路径 -- initiator_base_url 清除的竞态

### 漏洞假设

在 `navigation_request.cc:6701-6709` 的 `CommitNavigation()` 中:

```cpp
if (GetURL().IsAboutSrcdoc() &&
    (!common_params().initiator_origin ||
     origin_to_commit.GetTupleOrPrecursorTupleIfOpaque() !=
         common_params()
             .initiator_origin->GetTupleOrPrecursorTupleIfOpaque())) {
    // TODO(crbug.com/40165505): Make this unreachable by blocking
    // cross-origin about:srcdoc navigations.
    common_params_->initiator_base_url = std::nullopt;
}
```

这段代码承认 **跨 origin 的 about:srcdoc 导航仍然可能发生**。在 `CheckAboutSrcDoc()` (line 7790-7845) 中，虽然有多重检查，但仍有两个放行路径:

1. **Case 2 (line 7810-7817)**: 浏览器发起的 about:srcdoc 导航被允许 -- TODO 注释说"暂时允许"
2. **Case 4 (line 7830-7839)**: `src = 'about:srcdoc'` 被允许，只要 initiator origin 匹配 parent origin

关键问题在于 Case 4 的检查: 它仅验证 **initiator origin** 匹配 parent origin，但在 sandboxed iframe 场景下:
- iframe 可能有 opaque origin (因为 sandbox kOrigin)
- 但 initiator_origin 可能仍然是 parent 的 non-opaque origin
- 这可能导致 about:srcdoc 在 sandbox 上下文中被错误允许

同时，在 `CommitNavigation` 时的修复 (清除 initiator_base_url) 是 **事后补救** 而非预防，在清除之前的代码路径中 `initiator_base_url` 可能已被使用。

### 代码位置

- `content/browser/renderer_host/navigation_request.cc:7790-7845` -- CheckAboutSrcDoc
- `content/browser/renderer_host/navigation_request.cc:6701-6709` -- 跨 origin srcdoc 的 base URL 清除
- `content/browser/renderer_host/navigation_request.cc:11915-11931` -- srcdoc origin 继承

### 可利用性分析

从普通网页触发:
1. 页面 A (origin-a.com) 包含 `<iframe id="f" srcdoc="...">`
2. iframe 的 origin 继承自 parent (origin-a.com)
3. 如果有另一个同 origin 的脚本设置 `f.src = "about:srcdoc"`，这被允许
4. 但如果 iframe 被 sandbox 了 (有 kOrigin flag)，新 srcdoc 文档的 origin 应该是 opaque
5. 然而 `CheckAboutSrcDoc` 的 Case 4 可能允许这种导航，即使 sandbox context 已改变

这主要是一个防御深度问题，实际利用困难。

### 攻击者可获得

- 在特定 sandbox 配置下，可能通过 about:srcdoc 导航绕过 sandbox 的 origin 隔离
- 可能继承错误的 base URL

### 置信度: LOW

---

## Finding N6-07: Prerender 激活中同文档导航后的 URL 不匹配

### 漏洞假设

在 `navigation_request.cc:7195-7209` 的 `CommitPageActivation()` 中:

```cpp
// The prerender page might have navigated. Update the URL and the redirect
// chain, as the prerendered page might have been redirected or performed
// a same-document navigation.
// TODO(crbug.com/40170496): Ensure that the tests that navigate
// MPArch activation flow do not crash. This is a hack to unblock the basic
// MPArch activation flow for now. There are probably other parameters which
// are out of sync, and we need to carefully think through how we can
// activate a RenderFrameHost whose URL doesn't match the one that was
// initially passed to NavigationRequest
common_params_->url = rfh->GetLastCommittedURL();
// TODO(crbug.com/40170496): We may have to add the entire redirect chain.
redirect_chain_.clear();
redirect_chain_.push_back(rfh->GetLastCommittedURL());
```

**这是一个自我承认的 hack**: 预渲染页面可能在激活前执行了同文档导航 (pushState/replaceState)，导致其 URL 与初始预渲染 URL 不同。代码通过直接覆盖 `common_params_->url` 来"修复"这个不匹配。

风险:
1. 预渲染页面可以通过 `pushState` 将 URL 改为任意同 origin URL
2. 激活时，这个修改后的 URL 被直接信任
3. 导航控制器中记录的 URL 变成了预渲染页面自己选择的 URL
4. redirect_chain_ 被清空并设为新 URL，丢失了原始导航路径

### 代码位置

- `content/browser/renderer_host/navigation_request.cc:7195-7209` -- URL 覆盖 hack
- `content/browser/renderer_host/navigation_request.cc:7090` -- CommitPageActivation 入口

### 可利用性分析

从普通网页触发:
1. 页面 A 预渲染页面 B (`https://example.com/page`)
2. 预渲染的页面 B 执行 `history.pushState({}, '', '/admin')`
3. 用户导航到 `https://example.com/page`
4. 预渲染激活，但 `common_params_->url` 被设为 `/admin`
5. 浏览器 URL 栏显示 `/admin` (因为这是同 origin 的合法 pushState)

这本身不是安全漏洞 (因为 pushState 只能改变同 origin URL)，但存在以下风险:
- NavigationEntry 中记录的 URL 可能与用户点击的 URL 不同
- redirect_chain_ 被清空，审计日志丢失原始导航信息
- 可能影响依赖 URL 的安全决策

### 攻击者可获得

- 操控 NavigationEntry 中的 URL 历史记录
- 绕过基于 URL 的安全策略 (如某些 CSP 或 extension 规则)

### 置信度: MEDIUM-LOW

---

## Finding N6-08: CSP attribute 快照时机问题 -- beforeunload 期间可修改 CSP 属性

### 漏洞假设

在 `navigation_request.cc:3027-3031` 和 `navigation_request.cc:7853-7857` 中有两处关于 CSP attribute 快照时机的 TODO:

```cpp
// TODO(antoniosartori): This takes a snapshot of the 'csp' attribute. This
// should be done at the beginning of the navigation instead. Otherwise, the
// attribute might have change while waiting for the beforeunload handlers to
// complete.
SetupCSPEmbeddedEnforcement();
```

以及:

```cpp
// TODO(antoniosartori): Probably we should have taken a snapshot of the 'csp'
// attribute at the beginning of the navigation and not now, since the
// beforeunload handlers might have modified it in the meantime.
// See pull request about the spec:
// https://github.com/w3c/webappsec-cspee/pull/11
```

`SetupCSPEmbeddedEnforcement()` 使用 `frame_tree_node()->csp_attribute()` 来获取当前的 CSP 嵌入式强制属性。但这个属性可能在 `beforeunload` 处理期间被修改。

### 代码位置

- `content/browser/renderer_host/navigation_request.cc:3027-3031` -- BeginNavigation 中的 CSP 快照 TODO
- `content/browser/renderer_host/navigation_request.cc:7847-7899` -- SetupCSPEmbeddedEnforcement 实现
- `content/browser/renderer_host/navigation_request.cc:7859-7870` -- 使用当前时刻的 csp_attribute

### 可利用性分析

攻击场景:
1. 父页面对 iframe 设置了 `csp="script-src 'none'"` 属性
2. 父页面中有 beforeunload handler
3. iframe 开始导航到 attacker.com
4. 在 beforeunload 期间，父页面修改 iframe 的 csp attribute 为 `csp=""`(移除限制)
5. `SetupCSPEmbeddedEnforcement()` 读取到修改后的空 CSP
6. iframe 的导航不受原始 CSP 限制

这需要父页面配合 (修改 csp 属性)，所以在跨 origin 场景下难以利用。但在同 origin 场景下，一个页面中的脚本可以在 beforeunload 期间修改另一个 iframe 的 csp attribute。

### 攻击者可获得

- 在特定时序窗口中绕过 iframe CSP 嵌入式强制策略
- 加载本应被 CSP 阻止的脚本

### 置信度: MEDIUM

注: 利用需要对 beforeunload 时序的精确控制，且需要同 origin 上下文。

---

## Finding N6-09: Fenced Frame container_policy 从 renderer 直接传入 -- 缺少浏览器端完整性验证

### 漏洞假设

在 `fenced_frame.cc:388-391`:
```cpp
inner_root->SetPendingFramePolicy(blink::FramePolicy(
    current_frame_policy.sandbox_flags, frame_policy.container_policy,
    current_frame_policy.required_document_policy,
    frame_policy.deferred_fetch_policy));
```

`container_policy` 和 `deferred_fetch_policy` 直接从 renderer 提供的 `frame_policy` 中获取。虽然:
- `CheckPermissionsPoliciesForFencedFrames()` 在 `navigation_request.cc:10438-10475` 中验证了 permissions policy
- 验证逻辑检查了 `effective_enabled_permissions()` 中的每个 feature 是否在 outer document 的 policy 中被允许

但有一个问题:
- `IsFencedFrameRequiredPolicyFeatureAllowed()` (line 10402-10436) 检查 `embedder_allowlist->MatchesAll()` (line 10414)
- 如果 embedder 的 allowlist 不是 "all"，检查直接返回 false
- 但如果 embedder 的 allowlist 是 "all" (默认情况)，则仅检查 container_policy 是否 `Contains(origin)`
- **container_policy 来自 renderer**，被攻陷的 renderer 可以提供包含任意 origin 的 container_policy

### 代码位置

- `content/browser/fenced_frame/fenced_frame.cc:388-391` -- container_policy 直接从 renderer 传入
- `content/browser/renderer_host/navigation_request.cc:10402-10436` -- IsFencedFrameRequiredPolicyFeatureAllowed
- `content/browser/renderer_host/navigation_request.cc:10438-10475` -- CheckPermissionsPoliciesForFencedFrames

### 可利用性分析

需要被攻陷的 renderer 进程才能利用。在正常网页中，renderer 提供的 container_policy 受到 Blink 的验证。但如果 renderer 被攻陷:
1. 可以构造任意 container_policy
2. 使 fenced frame 获得本不应有的 permissions
3. 可能绕过 fenced frame 的权限限制

### 攻击者可获得

- 被攻陷 renderer: 操控 fenced frame 的 permissions policy
- 不需要被攻陷 renderer: 无法利用

### 置信度: LOW (需要被攻陷 renderer)

---

## Finding N6-10: Cross-origin redirect 后 CSP 使用 initiator 的 RenderFrameHost -- Use-After-Free 风险

### 漏洞假设

在 `navigation_request.cc:7715-7723` 中:

```cpp
// Note: the initiator RenderFrameHost could have been deleted by
// now. Then this RenderFrameHostCSPContext will do nothing and we won't
// report violations for this check.
//
// If the initiator frame has navigated away in between, we also use a no-op
// `initiator_csp_context`, in order not to trigger `securitypolicyviolation`
// events in the wrong document.
RenderFrameHostCSPContext initiator_context(
    GetInitiatorDocumentRenderFrameHost());
```

代码承认 initiator RenderFrameHost 可能已被删除。如果 initiator frame 已导航离开:
1. CSP 检查使用 no-op context
2. 不会报告 violation events
3. **但 CSP 策略本身是否仍正确？**

`initiator_policies` 来自 `policy_container_builder_->InitiatorPolicies()` (line 7699-7700)，这是在导航开始时的快照。所以策略内容本身是正确的，只是 violation reporting 可能丢失。

这不是直接的安全漏洞，但可能导致:
- CSP violation 事件不被报告
- 安全监控系统无法检测到 CSP 绕过尝试

### 代码位置

- `content/browser/renderer_host/navigation_request.cc:7715-7723` -- initiator context 可能为空

### 置信度: LOW (仅影响 violation reporting，不影响策略执行)

---

## Finding N6-11: Redirect 时 tentative_data_origin_to_commit_ 重置 -- Data URL 重定向链中的 nonce 不一致

### 漏洞假设

在 `navigation_request.cc:3643-3644`:
```cpp
// Reset the tentative origin_to_commit, as the redirected one is different.
tentative_data_origin_to_commit_ = std::nullopt;
```

每次 redirect 时，data URL 的缓存 origin (包含 opaque nonce) 被重置。如果重定向链是:
1. `data:text/html,...` -> redirect -> `data:text/html,...` (另一个 data URL)

第一个 data URL 的 opaque origin nonce 被丢弃，第二个 data URL 获得新的 nonce。这是正确行为。

但如果中间经过跨 origin 重定向再回到 data URL，SiteInstance 的选择可能基于第一个 data URL 的 origin nonce，而实际提交使用第二个 data URL 的新 nonce。这可能导致 SiteInstance 不匹配。

### 代码位置

- `content/browser/renderer_host/navigation_request.cc:3643-3644` -- origin 重置
- `content/browser/renderer_host/navigation_request.cc:4495-4506` -- data URL origin 传播到 UrlInfo

### 可利用性分析

实际场景中 data URL 不能被重定向到 (data URL 不支持服务器端重定向)，所以这个问题在实践中难以触发。只有在 extension redirect 等特殊场景下才可能发生。

### 置信度: LOW

---

## 总结

| Finding | 描述 | 置信度 | 可利用性 |
|---------|------|--------|---------|
| N6-01 | ValidateCommitOriginAtCommit 关闭导致历史导航 PageState 泄露 | MEDIUM | 需要特定重定向场景 |
| N6-02 | kEnforceSameDocumentOriginInvariants 关闭导致同文档 origin/policy 变更 | MEDIUM-LOW | 需要被攻陷 renderer |
| N6-03 | Prerender 激活不比较 CSP disposition | LOW | 需要 CSP 动态变化 |
| N6-04 | Fenced Frame sandbox 浏览器端忽略 | MEDIUM-LOW | 需要被攻陷 renderer |
| N6-05 | Blob URL revoke 后 origin 回退 | LOW | Opaque origin 限制影响 |
| N6-06 | about:srcdoc 跨 origin 导航残留路径 | LOW | 需要特定 sandbox 配置 |
| N6-07 | Prerender pushState 后 URL 不匹配激活 | MEDIUM-LOW | 可从普通网页触发 |
| N6-08 | CSP attribute 快照时机 TOCTOU | MEDIUM | 需要同 origin + 精确时序 |
| N6-09 | Fenced Frame container_policy 缺少完整验证 | LOW | 需要被攻陷 renderer |
| N6-10 | Cross-origin redirect CSP reporting 丢失 | LOW | 仅影响 reporting |
| N6-11 | Data URL redirect 中 nonce 不一致 | LOW | 实践中难以触发 |

### 最有价值的发现

**N6-01 (ValidateCommitOriginAtCommit 关闭)** 和 **N6-08 (CSP attribute TOCTOU)** 是最值得深入研究的发现:

- N6-01 涉及一个 **默认关闭的安全检查** 和 **已知的 stale origin 问题**，有真实的 crbug 跟踪 (crbug.com/420965165, crbug.com/41492620)
- N6-08 涉及一个 **有明确代码注释承认** 的 TOCTOU 问题，有 spec discussion (webappsec-cspee/pull/11)

**N6-07 (Prerender pushState URL mismatch)** 也值得关注，因为代码中有 TODO 承认这是 "hack"，且可以从普通网页触发。
