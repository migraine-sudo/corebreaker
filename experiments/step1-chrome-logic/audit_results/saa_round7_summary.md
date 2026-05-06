# Round 7: SAA "Beyond Cookies" StorageAccessHandle — EXCLUDED

## 审计目标
Storage Access API "Beyond Cookies" 的 `StorageAccessHandle` 实现，7种binding与第一方存储系统的交互。

## 架构理解

### 核心文件 (12 files)
1. `content/browser/storage_access/storage_access_handle.cc` — Browser-side mojo handler
2. `content/browser/storage_access/storage_access_handle.h` — Header
3. `third_party/blink/public/mojom/storage_access/storage_access_handle.mojom` — IPC definition
4. `third_party/blink/renderer/modules/storage_access/storage_access_handle.cc` — Renderer JS binding
5. `third_party/blink/renderer/modules/storage_access/global_storage_access_handle.cc` — Singleton per window
6. `third_party/blink/renderer/modules/storage_access/document_storage_access.cc` — requestStorageAccess flow
7. `content/browser/worker_host/shared_worker_connector_impl.cc` — SharedWorker override path
8. `content/browser/worker_host/shared_worker_service_impl.cc` — SharedWorker creation with SAA
9. `content/browser/dom_storage/dom_storage_context_wrapper.cc` — localStorage/sessionStorage browser validation
10. `storage/browser/blob/blob_url_store_impl.cc` — BlobURL partitioning logic
11. `content/browser/renderer_host/render_frame_host_impl.cc` — IsFullCookieAccessAllowed, BlobURL binding
12. `components/content_settings/core/common/cookie_settings_base.cc` — Cookie/SAA access decisions

### 数据流
```
JS: document.requestStorageAccess({indexedDB: true, ...})
 → Renderer: DocumentStorageAccess::RequestStorageAccessImpl
   → Browser: PermissionService::RequestPermission(STORAGE_ACCESS)
     → User gesture + permission grant
   → Renderer: StorageAccessHandle 构造 → GlobalStorageAccessHandle::GetRemote()
     → BrowserInterfaceBroker.GetInterface(StorageAccessHandle)
       → Browser: StorageAccessHandle::Create
         → CHECK: IsFullCookieAccessAllowed()
         → Creates DocumentService, binds mojo receiver
   → Renderer: 通过 remote_ 调用各 Bind*() 方法
     → Browser: 使用 StorageKey::CreateFirstParty(origin) 绑定各子系统
```

### 信任边界
- **Renderer → Browser IPC:** `StorageAccessHandle` mojo interface 无条件注册于 BrowserInterfaceBroker
- **Security gate:** Browser-side `IsFullCookieAccessAllowed()` at Create time (single check, no re-validation)
- **Renderer-side gate:** JS API requires permission grant + user gesture; `base::PassKey` prevents internal bypass

### 安全检查列表
1. `StorageAccessHandle::Create` — `IsFullCookieAccessAllowed()` (browser, 一次性)
2. `DOMStorageContextWrapper::IsRequestValid` — `CanAccessDataForOrigin()` + StorageKey match (browser)
3. `SharedWorkerServiceImpl::ConnectToWorker` — `IsThirdPartyContext()` + same_site_cookies check
4. `BlobURLStoreImpl` — `storage_access_check_callback` (always false for SAA handle)
5. Renderer: `requestStorageAccess()` permission flow + user gesture
6. Renderer: `base::PassKey` on SharedWorker/BroadcastChannel/PublicURLManager constructors

### 防御层分析
- **层1:** JS API permission grant (renderer-side, user gesture + prompt)
- **层2:** Browser-side `IsFullCookieAccessAllowed()` at mojo binding time
- **层3:** `CanAccessDataForOrigin()` process-level isolation (for localStorage/sessionStorage)
- **层4:** Individual sub-system checks (SharedWorker cookie context, BlobURL partitioning)
- **层5:** `base::PassKey` pattern preventing renderer-internal bypass

---

## 假设分析

### 假设 A: IsFullCookieAccessAllowed() 在 3PC 未阻止时无效

**位置:** `content/browser/storage_access/storage_access_handle.cc:55`

**观察:** 当 3PC blocking 未启用 (Chrome 默认), `IsFullCookieAccessAllowed()` 对所有 third-party iframe 返回 true。StorageAccessHandle mojo interface 无条件注册。理论上, 任何 renderer 可直接绑定获得 first-party storage access。

**排除原因:** 需要 compromised renderer (Gate 3)
- Renderer 侧使用 `base::PassKey<StorageAccessHandle>` 防止内部代码绕过
- `GlobalStorageAccessHandle` 只从 `StorageAccessHandle` 构造函数调用
- `StorageAccessHandle` 只从 `requestStorageAccess()` 的 resolved promise 创建
- 正常 renderer 无法在不经过 JS API 的情况下触发 mojo binding
- 即使 browser-side gate 无效, renderer-side gate 完整阻止

### 假设 B: 绑定后权限撤销

**位置:** `content/browser/storage_access/storage_access_handle.cc` (DocumentService lifetime)

**观察:** StorageAccessHandle 是 DocumentService — 存活到文档销毁。绑定的 IDBFactory/LockManager/CacheStorage mojo pipes 独立存活。无 revocation 机制。

**排除原因:** 设计正确
- SAA 权限在整个文档生命周期内有效 (`SetStorageAccessApiStatus` 只在 grant 和 navigation commit 时调用)
- Chrome 明确记录此行为: 权限 per-document, 不会 mid-document revoke
- 与其他权限模型一致 (camera, microphone 等)

### 假设 C: SharedWorker 跨 partition 通信

**位置:** `content/browser/worker_host/shared_worker_service_impl.cc:462-465`

**观察:** SAA SharedWorker 使用 `storage_access_api_status = kAccessViaAPI` 且 `creator_storage_key_` 是 first-party。这允许它匹配 first-party context 的 SharedWorker instance, 实现跨 partition 通信。

**排除原因:** 设计正确（这是 SAA "Beyond Cookies" 的核心功能）
- Line 143-148: 即使用 SAA, third-party frame 仍只能创建 `same_site_cookies == kNone` 的 SharedWorker
- SharedWorker 的 cookie context 被正确限制
- 跨 partition 通信正是 SAA 的设计目的（合法的 SSO, analytics 等用例）

### 假设 D: BlobURL 跨 partition 泄露

**位置:** `content/browser/storage_access/storage_access_handle.cc:175-182`

**观察:** SAA handle 的 BlobURLStore 使用 first-party StorageKey 注册 blob URL。

**排除原因:** 显式防御
- `storage_access_check_callback` 被设为 `[]() -> bool { return false; }` — 永远不允许 bypass partitioning
- 注释明确说明 "StorageAccessHandle context still shouldn't bypass the partitioning check"
- 对比: 正常 RFH 的 BlobURLStore 检查 `kStorageAccessGrantEligible && IsFullCookieAccessAllowed()`
- BlobURL partitioning feature `kBlockCrossPartitionBlobUrlFetching` 正确阻止跨 partition 访问

### 假设 E: DOMStorage IsRequestValid 在 3PC 未阻止时可绕过

**位置:** `content/browser/dom_storage/dom_storage_context_wrapper.cc:330-334`

**观察:** `IsRequestValid` 允许 first-party StorageKey 访问当 `IsFullCookieAccessAllowed()` 为 true。当 3PC 未阻止时, 此条件对所有 third-party iframe 成立。

**排除原因:** 同假设 A, 需要 compromised renderer
- 正常 renderer 代码路径只通过 `StorageNamespace::GetCachedArea` 传递 StorageKey
- `kStorageAccessAPI` context 只由 `GlobalStorageAccessHandle` 使用
- `GlobalStorageAccessHandle` 受 `base::PassKey` + `StorageAccessHandle` 生命周期保护
- `CanAccessDataForOrigin()` process-level check 是额外独立防御

---

## 综合评估

### 安全模型评价
StorageAccessHandle 的安全模型分为两层:
1. **Renderer-side (primary):** JS API permission flow + `base::PassKey` + class encapsulation
2. **Browser-side (defense-in-depth):** `IsFullCookieAccessAllowed()` + process isolation

当 3PC blocking 未启用时, browser-side `IsFullCookieAccessAllowed()` 确实对所有 third-party iframe 返回 true, 使得 browser-side gate 形同虚设。但这不构成可利用漏洞, 因为:
- Renderer-side 是 primary security boundary
- Browser-side 是 defense-in-depth (符合 Chrome 安全模型)
- 利用需要 compromised renderer → Gate 3

### 设计建议 (非漏洞, 但值得注意)
`StorageAccessHandle::Create` 可以增加额外检查:
```cpp
// 除了 IsFullCookieAccessAllowed(), 还应验证 SAA permission 是否被显式 grant
if (!host->GetCookieSettingOverrides().Has(
        net::CookieSettingOverride::kStorageAccessGrantEligible)) {
    return;  // 需要显式 SAA grant, 而非仅 cookie 可访问
}
```
这会使 browser-side gate 独立于 3PC blocking 配置工作。但缺少这个检查不构成可报告漏洞 (defense-in-depth finding, Gate 3).

---

## 结论

**EXCLUDED** — 5 层防御全部完整, 无可绕过路径:
1. JS API 权限流程（用户交互 + permission prompt）
2. Browser-side cookie access check（defense-in-depth）
3. Process isolation（CanAccessDataForOrigin）
4. Sub-system 独立检查（SharedWorker cookie context, BlobURL partitioning）
5. Renderer 代码封装（base::PassKey, class hierarchy）

唯一潜在 weakness（IsFullCookieAccessAllowed 在 3PC 未阻止时无效）需要 compromised renderer, 违反 Gate 3。
