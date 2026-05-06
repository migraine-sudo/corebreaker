# Extension Audit Round 1 Summary

## 审计目标
Chrome Extension 相关攻击面，基于历史 CVE 模式分析 + 源码审计

## 三个假设结果

### 假设 1: Navigation Throttle blob/filesystem URL exception — EXCLUDED

**位置:** `extensions/browser/extension_navigation_throttle.cc:243-256`

**假设:** 非扩展页面可导航到有 `webView` 权限的扩展的 `blob:chrome-extension://` URL，因为检查只验证目标扩展有权限而非发起者是该扩展的 webview。

**排除原因:** 2+ 层独立防御完全缓解
1. `webview` 权限仅限 `platform_app` 类型（正在被弃用），普通 MV3 扩展无法有此权限
2. Line 392-394 第二层检查：cross-origin initiator 到 blob/filesystem URL **无条件 CANCEL**
3. `ChildProcessSecurityPolicy::CanRequestURL` 在进程层独立阻止
4. Renderer 层 `SecurityOrigin::canDisplay()` 也会阻止

**注:** 存在一个 `DISABLED_` test (`DISABLED_NestedURLNavigationsToAppBlocked`)，暗示历史上此检查曾不完整，但当前代码有足够防御。

---

### 假设 2: Offscreen Document ViewType 能力差异 — EXCLUDED

**位置:** `extensions/renderer/script_context_set.cc:324`, `extensions/common/api/_api_features.json`

**假设:** 某些 API permission check 遗漏了 `kOffscreenDocument` ViewType，导致能力泄露。

**排除原因:** 安全模型设计正确
1. Offscreen document 获得 `kOffscreenExtension` context type（line 324-326）
2. `_api_features.json` 仅显式授权 messaging API（runtime.connect/sendMessage/onMessage 等），共 9 个 API
3. 96 个 `privileged_extension` API 对 offscreen 不可用
4. `reason` 机制只影响 lifetime（何时关闭），不影响 capability
5. Web API 能力（fetch + CORS bypass）是预期行为（extension process 特权）
6. Process-level 无法区分 offscreen vs privileged extension，但利用需要 compromised renderer（违反 Gate 3）

---

### 假设 3: Service Worker 权限传播竞态 — EXCLUDED

**位置:** `extensions/browser/service_worker/service_worker_host.cc:325-348`

**假设:** worker idle 期间 revoke 权限，`GetServiceWorker()` 返回 null 导致 `UpdatePermissions` 跳过，worker 重启后持有旧权限。

**排除原因:** 2 层冗余更新 + browser 端权威验证
1. **Renderer process 级别更新（不依赖 worker 活跃状态）:** `permissions_updater.cc:718` 通过 `mojom::Renderer::UpdatePermissions` 更新整个 process 的 `PermissionsData`
2. **共享 PermissionsData 对象:** Worker 重启后从 `RendererExtensionRegistry::Get()->GetByID()` 获取同一个 Extension 实例，其 `permissions_data_` 已被 process-level 更新
3. **Service Worker 专用更新是冗余的:** `ServiceWorkerData::UpdatePermissions` (service_worker_data.cc:54-72) 额外做 `UpdateBindings()`，但核心权限数据已由 renderer-level 覆盖
4. **Browser 端权威验证:** API 调用的 feature/permission check 在 browser process 执行，不信任 renderer 缓存

---

## 结论

Extension 子系统的核心权限模型设计健壮。三个假设均被多层防御缓解。

## 下一步建议

放弃当前 3 个假设方向（满足 Kill Criteria: "全部有 2+ 层防御且无法绕过"），转向更有潜力的目标：

1. **Side Panel API dispatch boundary** (2026 新代码，review 可能不完整)
2. **Extension messaging 的 externally_connectable 交互** (历史 CVE 持续出现)
3. **DNR + Service Worker fetch 交互** (NVD 无 CVE，可能未被探索)
4. **Extension permission request UI spoofing** (CVE-2025-0446/0451 表明仍活跃)
