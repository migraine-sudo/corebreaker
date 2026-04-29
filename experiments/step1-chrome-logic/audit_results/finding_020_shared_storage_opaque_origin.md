# Finding 020: Shared Storage CreateWorklet() 缺少 data_origin Opaque 验证

## 严重性: Medium (需要 compromised renderer)

## 摘要

`SharedStorageDocumentServiceImpl::CreateWorklet()` 接受 renderer 提供的 `data_origin` 参数但不检查其是否为 opaque origin。对比同文件中的 `SharedStorageUpdate()` 和 `SharedStorageBatchUpdate()` 方法都有 opaque origin 检查并调用 `ReportBadMessage()`。`SharedStorageWorkletHost` 构造函数仅用 DCHECK（release build 中不生效）保护。

## 受影响文件

- `content/browser/shared_storage/shared_storage_document_service_impl.cc:111-161` — 入口点，无 opaque 检查
- `content/browser/shared_storage/shared_storage_worklet_host.cc:417-418` — DCHECK-only 保护

## Bug 详情

### CreateWorklet() — 无 opaque 检查
```cpp
// shared_storage_document_service_impl.cc:111
void SharedStorageDocumentServiceImpl::CreateWorklet(
    const GURL& script_source_url,
    const url::Origin& data_origin,  // ← renderer 提供，未验证 opaque
    ...) {
  // 注释明确说跳过了 opaque 验证：
  // "Hence, we skip the mojom validation for opaque origin context for addModule()."
  ...
  GetSharedStorageRuntimeManager()->CreateWorkletHost(
      this, render_frame_host().GetLastCommittedOrigin(), data_origin, ...);
}
```

### SharedStorageUpdate() — 有 opaque 检查
```cpp
// shared_storage_document_service_impl.cc:167
if (render_frame_host().GetLastCommittedOrigin().opaque()) {
    receiver_.ReportBadMessage(
        "Attempted to call SharedStorageUpdate() from an opaque origin "
        "context.");
    return;
}
```

### WorkletHost 构造函数 — DCHECK-only
```cpp
// shared_storage_worklet_host.cc:417-418
// The data origin can't be opaque.
DCHECK(!shared_storage_origin_.opaque());
```

## 影响

Compromised renderer 可以用 opaque origin 作为 `data_origin` 创建 worklet：
- 访问 opaque origin 下的 shared storage（可能绕过 origin-keyed 隔离）
- `.well-known` opt-in 检查可能对 opaque origin 行为异常
- Budget 计算可能被破坏（opaque SchemefulSite 不匹配任何真实站点）

## Renderer 端检查

Renderer 端 `shared_storage_worklet.cc:222` 有 `IsOpaque()` 检查。因此需要 compromised renderer 才能利用。

## VRP 评估

- **严重性**: Medium — 需要 compromised renderer，但 browser 端缺少验证是标准安全模型违规
- **模式**: 同一个 service 的不同方法有不一致的安全检查（与 Finding 004, 005 模式相同）
- **代码注释**: 代码中有注释解释了为什么跳过检查，但理由不充分
- **VRP 价值**: Low-Medium — Chromium 团队可能认为这是已知设计决策
