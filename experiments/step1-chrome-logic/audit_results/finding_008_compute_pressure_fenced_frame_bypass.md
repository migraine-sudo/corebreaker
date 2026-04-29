# Finding 008: Compute Pressure API — Worker 绕过 Fenced Frame 限制

## 严重性: Low-Medium

## 摘要

Compute Pressure API 在 frame 绑定路径中 (`browser_interface_binders.cc:672`) 显式阻止
fenced frame 中的访问，使用 `bad_message::ReceivedBadMessage` 终止 renderer。
但 DedicatedWorker 和 SharedWorker 的绑定路径完全跳过了 fenced frame 检查。

如果 fenced frame 可以创建 worker（需要验证），worker 可以成功绑定 Compute Pressure 服务。

## 受影响组件

- `content/browser/worker_host/dedicated_worker_host.cc:987` (`BindPressureService`)
- `content/browser/worker_host/shared_worker_host.cc:784` (`BindPressureService`)
- `content/browser/compute_pressure/pressure_service_for_dedicated_worker.cc`
- `content/browser/compute_pressure/pressure_service_for_shared_worker.cc`

## 漏洞详情

### Frame 绑定路径 — 有 Fenced Frame 检查

```cpp
// browser_interface_binders.cc:672-681
void BindPressureManager(
    RenderFrameHost* host,
    mojo::PendingReceiver<blink::mojom::WebPressureManager> receiver) {
  // ... secure origin check ...
  if (host->IsNestedWithinFencedFrame()) {
    bad_message::ReceivedBadMessage(
        host->GetProcess(),
        bad_message::BadMessageReason::
            BIBI_BIND_PRESSURE_MANAGER_FOR_FENCED_FRAME);
    return;  // ← 终止 renderer！
  }
  // ... PP check ...
}
```

### Worker 绑定路径 — 无 Fenced Frame 检查

```cpp
// dedicated_worker_host.cc (简化)
void DedicatedWorkerHost::BindPressureService(...) {
  // ← 没有 IsNestedWithinFencedFrame() 检查！
  // 直接创建 PressureServiceForDedicatedWorker
}
```

### PressureServiceForDedicatedWorker::CanCallAddClient 也不检查

```cpp
// 基类 PressureServiceBase::CanCallAddClient() 对 worker 返回 true
// PressureServiceForFrame::CanCallAddClient() 检查 fenced frame
// 但 Worker 子类没有 override — 无条件允许
```

## 攻击场景

1. 网页在 fenced frame 内创建一个 dedicated worker
2. Worker 通过 `PressureObserver.observe()` 请求 CPU 压力数据
3. 由于 worker 路径不检查 fenced frame，请求成功
4. Fenced frame 获得 CPU 压力信息 — 这违反了 fenced frame 的信息隔离要求

## 前提和限制

1. **Fenced frame 能否创建 worker**: 需要验证。如果 fenced frame 不能创建 worker，此漏洞不可利用
2. **信息泄露有限**: CPU 压力是粗粒度的 ("nominal", "fair", "serious", "critical")
3. **Spec 明确要求**: Compute Pressure spec 明确阻止 fenced frame 使用
4. **`HasImplicitFocus` 过滤**: 即使绑定成功，`ShouldDeliverUpdate()` 检查 `HasImplicitFocus()`，fenced frame 内的 worker 可能收不到更新

## VRP 可报告性

- **严重性**: Low（信息粗粒度，但违反 spec 要求）
- **已知性**: 没有 TODO 注释提及此问题
- **VRP 价值**: Low — 信息泄露有限，且需要确认 fenced frame 能创建 worker

## 发现方法

通过对比 Compute Pressure API 的 frame 和 worker 绑定路径的安全检查一致性发现。
