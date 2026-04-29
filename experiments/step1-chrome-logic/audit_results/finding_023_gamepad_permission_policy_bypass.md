# Finding 023: Gamepad API Browser 端完全缺失 Permission Policy 检查 ⭐⭐⭐

## 严重性: Medium-High (不需要 compromised renderer!)

## 摘要

`GamepadMonitor::Create()` 和 `GamepadHapticsManager::Create()` 在 browser 端绑定时完全忽略 `RenderFrameHost*` 参数，不检查 Permission Policy、fenced frame 状态或 sandbox flags。Renderer 端的 PP 检查仅在 `navigator.getGamepads()` 中执行，但 `gamepadconnected` 事件监听器注册路径（`DidAddEventListener`）完全不检查 PP。

这意味着**被 Permission Policy 禁止使用 gamepad 的跨域 iframe 仍然可以通过事件监听器接收 gamepad 输入数据**。

## 受影响文件

- `device/gamepad/gamepad_monitor.cc:25-29` — Create() 忽略 RFH
- `device/gamepad/gamepad_haptics_manager.cc:20-25` — Create() 忽略 RFH
- `content/browser/browser_interface_binders.cc:845-846,945` — 直接绑定，无安全检查
- `third_party/blink/renderer/modules/gamepad/navigator_gamepad.cc:290-314` — DidAddEventListener 无 PP 检查

## Bug 详情

### Browser 端：GamepadMonitor 完全不检查 PP

```cpp
// gamepad_monitor.cc:25-29
void GamepadMonitor::Create(
    content::RenderFrameHost*,  // Part of the BinderMapForContext interface.
    mojo::PendingReceiver<mojom::GamepadMonitor> receiver) {
  // RenderFrameHost* 被完全忽略！
  // 没有 Permission Policy 检查
  // 没有 fenced frame 检查
  // 没有 sandbox 检查
  mojo::MakeSelfOwnedReceiver(std::make_unique<GamepadMonitor>(),
                              std::move(receiver));
}
```

### Browser 端：GamepadHapticsManager 同样不检查

```cpp
// gamepad_haptics_manager.cc:20-25
void GamepadHapticsManager::Create(
    content::RenderFrameHost*,
    mojo::PendingReceiver<mojom::GamepadHapticsManager> receiver) {
  // 同样忽略 RFH
  mojo::MakeSelfOwnedReceiver(std::make_unique<GamepadHapticsManager>(),
                              std::move(receiver));
}
```

### 绑定方式对比

```cpp
// browser_interface_binders.cc
// Gamepad — 直接绑定，无安全检查:
map->Add<device::mojom::GamepadHapticsManager>(&device::GamepadHapticsManager::Create);
map->Add<device::mojom::GamepadMonitor>(&device::GamepadMonitor::Create);

// Sensor — 通过 RFH 代理，有 PP 检查:
map->Add<blink::mojom::WebSensorProvider>(
    &BindRenderFrameHostImpl<&RenderFrameHostImpl::GetSensorProvider>);
// → frame_sensor_provider_proxy.cc:71-81 检查 IsFeatureEnabled()

// Compute Pressure — 有自定义绑定函数:
map->Add<blink::mojom::WebPressureManager>(&BindPressureManager);
// → browser_interface_binders.cc:672 检查 IsNestedWithinFencedFrame()
// → browser_interface_binders.cc:682-688 检查 IsFeatureEnabled()
```

### Renderer 端：getGamepads() 有检查

```cpp
// navigator_gamepad.cc:107-108
if (!context || !context->IsFeatureEnabled(
                    network::mojom::PermissionsPolicyFeature::kGamepad)) {
  exception_state.ThrowSecurityError(kFeaturePolicyBlocked);
  return HeapVector<Member<Gamepad>>();
}
```

### Renderer 端：事件监听器注册无检查！

```cpp
// navigator_gamepad.cc:290-314
void NavigatorGamepad::DidAddEventListener(LocalDOMWindow*,
                                           const AtomicString& event_type) {
  // 没有任何 Permission Policy 检查!
  if (IsGamepadConnectionEvent(event_type)) {
    has_connection_event_listener_ = true;
  }
  // ...
  if (has_connection_event_listener_ || has_input_changed_event_listener_) {
    // ...
    if (GetPage() && GetPage()->IsPageVisible()) {
      StartUpdatingIfAttached();  // → 建立 GamepadMonitor Mojo 连接
    }
  }
}
```

### 事件携带完整 Gamepad 数据

```cpp
// navigator_gamepad.cc:419-424
if (has_connection_event_listener_ && is_connected) {
  Gamepad* pad = gamepads_[index];  // 完整的 Gamepad 对象(axes, buttons 等)
  is_gamepads_exposed_ = true;
  DispatchGamepadConnectionChangedEvent(event_type_names::kGamepadconnected, pad);
}
```

## 攻击场景

### 场景 1: PP Bypass — 跨域 iframe 读取 Gamepad 输入 (不需要 compromised renderer!)

1. 嵌入页面设置 `Permissions-Policy: gamepad=()` 禁止所有 iframe 使用 gamepad
2. 跨域 iframe 的 `navigator.getGamepads()` 会被渲染器正确拒绝
3. 但该 iframe 可以注册 `gamepadconnected` 事件监听器
4. 事件监听器注册触发 `StartUpdating` → `GamepadSharedMemoryReader` → 获取 `GamepadMonitor` Mojo 接口
5. Browser 端不检查 PP，直接绑定 → `GamepadStartPolling` 返回共享内存
6. `gamepadconnected` 事件携带完整 Gamepad 对象（包含 axes、buttons 输入数据）
7. **结果**: 被 PP 禁止的 iframe 可以接收 gamepad 连接/断开事件和输入数据

### 场景 2: Fenced Frame 中的 Gamepad 访问

1. `kGamepad` PP feature 不在 `kFencedFrameAllowedFeatures` 白名单中
2. Fenced frame 中不应该能使用 Gamepad API
3. 但 `GamepadMonitor::Create` 不检查 `IsNestedWithinFencedFrame()`
4. Fenced frame 中的代码可以完全绑定并使用 GamepadMonitor 和 GamepadHapticsManager

### 场景 3: Gamepad Haptics 振动

1. 被 PP 禁止的 iframe 或 fenced frame 可以获取 `GamepadHapticsManager`
2. 调用 `PlayVibrationEffectOnce` 触发手柄振动
3. 无需任何 permission prompt

## Fenced Frame 对比

| API | Browser 端 fenced frame 检查 |
|-----|---------------------------|
| BatteryMonitor | 有 (browser_interface_binders.cc:651) |
| ComputePressure | 有 (browser_interface_binders.cc:672) |
| Serial | 有 (render_frame_host_impl.cc:14975) |
| **Gamepad** | **无** |
| **GamepadHaptics** | **无** |

## 前提条件

- **不需要 compromised renderer**
- 只需要一个跨域 iframe 或 fenced frame
- 需要用户有连接的游戏手柄

## VRP 评估

- **严重性**: Medium-High
  - 不需要 compromised renderer!
  - Permission Policy bypass 直接可从网页利用
  - Gamepad 输入可能包含敏感信息（某些无障碍设备模拟为 gamepad）
  - Fenced Frame 限制被完全绕过
- **VRP 价值**: Medium-High
  - 明确的 PP bypass（对比其他 API 都有 browser-side 检查）
  - 多层面问题：PP bypass + fenced frame bypass + 缺少 bad message
  - 修复简单明确

## 建议修复

```cpp
// browser_interface_binders.cc
void BindGamepadMonitor(
    RenderFrameHost* host,
    mojo::PendingReceiver<device::mojom::GamepadMonitor> receiver) {
  if (host->IsNestedWithinFencedFrame()) {
    mojo::ReportBadMessage("Gamepad is not allowed in fenced frames.");
    return;
  }
  if (!host->IsFeatureEnabled(
          network::mojom::PermissionsPolicyFeature::kGamepad)) {
    mojo::ReportBadMessage("Permissions policy blocks access to Gamepad.");
    return;
  }
  device::GamepadMonitor::Create(host, std::move(receiver));
}

// 同样修复 GamepadHapticsManager
```
