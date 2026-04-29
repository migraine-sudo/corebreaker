# Finding 022: Presentation API StartPresentation() 缺少 Browser 端 User Activation 检查

## 严重性: Medium (需要 compromised renderer)

## 摘要

`PresentationServiceImpl::StartPresentation()` 不在 browser 端验证 transient user activation。User activation 检查仅在 renderer 侧 (`presentation_request.cc:138-143`) 执行。Compromised renderer 可以无需用户交互触发 Media Router 选择 UI。

## 受影响文件

- `content/browser/presentation/presentation_service_impl.cc:219-253` — StartPresentation()
- `content/browser/presentation/presentation_service_impl.cc:371-401` — SetDefaultPresentationUrls()
- `content/browser/browser_interface_binders.cc:895-896` — PresentationService 绑定

## Bug 详情

### Browser 端无 User Activation 检查
```cpp
// presentation_service_impl.cc:219-253
void PresentationServiceImpl::StartPresentation(
    const std::vector<GURL>& presentation_urls,
    NewPresentationCallback callback) {
  // 无 user activation 检查！
  // 直接调用 delegate 显示 Media Router UI
  controller_delegate_->StartPresentation(request, ...);
}
```

### Renderer 端检查（唯一的检查）
```cpp
// presentation_request.cc:138-143
if (!LocalFrame::HasTransientUserActivation(frame)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "PresentationRequest::start() requires user gesture.");
    return;
}
```

### 对比：其他需要 user gesture 的 API 都有 browser 端检查

- EyeDropper: `eye_dropper_chooser_impl.cc:27-33` — `UpdateUserActivationState(ConsumeTransientActivation)`
- File Picker: browser 端检查 `HasTransientUserActivation()`
- Window.open (popups): `render_frame_host_impl.cc:10244` — browser 端检查

## 影响

1. **Compromised renderer** 可以直接调用 `StartPresentation()` Mojo 方法
2. 这会弹出 Media Router 设备选择 UI（Chrome Cast picker）
3. 用户仍需在 UI 中选择设备才能建立连接
4. 但弹出 UI 本身不需要用户交互 — **这违反了 user activation 要求**

### 附加问题：Sandbox/Fenced Frame 检查缺失

- `PresentationService` Mojo 接口绑定时没有检查 sandbox flags
- Renderer 端有 `kPresentationController` sandbox flag 检查
- Browser 端不检查 `IsSandboxed(WebSandboxFlags::kPresentationController)`
- Compromised renderer 在 sandboxed iframe 中可以使用 Presentation API

## 前提条件

- 需要 compromised renderer
- 但这是 Chromium 标准威胁模型中的标准假设

## VRP 评估

- **严重性**: Medium — 与 Finding 007 (Digital Credentials) 相同模式
- **模式**: renderer-only security check，browser 不做验证
- **影响**: 弹出系统 UI（Media Router 选择器）无需用户交互
- **VRP 价值**: Low-Medium — 用户仍需在 UI 中选择设备才有实际影响
