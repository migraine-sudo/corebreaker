# Finding 007: Digital Credentials API — 缺少 Browser 端 User Activation 检查 ⭐

## 严重性: Medium

## 摘要

Digital Credentials API (`navigator.identity.get()` / `navigator.identity.create()`) 的
browser 端实现 (`DigitalIdentityRequestImpl::Get()` / `Create()`) 缺少 transient user
activation 检查。User activation 验证仅在 renderer 侧进行（`digital_identity_credential.cc`
line 273），browser 端未二次验证。

按照 Chromium 安全模型，renderer 可能被攻陷（compromised renderer）。安全关键检查必须在
browser 端强制执行，renderer 侧检查仅作为用户体验优化。

## 受影响组件

- `content/browser/digital_credentials/digital_identity_request_impl.cc`
- Mojo 接口: `blink::mojom::DigitalIdentityRequest`

## 漏洞详情

### Browser 端安全检查表

| 检查 | `Get()` (line 448) | `Create()` (line 542) | 状态 |
|------|-------|---------|------|
| Feature flag | ✓ `IsDigitalCredentialsEnabled()` | ✓ `IsDigitalCredentialsCreationEnabled()` | 安全 |
| Fenced frame | ✓ `IsNestedWithinFencedFrame()` | ✓ | 安全 |
| Permission Policy | ✓ `kDigitalCredentialsGet` | ✓ `kDigitalCredentialsCreate` | 安全 |
| IsActive + Visible | ✓ (line 516-520) | ✓ | 安全 |
| Duplicate request | ✓ `callback_` 检查 | ✓ | 安全 |
| **User Activation** | **❌ 缺失** | **❌ 缺失** | **漏洞** |

### Renderer 端 User Activation 检查 (line 273-285)

```cpp
// third_party/blink/renderer/modules/credentialmanagement/digital_identity_credential.cc:273
bool has_activation = LocalFrame::ConsumeTransientUserActivation(
    To<LocalDOMWindow>(resolver->GetExecutionContext())->GetFrame(),
    UserActivationUpdateSource::kRenderer);
base::UmaHistogramBoolean(
    "Blink.DigitalCredentials.Get.HasTransientUserActivation",
    has_activation);
if (!has_activation) {
  resolver->Reject(MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kNotAllowedError,
      "The 'digital-credentials-get' feature requires transient "
      "activation."));
  return;  // ← 不发 Mojo IPC
}
```

### Browser 端 `Get()` 无 User Activation 检查 (line 448-540)

```cpp
void DigitalIdentityRequestImpl::Get(
    std::vector<blink::mojom::DigitalCredentialGetRequestPtr>
        digital_credential_requests,
    GetCallback callback) {
  if (!webid::IsDigitalCredentialsEnabled()) { ... }        // ← 有
  if (render_frame_host().IsNestedWithinFencedFrame()) { ... } // ← 有
  if (!render_frame_host().IsFeatureEnabled(kDigitalCredentialsGet)) { ... } // ← 有
  if (callback_) { ... }  // duplicate check
  // ... 直接进入 provider 调用流程
  // ← 没有 HasTransientUserActivation() 检查！
  
  provider_ = GetContentClient()->browser()->CreateDigitalIdentityProvider();
  // ...
  provider_->ShowDigitalIdentityInterstitial(...);  // 或直接调用 provider_->Get()
}
```

### `kErrorNoTransientUserActivation` 枚举未被使用

```cpp
// digital_identity_request_impl.cc:307
case RequestStatusForMetrics::kErrorNoTransientUserActivation:
  return RequestDigitalIdentityStatus::kErrorNoTransientUserActivation;
```

该错误状态存在于枚举中，但 browser 端代码从未设置它 — 只用于 embedder 的 DigitalIdentityProvider 可选返回。

## 攻击场景

### Compromised Renderer 无用户交互触发凭据请求

1. 攻击者通过已知漏洞或 WebAssembly bug 获得 renderer 进程控制权
2. 攻击者直接通过 Mojo IPC 调用 `DigitalIdentityRequest::Get()`
3. Browser 端接受请求（通过了 PP、feature flag、fenced frame 等检查）
4. 对于满足 interstitial bypass 条件的请求（年龄验证、DPC、电话号码验证）：
   - 直接调用 `provider_->Get()` — 无任何 browser UI 提示
   - 用户完全不知情
5. 对于不满足 bypass 条件的请求：
   - 会显示 interstitial — 但这不应是唯一的防护层

### Interstitial Bypass 使场景更危险

```cpp
// digital_identity_request_impl.cc (简化 ComputeInterstitialType)
std::optional<InterstitialType> interstitial_type = ComputeInterstitialType(...);
if (!interstitial_type) {
  // ← 直接发送到 wallet，无 UI 提示！
  OnInterstitialDone(std::move(request_to_send), ...);
  return;
}
```

当请求声称只需要"年龄验证"或"电话号码验证"等低风险 claim 时，interstitial 被跳过。
Compromised renderer 可以构造这样的请求来绕过任何 UI 提示。

## 对比其他 API 的 Browser 端 User Activation 检查

- **Payment Request API**: Browser 端检查 `render_frame_host().HasTransientUserActivation()`
- **Web Share API**: Browser 端检查 transient user activation
- **File System Access API (`showOpenFilePicker`)**: Browser 端检查 user activation
- **Clipboard (write)**: Browser 端检查 user activation

## VRP 可报告性分析

- **新颖性**: 这是一个标准的"renderer-only security check"模式漏洞
- **Chromium 安全模型**: Chromium 明确规定 renderer 可能被攻陷，browser 端必须强制安全检查
- **已知性**: 没有 TODO 注释提及此问题，crbug 搜索可能需要确认
- **影响**: 取决于 platform wallet 是否自己检查 user activation（Android Intent 可能有，但这不应是唯一防护）
- **预期评级**: Medium（compromised renderer + 可绕过 interstitial → 无 UI 凭据泄露）
- **VRP 价值**: 中等 — 需要 compromised renderer 作为前提，但这是 Chromium VRP 的标准威胁模型

## 建议修复

```cpp
void DigitalIdentityRequestImpl::Get(
    std::vector<blink::mojom::DigitalCredentialGetRequestPtr>
        digital_credential_requests,
    GetCallback callback) {
  // 现有检查 ...
  
  // 添加: browser 端 user activation 检查
  if (!render_frame_host().HasTransientUserActivation()) {
    std::move(callback).Run(
        RequestDigitalIdentityStatus::kErrorNoTransientUserActivation,
        /*protocol=*/std::nullopt, /*token=*/base::Value());
    return;
  }
  // 消费 user activation 防止重复使用
  render_frame_host().frame_tree_node()->UpdateUserActivationState(
      blink::mojom::UserActivationUpdateType::kConsumeTransientActivation,
      blink::mojom::UserActivationNotificationType::kNone);
  
  // ... 继续现有逻辑
}
```

## 发现方法

通过系统性审计 Digital Credentials API 的 browser 端安全检查与 renderer 端检查的一致性发现。
这是 Chromium 安全审计的标准方法：对于每个 renderer 侧的安全检查，验证 browser 端是否有等效的强制检查。
