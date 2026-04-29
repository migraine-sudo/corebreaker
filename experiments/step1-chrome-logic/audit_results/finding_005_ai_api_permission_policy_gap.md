# Finding 005: AI API (AIManager) — Proofreader 和 Classifier 缺少 Permission Policy 检查

## 严重性: Medium

## 摘要

Chrome 内置 AI API (`chrome/browser/ai/ai_manager.cc`) 的 `Proofreader` 和 `Classifier`
功能缺少 Permissions Policy 检查。同一接口中的其他 AI 功能（LanguageModel、Summarizer、
Writer、Rewriter）都有一致的 PP 检查。代码中有明确的 TODO 注释承认了这一缺失。

此外，`GetLanguageModelParams` 和 `AddModelDownloadProgressObserver` 也没有 PP 检查。

## 受影响组件

- `chrome/browser/ai/ai_manager.cc`
- Mojo 接口: `blink::mojom::AIManager`

## 漏洞详情

### Permission Policy 检查一致性

| 方法 | PP 检查 | 状态 |
|------|---------|------|
| `CanCreateLanguageModel` | `IsPermissionsPolicyBlocked(kLanguageModel)` ✓ | 安全 |
| `CreateLanguageModel` | `IsBlocked(kLanguageModel)` ✓ | 安全 |
| `CanCreateSummarizer` | `IsPermissionsPolicyBlocked(kSummarizer)` ✓ | 安全 |
| `CreateSummarizer` | `IsBlocked(kSummarizer)` ✓ | 安全 |
| `CanCreateWriter` | `IsPermissionsPolicyBlocked(kWriter)` ✓ | 安全 |
| `CreateWriter` | `IsBlocked(kWriter)` ✓ | 安全 |
| `CanCreateRewriter` | `IsPermissionsPolicyBlocked(kRewriter)` ✓ | 安全 |
| `CreateRewriter` | `IsBlocked(kRewriter)` ✓ | 安全 |
| **`CanCreateProofreader`** | **无** ❌ `TODO(crbug.com/466425250)` | **缺失** |
| **`CreateProofreader`** | **`IsBlocked()` 无参数** ❌ | **缺失** — 只检查 pref，不检查 PP |
| **`CanCreateClassifier`** | **无** ❌ `TODO(crbug.com/499365168)` | **缺失** |
| **`CreateClassifier`** | **`IsBlocked()` 无参数** ❌ | **缺失** — 只检查 pref，不检查 PP |
| `GetLanguageModelParams` | **无** | 只返回参数信息，风险较低 |
| `AddModelDownloadProgressObserver` | **无** | 只订阅下载进度，风险较低 |

### `IsBlocked()` 的两种调用形式

```cpp
// 有 PP 检查的正确形式 (line 453)
if (IsBlocked(network::mojom::PermissionsPolicyFeature::kLanguageModel)) {

// 无 PP 检查的形式 (line 698, 951)
if (IsBlocked()) {  // ← feature 参数缺失，只检查 pref
```

`IsBlocked` 实现 (line 1166-1172):
```cpp
bool AIManager::IsBlocked(
    std::optional<network::mojom::PermissionsPolicyFeature> feature) {
  if (feature.has_value() && IsPermissionsPolicyBlocked(feature.value())) {
    return true;  // ← 只在 feature 有值时才检查 PP
  }
  return GetPrefBlockedResult().has_value();  // ← 无参数时只检查 pref
}
```

### CanCreateProofreader — 无 PP 检查 (line 672-691)

```cpp
void AIManager::CanCreateProofreader(
    blink::mojom::AIProofreaderCreateOptionsPtr options,
    CanCreateProofreaderCallback callback) {
  // TODO(crbug.com/466425250): Enforce permissions policy.
  if (auto pref_blocked_result = GetPrefBlockedResult()) {
    std::move(callback).Run(*pref_blocked_result);
    return;
  }
  // ... 直接进入能力检查，无 PP 检查
}
```

### CreateProofreader — `IsBlocked()` 无参数 (line 694-701)

```cpp
void AIManager::CreateProofreader(
    mojo::PendingRemote<blink::mojom::AIManagerCreateProofreaderClient> client,
    blink::mojom::AIProofreaderCreateOptionsPtr options) {
  // TODO(crbug.com/466425250): Enforce permissions policy.
  if (IsBlocked()) {  // ← 无 PP feature 参数！
    receivers_.ReportBadMessage("Policy or user setting disabled");
    return;
  }
  // ...
}
```

### CanCreateClassifier — 无 PP 检查 (line 933-944)

```cpp
void AIManager::CanCreateClassifier(
    blink::mojom::AIClassifierCreateOptionsPtr options,
    CanCreateClassifierCallback callback) {
  // TODO(crbug.com/499365168): Enforce permissions policy and
  // CheckAndFixLanguages.
  if (auto pref_blocked_result = GetPrefBlockedResult()) {
    std::move(callback).Run(*pref_blocked_result);
    return;
  }
  // ... 直接进入能力检查，无 PP 检查
}
```

### CreateClassifier — `IsBlocked()` 无参数 (line 946-974)

```cpp
void AIManager::CreateClassifier(
    mojo::PendingRemote<blink::mojom::AIManagerCreateClassifierClient> client,
    blink::mojom::AIClassifierCreateOptionsPtr options) {
  // TODO(crbug.com/499365168): Enforce permissions policy and
  // CheckAndFixLanguages.
  if (IsBlocked()) {  // ← 无 PP feature 参数！
    receivers_.ReportBadMessage("Policy or user setting disabled");
    return;
  }
  // ...
}
```

## 攻击场景

### 场景: 跨域 iframe 未经授权使用 AI 功能

1. `publisher.com` 嵌入第三方 iframe `tracker.com`
2. `publisher.com` 设置 `Permissions-Policy: ai-proofreader=()` 或 `ai-classifier=()` 拒绝所有子框架使用该功能
3. `tracker.com` iframe 仍然可以调用 `ai.proofreader.create()` 或 `ai.classifier.create()`
4. Permission Policy 限制被绕过

### 影响

- **资源滥用**: 第三方 iframe 可以使用嵌入页面主机的 AI 推理资源（本地模型），消耗 CPU/GPU
- **隐私**: Proofreader 和 Classifier 处理用户输入的文本/数据，不受嵌入者控制的第三方 iframe 可以滥用这些 API
- **PP 绕过**: 站点管理者无法通过 Permissions-Policy 头限制这些 AI 功能的使用

## 前提和限制

1. **Chrome AI 功能需要已下载本地模型**: 用户必须已安装 Chrome AI 模型
2. **PP 类型可能尚未定义**: 如果 `kProofreader` 和 `kClassifier` PP feature 枚举尚未定义，则 renderer 侧也无法设置限制。但 TODO 表明这是计划中的功能
3. **功能可能在 Chrome Origin Trial 阶段**: 新 AI API 可能尚未 GA
4. **Chromium 团队已知**: TODO 注释中有 crbug 链接，说明团队已跟踪此问题

## VRP 可报告性分析

- **已知性**: TODO + crbug 说明团队已知，但尚未修复
- **VRP 政策**: Chrome VRP 通常接受"已知但未修复"的问题，尤其是有明确安全影响的
- **竞争风险**: crbug 可能是公开的，其他研究者可能已报告
- **预期评级**: Low-Medium（PP 绕过，但影响限于 AI API 功能使用）

## 建议修复

为 Proofreader 和 Classifier 添加与其他 AI 方法一致的 PP 检查：

```cpp
void AIManager::CanCreateProofreader(...) {
  if (IsPermissionsPolicyBlocked(
          network::mojom::PermissionsPolicyFeature::kProofreader)) {
    receivers_.ReportBadMessage("Permissions policy disabled");
    return;
  }
  // ...
}

void AIManager::CreateProofreader(...) {
  if (IsBlocked(network::mojom::PermissionsPolicyFeature::kProofreader)) {
    receivers_.ReportBadMessage("Policy or user setting disabled");
    return;
  }
  // ...
}
```

## 发现方法

通过系统性审计 `AIManager` 所有 Mojo 方法的 Permission Policy 检查一致性发现。
这是 Pattern 2（新 API 方法缺少已有权限检查）的又一实例。
