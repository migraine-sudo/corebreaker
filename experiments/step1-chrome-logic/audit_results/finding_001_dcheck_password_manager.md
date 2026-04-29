# Finding 001: password_manager 残留 DCHECK-only 安全检查

## 状态: 待验证

## 摘要

CL 7735722 修复了 `PasswordManager::OnPresaveGeneratedPassword` 中的 DCHECK-only 安全检查
（CVE-2026-6312 High），但同一代码库中还有 3 个同类 DCHECK 未被修复为 runtime check。

## 残留 DCHECK 位置

### 1. password_manager.cc:698 — `OnPasswordNoLongerGenerated`

```cpp
void PasswordManager::OnPasswordNoLongerGenerated(PasswordManagerDriver* driver,
                                                  const FormData& form_data) {
    DCHECK(client_->IsSavingAndFillingEnabled(form_data.url()));
    // release 模式下直接继续执行
    PasswordFormManager* form_manager = GetMatchedManagerForForm(...);
    if (form_manager) {
        form_manager->PasswordNoLongerGenerated();  // 修改状态
    }
}
```

**影响**: 在 Incognito/企业策略禁止保存密码时，仍能修改密码表单管理器的生成状态。
单独看影响较低 — `PasswordNoLongerGenerated()` 只是清除生成标记。

### 2. password_manager.cc:714 — `SetGenerationElementAndTypeForForm`

```cpp
void PasswordManager::SetGenerationElementAndTypeForForm(...) {
    PasswordFormManager* form_manager = GetMatchedManagerForForm(driver, form_id);
    if (form_manager) {
        DCHECK(client_->IsSavingAndFillingEnabled(form_manager->GetURL()));
        // release 模式下直接继续
        form_manager->SetGenerationElement(generation_element);
        form_manager->SetGenerationPopupWasShown(type);
    }
}
```

**影响**: 在策略禁止时仍能标记字段为密码生成字段并记录弹窗显示。
可能导致密码生成 UI 在不该出现的地方出现。

### 3. credential_manager_impl.cc:325 — `OnProvisionalSaveComplete`

```cpp
void CredentialManagerImpl::OnProvisionalSaveComplete() {
    DCHECK(form_manager_);
    const PasswordForm& form = form_manager_->GetPendingCredentials();
    DCHECK(client_->IsSavingAndFillingEnabled(form.url));
    // release 模式下继续 → 可能调用 form_manager_->Save()
    if (form.federation_origin.IsValid()) {
        // ... federated match → Save()
    } else if (form.match_type) {
        form_manager_->Save();  // ← 保存凭据！
    }
    client_->PromptUserToSaveOrUpdatePassword(...);
}
```

**影响**: 这个最严重。虽然入口 `Store()` 有 runtime check，但 `OnProvisionalSaveComplete`
是异步回调（fetch 完成后调用）。存在 TOCTOU 窗口 — 如果在 `Store()` 检查通过后、
`OnProvisionalSaveComplete` 执行前策略状态改变（例如进入 Incognito），凭据仍会被保存。

## 与 CVE-2026-6312 的关系

CL 7735722 的 commit message:
> Fix potential Incognito and policy bypass via DCHECK in OnPresaveGeneratedPassword

修复只改了 1 个函数，但同一安全属性（`IsSavingAndFillingEnabled`）在 3 个其他位置仍然
只有 DCHECK 保护。这是一个**不完整修复**。

## 建议修复

将 3 个 DCHECK 替换为 runtime if check:

```cpp
// password_manager.cc:698
if (!client_->IsSavingAndFillingEnabled(form_data.url())) return;

// password_manager.cc:714 (在 if (form_manager) 内部)
if (!client_->IsSavingAndFillingEnabled(form_manager->GetURL())) return;

// credential_manager_impl.cc:325
if (!client_->IsSavingAndFillingEnabled(form.url)) return;
```

## 调用链分析（已验证）

### credential_manager_impl.cc TOCTOU 完整链

```
Store() [line 65]
  ├── IsSavingAndFillingEnabled() check [line 77] ← runtime check ✓
  ├── creates CredentialManagerPasswordFormManager [line 108]
  │     └── triggers async password store fetch (FormFetcherImpl)
  │           ⋯ 异步等待 ⋯
  │           └── OnFetchCompleted() [credential_manager_password_form_manager.cc:38]
  │                 └── NotifyDelegate() → OnProvisionalSaveComplete()
  │
  └── OnProvisionalSaveComplete() [line 322]
        ├── DCHECK(IsSavingAndFillingEnabled()) [line 325] ← DCHECK only! no-op in release
        ├── form_manager_->Save() [line 336] ← 保存联合凭据
        ├── form_manager_->Save() [line 349] ← 更新现有凭据
        └── PromptUserToSaveOrUpdatePassword() [line 358] ← 新凭据提示保存
```

**TOCTOU 窗口**: 从 `Store()` line 77 检查通过到 `OnProvisionalSaveComplete()` 执行之间
存在异步密码存储查询的时间间隔。在此窗口内如果：
- 用户进入 Incognito 模式（`IsSavingAndFillingEnabled` 返回 false）
- 企业策略动态禁用密码保存
- 用户在设置中关闭密码保存

凭据仍会被保存。

### OnPresaveGeneratedPassword 对比

line 724 `OnPresaveGeneratedPassword` 已修复为 runtime if check — 这正是 CVE-2026-6312
的修复内容。但同一安全属性在 3 个其他位置仍然只有 DCHECK。

## 攻击场景

### 场景 1: Credential Management API + 策略变更

1. 网页调用 `navigator.credentials.store(cred)` — `Store()` runtime check 通过
2. 异步 fetch 开始（查询密码存储中的匹配凭据）
3. **在 fetch 进行时**，MDM 推送策略禁用密码保存
4. `OnProvisionalSaveComplete()` 被调用 — DCHECK 是 no-op — 凭据被保存

### 场景 2: SetGenerationElementAndTypeForForm

1. 用户在允许保存的标签页中触发密码生成
2. **在生成弹窗显示后**，通过设置/策略禁用密码保存
3. `SetGenerationElementAndTypeForForm` 仍然执行 — DCHECK 是 no-op
4. 密码生成 UI 在不该出现时出现

## 严重程度评估

- **credential_manager_impl.cc:325**: Medium-High — 可导致策略绕过保存凭据
- **password_manager.cc:698**: Low — 只清除生成标记
- **password_manager.cc:714**: Low-Medium — 标记字段为生成字段 + 记录弹窗显示

## 下一步

1. ~~验证是否可以构造场景~~ → 调用链已确认，TOCTOU 窗口存在
2. 写 VRP 报告作为 CVE-2026-6312 的不完整修复
3. PoC 验证：在 Chrome release build 中通过 Credential Management API + 动态策略变更复现
