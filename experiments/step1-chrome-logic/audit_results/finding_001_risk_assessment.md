# Finding 001: TOCTOU 实际风险评估

## IsSavingAndFillingEnabled 检查内容

```cpp
// chrome_password_manager_client.cc:270
bool ChromePasswordManagerClient::IsSavingAndFillingEnabled(const GURL& url) const {
    // 条件 A: 自动化测试开关
    if (base::CommandLine::ForCurrentProcess()->HasSwitch(switches::kEnableAutomation))
        return false;
    // 条件 B: 用户设置 — kOfferToSavePasswords
    // 条件 C: !IsOffTheRecord() — Incognito 检查
    // 条件 D: IsFillingEnabled(url) — SSL 错误 + 策略
    return settings_service &&
           settings_service->IsSettingEnabled(kOfferToSavePasswords) &&
           !IsOffTheRecord() &&
           IsFillingEnabled(url);
}
```

## TOCTOU 窗口大小分析

### 异步操作链

```
Store() → IsSavingAndFillingEnabled() check → FormFetcherImpl::Fetch()
  → PasswordStore::GetLogins() → GetGroupedMatchingLoginsAsync()
    → [后台线程] LoginDatabase::GetLogins() [SQLite 查询]
    → [后台线程] Affiliation 匹配
    → AggregatePasswordStoreResults() [等 profile + account 两个 store 都返回]
    → FindMatchesAndNotifyConsumers()
      → OnFetchCompleted()
        → OnProvisionalSaveComplete() → DCHECK only → Save()
```

### 预估延迟

- `LoginDatabase::GetLogins()` — SQLite 查询: 1-50ms (取决于数据库大小和磁盘 I/O)
- Affiliation 匹配: 可能涉及网络请求到 Google 服务器获取 affiliation 信息
- 等待两个 store (profile + account): 必须两个都完成才继续
- **合理估计窗口: 5ms ~ 数秒**（如果涉及 affiliation 网络请求可达数秒）

## 各条件的 TOCTOU 可利用性

### 条件 C: IsOffTheRecord() — 不可利用

`IsOffTheRecord()` 检查的是 `web_contents()->GetBrowserContext()->IsOffTheRecord()`。
一个标签页一旦创建在普通模式，它的 BrowserContext 不会变成 Incognito。
Incognito 和普通模式用不同的 BrowserContext，标签页不能在两者之间迁移。

**结论: 不能在窗口内通过 "进入 Incognito" 改变此条件。**

### 条件 B: kOfferToSavePasswords 设置 — 理论上可利用但需要用户操作

用户可以在 chrome://settings 中关闭 "提供保存密码" 选项。
这是一个实时的 pref 查询（通过 PasswordManagerSettingsService）。

**攻击场景**: 
1. 恶意网页调用 `navigator.credentials.store(cred)` — runtime check 通过
2. 用户在异步窗口内手动关闭密码保存设置
3. `OnProvisionalSaveComplete` 中 DCHECK 无效 → 凭据被保存

**可利用性: 极低** — 需要用户在毫秒级窗口内主动更改设置。不具有实际攻击意义。

### 条件 D: 企业策略动态变更 — 理论上可利用

MDM 可以推送策略禁用密码保存（`PasswordManagerEnabled = false`）。
策略可以在运行时动态更新。

**攻击场景**:
1. 企业用户浏览器当前允许保存密码
2. 恶意网页调用 `navigator.credentials.store(cred)` — runtime check 通过
3. MDM 在窗口内推送策略禁用密码保存
4. `OnProvisionalSaveComplete` → DCHECK no-op → Save()

**可利用性: 极低** — 攻击者无法控制企业 MDM 推送策略的时机。

### 条件 D: SSL 证书状态变化 — 理论上可利用但实际不行

`IsFillingEnabled` 检查 `IsCertStatusError(GetMainFrameCertStatus())`。
但在 `Store()` 已经通过的情况下，SSL 状态不会在同一页面内突变。

**可利用性: 不可利用。**

## 非 TOCTOU 场景: DCHECK 直接绕过（被 compromise 的 renderer）

更现实的场景是 **renderer 进程被 compromise** 后直接调用 Mojo 接口：

1. 被 compromise 的 renderer 直接通过 Mojo 向 browser 进程发送消息
2. 但 `Store()` 的 runtime check 在 browser 进程中，renderer 无法绕过
3. 除非 renderer 能直接触发 `OnProvisionalSaveComplete()` 而不经过 `Store()`

检查是否有从 renderer 直接触发 `OnProvisionalSaveComplete` 的路径:

`OnProvisionalSaveComplete` 是通过 `CredentialManagerPasswordFormManagerDelegate` 接口
由 `CredentialManagerPasswordFormManager::NotifyDelegate()` 调用的。
而 `NotifyDelegate()` 只在 `OnFetchCompleted()` 中调用。
`OnFetchCompleted()` 由 `FormFetcherImpl` 在密码存储查询完成后调用。

**结论: 没有从 renderer 直接触发的路径。所有调用必须经过 `Store()` 入口。**

## 最终风险评估

### TOCTOU 场景

| 条件变更 | 攻击者可控? | 窗口 | 实际可利用性 |
|----------|------------|------|-------------|
| Incognito 切换 | 不可能 | N/A | **不可利用** |
| 用户设置变更 | 需要用户操作 | ~5-50ms | **极低** |
| MDM 策略推送 | 不可控 | ~5-50ms | **极低** |
| SSL 状态变化 | 不可能 | N/A | **不可利用** |

### 总体评估

**实际安全风险: 低**

TOCTOU 窗口虽然存在，但：
1. 攻击者无法控制窗口内条件的变更时机
2. 最关键的 Incognito 条件（`IsOffTheRecord`）根本不会在窗口内改变
3. 唯一理论上可变的条件（用户设置、企业策略）需要外部操作且窗口极短

### 但仍值得报告的理由

1. **代码质量问题**: DCHECK 保护安全属性本身就是 bug pattern（CVE-2026-6312 已证明）
2. **不完整修复**: 同一个 CL 修了一个但漏了三个，这是经典的不完整修复
3. **防御深度**: 即使当前不容易利用，如果未来代码重构增加了异步延迟或改变了调用路径，这个 DCHECK 可能成为真正的安全漏洞
4. **修复成本极低**: 只需将 DCHECK 改为 if-return，3 行代码
5. **password_manager.cc:698 和 714 不依赖 TOCTOU**: 这两个 DCHECK 不在异步回调中，它们在直接方法调用中。如果 renderer 被 compromise 并直接调用这些 Mojo 入口（绕过 renderer 侧的检查），browser 进程中的 DCHECK 就完全失效了。

### 推荐 VRP 提交策略

**作为代码质量 / 不完整修复提交**，而非高危漏洞。预期评级 Low-Medium。
重点强调:
- 与已修复的 CVE-2026-6312 相同的模式
- 修复成本极低
- 防御深度原则

## 补充: password_manager.cc:698/714 的 Mojo 入口分析（已完成）

### OnPasswordNoLongerGenerated (line 698)

Mojo 入口: `ChromePasswordManagerClient::PasswordNoLongerGenerated` (line 1614)
→ 仅检查 `CheckFrameNotPrerendering` + driver 有效性
→ 直接调用 `password_manager_.OnPasswordNoLongerGenerated()`
→ **browser 侧无 `IsSavingAndFillingEnabled` runtime check**

对比 `AutomaticGenerationAvailable` (line 1507)：有 `IsGenerationEnabled()` 检查，
后者包含 `IsSavingAndFillingEnabled()` (password_generation_frame_helper.cc:128)。

结论: renderer 被 compromise 后可以直接通过 Mojo 调用 `PasswordNoLongerGenerated`
而不经过 `IsSavingAndFillingEnabled` 检查。但影响很低 — 只清除生成标记。

### SetGenerationElementAndTypeForForm (line 714)

调用链: Browser UI → `GeneratePassword()` → `GenerationResultAvailable()` callback
→ `ShowPasswordGenerationPopup()` → `SetGenerationElementAndTypeForForm()`

这不是直接从 renderer Mojo 调用的。是 browser 侧内部调用。
整条链上没有 `IsSavingAndFillingEnabled` runtime check，但触发需要用户通过 browser UI
点击密码生成按钮。

结论: 不可从 renderer 直接利用。风险极低。
