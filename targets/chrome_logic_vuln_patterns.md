# Chrome 逻辑漏洞模式分析 — 从实际 Diff 学习

> 通过 Chromium Gerrit Code Review 获取的已合入安全修复，逆向分析漏洞模式。

## 获取 Diff 的方法

不需要 clone Chromium，不需要 bug tracker 权限，通过 Gerrit API 即可：

```bash
# 1. 搜索已合入的安全修复 CL
curl -s --proxy http://127.0.0.1:7890 \
  "https://chromium-review.googlesource.com/changes/?q=status:merged+message:policy+message:bypass&n=20"

# 2. 获取 CL 的 revision ID
curl -s --proxy http://127.0.0.1:7890 \
  "https://chromium-review.googlesource.com/changes/{CL_NUMBER}/?o=CURRENT_REVISION"

# 3. 获取完整 patch（base64 编码）
curl -s --proxy http://127.0.0.1:7890 \
  "https://chromium-review.googlesource.com/changes/{CL_NUMBER}/revisions/{REV_ID}/patch" | \
  python3 -c "import sys,base64; print(base64.b64decode(sys.stdin.read().lstrip(\")}]'\n\")).decode())"

# 4. 获取修改的文件列表
curl -s --proxy http://127.0.0.1:7890 \
  "https://chromium-review.googlesource.com/changes/{CL_NUMBER}/revisions/{REV_ID}/files/"
```

其他有用的搜索关键词：
```
status:merged+message:security+message:bypass
status:merged+message:CSP+message:bypass
status:merged+message:DCHECK+message:fix
status:merged+message:permission+message:check
status:merged+message:"insufficient+policy"
status:merged+message:incognito+message:bypass
```

---

## 模式一：DCHECK-only 保护（release 下失效）

**实例**: CL 7735722 — Incognito and Policy bypass via DCHECK
**Bug ID**: 498301853
**组件**: `components/password_manager/`
**严重性**: High（CVE-2026-6312 Passwords）
**修改量**: 3 行

### 漏洞

```cpp
// password_manager.cc:725 (修复前)
void PasswordManager::OnPresaveGeneratedPassword(...) {
    DCHECK(client_->IsSavingAndFillingEnabled(form_data.url()));
    // release 模式下 DCHECK 是 no-op
    // → Incognito 模式下、或企业策略禁止保存密码时，密码仍会被保存
    PasswordFormManager* form_manager = ...
```

### 修复

```cpp
// password_manager.cc:725 (修复后)
void PasswordManager::OnPresaveGeneratedPassword(...) {
    if (!client_->IsSavingAndFillingEnabled(form_data.url())) {
        return;  // 真正的 runtime check
    }
    PasswordFormManager* form_manager = ...
```

### 可复制的审计方法

在 Chromium 源码中搜索安全检查只依赖 DCHECK 的地方：

```bash
# 在 Chromium 源码中搜索
grep -rn "DCHECK.*IsAllowed\|DCHECK.*IsEnabled\|DCHECK.*CanAccess\|DCHECK.*IsSaving\|DCHECK.*IsValid\|DCHECK.*HasPermission" \
  components/ chrome/browser/ content/browser/ --include="*.cc"
```

**关键洞察**: 这与我们在 ANGLE 中发现的 Bug 1（`ASSERT(glPerVertexVar)` → null deref）是**完全相同的模式**。DCHECK/ASSERT 在 debug 模式下保护代码，但 release 模式下是 no-op，导致安全检查被跳过。

---

## 模式二：错误类型匹配导致 CSP 绕过

**实例**: CL 7656988 — CSP bypass in source map fetches via removed frames
**Bug ID**: 490773579
**组件**: `front_end/core/sdk/PageResourceLoader.ts`（DevTools 前端）
**严重性**: Low（CVE-2026-5901 DevTools）
**修改量**: 22 行

### 漏洞

DevTools 加载 source map 时，只在错误消息**恰好是 "CSP violation"** 时才拒绝 fallback：

```typescript
// 修复前
} catch (e) {
    if (e.message.includes('CSP violation')) {
        // 阻止 fallback — 但只匹配这一种错误字符串！
        return { success: false, ... };
    }
    // 其他错误 → fallback 到 host bindings（绕过 CSP）
}
```

**攻击方法**: 注入一个 iframe，在 source map fetch 发出后立刻删除 iframe。fetch 失败的错误是 `"Frame not found"` 而不是 `"CSP violation"`，于是 fallback 被触发，绕过了 CSP。

### 修复

在 fetch 之前**主动检查 CSP 策略**，而不是依赖错误消息字符串匹配：

```typescript
// 修复后 — 先查 CSP 策略
let mustEnforceCSP = false;
if (isHttp && initiator.target) {
    const status = await networkManager.getSecurityIsolationStatus(initiator.frameId);
    if (status?.csp) {
        for (const csp of status.csp) {
            if (csp.effectiveDirectives.includes('connect-src') ||
                csp.effectiveDirectives.includes('default-src')) {
                mustEnforceCSP = true;
            }
        }
    }
}
// ...
} catch (e) {
    if (mustEnforceCSP || e.message.includes('CSP violation')) {
        // 不管错误是什么，只要有 CSP 就不 fallback
    }
}
```

### 可复制的审计方法

搜索**依赖错误消息字符串来做安全决策**的代码：

```bash
grep -rn "\.message.*includes\|\.message.*indexOf\|\.message.*===\|\.message.*match" \
  --include="*.ts" --include="*.js" --include="*.cc" \
  chrome/ content/ third_party/devtools-frontend/
```

搜索 **fallback 机制**（fallback 常常绕过安全检查）：

```bash
grep -rn "fallback\|fall.back\|retry\|alternative.*load" \
  --include="*.ts" --include="*.cc" \
  front_end/ chrome/browser/
```

---

## 模式三：Frame Tree 检查逻辑不完整

**实例**: CL 7681373 — LNA bypass via opener navigation
**Bug ID**: 491509051
**组件**: `content/browser/storage_partition_impl.cc`
**严重性**: Medium（CVE-2026-5881 LocalNetworkAccess）
**修改量**: 6 行新增 / 23 行删除

### 漏洞

Local Network Access (LNA) 权限检查要求 navigation initiator 在 navigating frame 的 frame tree 中。但有一种合法场景不满足这个条件：

```
top window (origin1) 嵌入 iframe (origin2)
→ iframe 打开新窗口 (origin2)
→ 新窗口通过 opener.location.href = "LNA-url" 导航 iframe
```

此时 initiator（新窗口）不在 iframe 的 frame tree 中，原来的代码会 fallback 到 `rfh = nullptr`，导致**权限检查被完全跳过**。

### 修复

删除了"initiator 必须在 frame tree 中"的检查，直接在 initiator 上检查 LNA 权限：

```cpp
// 修复后 — 直接用 initiator，不要求在 frame tree 中
rfh = request->GetInitiatorFrameToken().has_value()
    ? RenderFrameHost::FromFrameToken(...)
    : nullptr;
```

### 可复制的审计方法

搜索 **frame tree 遍历做安全检查** 的代码（容易遗漏跨窗口场景）：

```bash
grep -rn "GetParent\(\).*while\|frame_tree.*walk\|IsDescendantOf\|ancestor.*frame" \
  content/browser/ --include="*.cc"
```

搜索 **opener 相关的安全检查**：

```bash
grep -rn "opener\|GetOpener\|opener_.*frame\|opener_.*origin" \
  content/browser/ --include="*.cc"
```

---

## 总结：三种主要的 Chrome 逻辑漏洞模式

| 模式 | 核心问题 | 搜索策略 | 示例 |
|------|---------|---------|------|
| **DCHECK-only 保护** | 安全检查依赖 debug-only 断言 | `grep DCHECK.*Is.*Enabled` | Passwords bypass |
| **错误类型依赖** | 安全决策基于错误字符串匹配 | `grep message.*includes` | CSP bypass |
| **Frame 关系遗漏** | 安全检查假设特定的 frame 拓扑 | `grep GetParent.*while` | LNA bypass |

### 额外值得关注的模式

| 模式 | 说明 |
|------|------|
| **Timing window** | 在异步操作之间的状态不一致窗口（Security UI 欺骗） |
| **Fallback 逻辑** | 主路径被拒绝后 fallback 路径绕过安全检查 |
| **Feature flag 交互** | 新 feature flag 意外改变了安全行为 |
| **跨进程状态同步** | renderer 与 browser 进程之间的安全状态不一致 |

---

## 实操建议

### 不需要编译的审计方式

1. **Chromium Code Search**: https://source.chromium.org — 在线搜索和浏览 Chromium 源码
2. **Gerrit CL 搜索**: 搜安全修复的 diff，学习模式后找同类问题
3. **本地 shallow clone**:
   ```bash
   git clone --depth=1 --filter=blob:none https://chromium.googlesource.com/chromium/src
   # 只 ~2GB，不含历史，足够 grep
   ```

### 优先审计的目录

```
content/browser/         # 浏览器进程安全逻辑（Policy, LNA, Permissions）
chrome/browser/download/ # 下载保护
components/password_manager/ # 密码管理
front_end/               # DevTools 前端（TypeScript，最容易审计）
third_party/blink/renderer/core/frame/ # Frame 安全
```
