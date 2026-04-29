# 安全修复 Diff 模式分析

> 从 172 个 Gerrit CL 中提取的可复制漏洞模式。

## 模式汇总

| # | 模式 | 实例 CL | 可搜索性 | 优先级 |
|---|------|---------|---------|--------|
| 1 | DCHECK-only 保护 | 7735722 | 高 (grep) | **最高** |
| 2 | 新 API 缺少已有权限检查 | 7509483, 7029640 | 高 (grep) | **最高** |
| 3 | Intent sender 未验证 | 7763202 | 高 (grep) | 高 |
| 4 | 错误字符串依赖 | 7656988 | 中 (grep) | 高 |
| 5 | Frame tree 遍历不完整 | 7681373 | 中 | 中 |
| 6 | 回调 reentrant 竞态 | 6875344 | 低 | 中 |
| 7 | renderer 3PCD 策略绕过 | 7726801 | 中 | 中 |
| 8 | UI 快捷键绕过策略 | 4661413 | 低 | 低 |
| 9 | 下载恢复 hash 不同步 | 7762205 | 中 | **高** |

---

## 模式 1: DCHECK-only 保护（已知，最高优先级）

**CL 7735722** — password_manager 中 `DCHECK(IsSavingAndFillingEnabled)` 在 release 无效，导致 Incognito 策略绕过。

**搜索**:
```bash
grep -rn "DCHECK.*Is.*Enabled\|DCHECK.*Is.*Allowed\|DCHECK.*Can.*Access\|DCHECK.*Has.*Permission" \
  content/browser/ components/ chrome/browser/ --include="*.cc"
```

---

## 模式 2: 新 API 方法缺少已有权限检查（新发现，最高优先级）

**CL 7509483** — `ClipboardHostImpl` 新增的 `ReadAvailableCustomAndStandardFormats()` 和 `ReadUnsanitizedCustomFormat()` 缺少 `IsRendererPasteAllowed()` 检查。其他 clipboard 方法都有。

**CL 7029640** — `clipboardchange` 事件无需用户激活或 clipboard-read 权限就能触发。

**核心问题**: 当一个类/接口新增方法时，开发者常常忘记复制已有方法的安全检查。

**搜索策略**:
1. 找到 Mojo IPC 接口的方法列表
2. 检查每个方法是否有一致的权限检查
3. 新增的方法（最近 6 个月的 commit）是重点

```bash
# 在 Chromium 中搜索 Mojo 接口实现中可能缺少权限检查的方法
# 先找 clipboard 相关的所有实现方法
grep -rn "void ClipboardHostImpl::" content/browser/ --include="*.cc"
# 再检查哪些有 IsRendererPasteAllowed，哪些没有
```

**泛化搜索**:
```bash
# 找所有 HostImpl 类（Mojo 接口的 browser 端实现）
grep -rn "class.*HostImpl.*public" content/browser/ --include="*.h" | head -50
# 对每个类，检查方法间的权限检查一致性
```

---

## 模式 3: Android Intent sender 未验证（新发现）

**CL 7763202** — `ReaderModeManager.isReaderModeCreatedIntent()` 未检查 `wasIntentSenderChrome()`，外部 app 可构造 intent extra 在 Chrome incognito 中打开标签。

**搜索**:
```bash
# 找所有从 intent extra 读取数据但未验证 sender 的地方
grep -rn "safeGetIntExtra\|safeGetStringExtra\|getIntExtra\|getStringExtra" \
  chrome/android/ --include="*.java" | grep -v "wasIntentSenderChrome\|isTrusted"
```

---

## 模式 4: 错误字符串依赖（已知）

**CL 7656988** — DevTools source map fetch CSP bypass。

---

## 模式 5: Frame tree 遍历不完整（已知）

**CL 7681373** — LNA bypass via opener navigation。

---

## 模式 6: 回调 reentrant 竞态条件（新发现）

**CL 6875344** — ServiceWorker timeout 回调触发新请求，修改正在遍历的容器。5 个 backport (M132-M140) 说明影响范围大。

**搜索**:
```bash
# 找遍历容器并在循环中调用回调的代码
grep -rn "while.*begin\(\).*end\(\)" content/browser/ --include="*.cc" | head -30
# 或找 swap+iterate 模式（已知的 fix pattern）
grep -rn "\.swap(" content/browser/service_worker/ --include="*.cc"
```

---

## 模式 7: renderer 侧 3PCD 策略绕过

**CL 7726801** — Storage Access API 在 renderer 侧绕过 3PCD 策略。虽然修复说影响不明确（autogrants 已移除），但代码清理本身说明这类逻辑值得审计。

---

## 模式 9: 下载恢复 hash 状态不同步（新发现，高优先级）

**CL 7762205** (2026-04-21, 非常新) — 下载中断恢复时，如果 offset 被 clamp 到 0 重新开始，SHA-256 hash 状态仍保留旧值，导致最终 hash 与文件内容不匹配。攻击者可利用此绕过 Safe Browsing 哈希黑名单。

修复 3 处：
1. `DownloadItemImpl::ResumeInterruptedDownload` — offset=0 时清除 hash_state
2. `HandleSuccessfulServerResponse` — 收到 200 OK (非 206 Partial) 时重置 hash
3. `BaseFile::Open` — 文件截断到 0 时创建新的 SecureHash

**核心问题**: 状态机中多个组件之间的状态同步问题。下载系统是一个复杂状态机（进行中→中断→恢复→完成），hash 状态需要与文件内容保持同步，但在恢复路径中遗漏了重置。

**搜索策略**:
```bash
# 搜索下载系统中的状态重置逻辑
grep -rn "set_offset\|set_hash_state\|hash_state\|secure_hash\|bytes_so_far" \
  components/download/ --include="*.cc"
# 搜索其他状态机中可能遗漏的重置
grep -rn "Resume.*Download\|ResumeInterrupted\|HandleSuccessful" \
  components/download/ --include="*.cc"
```

---

## 优先审计计划

### 第一步: Mojo 接口权限一致性审计（模式 2）

这是最容易系统化检查的模式，也是 2026 年产出最密集的。

目标接口:
1. `ClipboardHostImpl` — 还有其他新方法没检查吗？
2. `FileSystemAccessManagerImpl` — File System Access API
3. `WebBluetoothServiceImpl` — Web Bluetooth
4. `WebUSBServiceImpl` — WebUSB
5. `HidServiceImpl` — WebHID
6. `SerialServiceImpl` — Web Serial

### 第二步: DCHECK 安全检查审计（模式 1） — 已完成

在 Chromium 源码中搜索 `DCHECK.*IsSavingAndFillingEnabled` 等模式。

**结果: Finding 001** — 3 个残留 DCHECK-only 安全检查:
- `credential_manager_impl.cc:325` — TOCTOU + 可保存凭据 (Medium-High)
- `password_manager.cc:698` — 清除生成标记 (Low)
- `password_manager.cc:714` — 标记生成字段 (Low-Medium)

VRP 报告已写: `vrp_report_dcheck_password_incomplete_fix.md`

其他 DCHECK 审计结果:
- `navigation_request.cc` — 大量 DCHECK→CHECK TODO, 但开发者已跟踪 (crbug/497761255)
- `fenced_frame_reporter.cc:903` — HTTPS scheme DCHECK, 攻击面有限

### 第三步: Mojo 接口权限一致性审计（模式 2） — 已完成

审计了 15+ Mojo HostImpl 实现:

| 接口 | 状态 | 说明 |
|------|------|------|
| ClipboardHostImpl | 低优先级 | ReadAvailableTypes/IsFormatAvailable 缺检查, 但只返回元数据 |
| BlinkNotificationServiceImpl | 安全 | 每个方法都重新检查 CheckPermissionStatus() |
| WebUSBServiceImpl | 安全 | 一致的 HasDevicePermission 检查 |
| HidServiceImpl | 安全 | 一致的 HasDevicePermission 检查 |
| IdleManagerImpl | 安全 | SetIdleOverride/ClearIdleOverride 是 DevTools 内部接口 |
| BackgroundFetchContext | 安全 | 有 GetPermissionForOrigin |
| PushMessagingManager | 安全 | 有权限检查 |
| SerialServiceImpl | 安全 | 构造函数 DCHECK + 独立方法权限检查 |
| DigitalIdentityRequestImpl | 安全 | Feature flag + fenced frame + permissions policy + visibility |
| SharedStorageDocumentServiceImpl | 安全 | opaque origin + secure context + IsSharedStorageAllowed |
| AdAuctionServiceImpl | **发现漏洞** | DeprecatedReplaceInURN/GetURLFromURN 缺少 run-ad-auction Permission Policy 检查。Finding 004。 |
| ContactsManagerImpl | 安全 | 主框架限制 |
| KeyboardLockServiceImpl | 安全 | 活跃/父框架检查 |

### 第四步: 深度 Mojo 权限一致性审计（模式 2，二次扫描） — 进行中

第二轮审计聚焦于更多接口的逐方法检查:

| 接口 | 状态 | 说明 |
|------|------|------|
| **AdAuctionServiceImpl** | **发现漏洞** | DeprecatedReplaceInURN/GetURLFromURN 缺 run-ad-auction PP 检查。VRP 报告已写。 |
| FileSystemAccessManagerImpl | 安全 | BindReceiver 有 origin 检查，所有方法一致 |
| PermissionServiceImpl | 安全 | 每个方法都 ValidatePermissionDescriptor |
| BlobRegistryImpl | 低风险 | RegisterFromStream 无 Delegate 检查，但只接收 inline data |
| MidiHost | 无当前风险 | 非 SysEx 检查被 kBlockMidiByDefault 保护，但该 flag 默认启用 |

### 第五步: Service Worker Static Router 安全审计 — 已完成

发现 3 个安全修复被 feature flag 默认关闭（Finding 003）:
- kServiceWorkerStaticRouterCORPCheck — CORP 检查用错误 URL
- kServiceWorkerStaticRouterOpaqueCheck — opaque response 未阻止
- kRestrictSharedWorkerWebSocketCrossSiteCookies — WebSocket cookie 泄露

但这些都是 Chromium 团队已知并在逐步启用的修复。VRP 价值低。

### 第六步: Android Intent 验证审计（模式 3）

搜索 `chrome/android/` 中从 intent extra 读取数据但未验证来源的代码。（待执行）
