# 基于 CVE 模式匹配的新漏洞发现汇总

> 分析日期: 2026-04-30
> 基于 19_cve_deep_analysis.md 中 6 个 CVE 的攻击模式

---

## 模式 1: Binder 权限检查缺失（类比 CVE-2025-22431）

### 发现 1.1: MediaSessionService 全面审计（V-201 + V-202 系列）

**已在设备上验证的零权限漏洞:**

| 事务码 | 方法 | 影响 | 验证状态 |
|--------|------|------|----------|
| 5 | dispatchMediaKeyEvent | BAL绕过（启动语音助手） | ✅ 已验证 |
| 5 | dispatchMediaKeyEvent (asSystem=true) | 系统身份伪装 | ✅ 已验证 |
| 6 | dispatchMediaKeyEventToSessionAsSystemService | 无权限以系统身份向session发事件 | ✅ 代码确认 |
| 7 | dispatchVolumeKeyEvent | 无权限+asSystem可控 | ✅ 代码确认 |
| 8 | dispatchVolumeKeyEventToSessionAsSystemService | 无权限以系统身份发音量事件 | ✅ 代码确认 |
| 9 | dispatchAdjustVolume | 零权限静音设备 | ✅ 已验证（11→0） |
| 25 | setCustomMediaKeyDispatcher | 任意类实例化（V-201） | ✅ 已验证 |
| 26 | setCustomMediaSessionPolicyProvider | 同V-201 | ✅ 代码确认 |

**核心发现:** MediaSessionService 中至少 8 个 Binder 方法缺失权限检查。

### 发现 1.2: AudioService 零权限方法

| 事务码 | 方法 | 权限检查 | 影响 |
|--------|------|----------|------|
| 22 | handleVolumeKey | 无 | 注入音量键事件（但可能被HardeningEnforcer阻止） |
| 199 | setNavigationRepeatSoundEffectsEnabled | 无 | 静默禁用导航音效 |
| 201 | setHomeSoundEffectEnabled | 无 | 静默禁用Home键音效 |

**注:** AudioService 的 handleVolumeKey 调用成功但实际音量未变（HardeningEnforcer 下游拦截）。sound effect 方法确认无任何权限检查。

### 发现 1.3: VoiceInteractionManagerService 缺失调用者验证

- `showSessionFromSession` / `hideSessionFromSession` 没有 `enforceIsCurrentVoiceInteractionService()` 调用
- 对比 `showSession` 方法正确调用了该检查
- 影响: 可能的会话劫持和 Intent 注入

### 发现 1.4: StatusBarManagerService 非对称权限

- `disable2ForUser` 缺少 `enforceValidCallingUser()`（但 `disableForUser` 有）
- 跨用户攻击面（但需要 signature-level STATUS_BAR 权限）

---

## 模式 2: 速率限制缺失（类比 CVE-2024-34737）

### 发现 2.1: setRequestedOrientation 无速率限制

- **位置:** ActivityClientController.java:957
- **权限:** 无（仅需 activity token）
- **影响:** 快速循环屏幕方向强制 display rotation 重计算、所有窗口 re-layout、UI 抖动
- **严重性:** HIGH — 架构上等同于 CVE-2024-34737

### 发现 2.2: setPictureInPictureParams 速率限制绕过

- **位置:** ActivityClientController.java:1157
- **CVE-2024-34737 修复不完整:** 仅限速了宽高比修改
- **绕过:** 修改 PiP actions/title/subtitle 不受任何限速
- **影响:** IPC 风暴到 SystemUI，task info 无限分发

### 发现 2.3: setTaskDescription 无速率限制

- **位置:** ActivityClientController.java:1449
- **权限:** 无（仅需 activity token）
- **影响:** 每次调用可能写磁盘（icon save），IPC 洪泛，内存压力

### 发现 2.4: convertFromTranslucent/convertToTranslucent 无速率限制

- **位置:** ActivityClientController.java:1002/1045
- **影响:** 每次调用创建 Shell transition，修改窗口遮挡状态

### 发现 2.5: setWallpaperComponent 无速率限制

- **位置:** WallpaperManagerService.java:2874
- **权限:** SET_WALLPAPER（normal，自动授予）
- **影响:** 强制壁纸服务 unbind/rebind、引擎重建、全屏重绘

---

## 模式 3: 输入大小无限制 + 持久化（类比 CVE-2024-49740）

### 发现 3.1: DevicePolicyManager.setApplicationRestrictions 无 Bundle 大小验证

- **位置:** DevicePolicyManagerService.java:9311
- **权限:** Device Owner / Profile Owner / 委托的 app-restrictions 管理器
- **持久化:** 写入 `/data/system/users/<userId>/res_<package>.xml`
- **影响:** 委托者可以写入无限大 Bundle（每次 Binder 限制 ~1MB，但可对不同包名重复调用）

### 发现 3.2: AccountManager password 1MB 限制

- **位置:** AccountManagerService.java:1559
- **单 account 密码限 1M 字符，最多 100 accounts = 100MB**
- **需要:** authenticator 身份（较高门槛）

---

## 模式 4: 字符串路径绕过（类比 CVE-2024-43093）

### 发现 4.1: PackageInstallerSession.getRelativePath 未 canonicalize

- **位置:** PackageInstallerSession.java:3444-3453
- **检查:** `getAbsolutePath().contains("/.")` + `startsWith(base)`
- **问题:** 不检查 symlinks，不 canonicalize
- **影响:** 如果能在 staging 目录植入 symlink，可能逃逸安装目录

### 发现 4.2: StorageManagerService.fixupAppDir 未 canonicalize

- **位置:** StorageManagerService.java:2688-2714
- **检查:** 正则匹配 raw input string
- **对比:** 同类中的 `mkdirs()` 正确使用了 `getCanonicalFile()`
- **影响:** 目录权限变更可能被重定向

### 发现 4.3: FullRestoreEngine.isCanonicalFilePath 伪规范化检查

- **位置:** FullRestoreEngine.java:270-272
- **检查:** 仅 `str.contains("..")` 和 `str.contains("//")`
- **问题:** 不检查 URL 编码、Unicode 变体、null bytes
- **影响:** 恶意 backup archive 可能实现任意路径文件写入（以 system 身份）

---

## 优先级排序

| 优先级 | 发现 | 验证难度 | 报告价值 |
|--------|------|----------|----------|
| P0 | V-202 MediaSession 全面审计（已验证） | ✅ 完成 | HIGH |
| P1 | V-204 setRequestedOrientation DoS（已验证） | ✅ 完成 | HIGH |
| P2 | NotificationChannel 5000×3KB 持久化 | ✅ 已验证: 15.6MB | MEDIUM |
| P3 | ShortcutService PersistableBundle 无大小限制 | ✅ 已验证: 7.5MB (binder限制500KB/条) | MEDIUM |
| P4 | VoiceInteractionManager showSessionFromSession 缺权限检查 | ✅ 已验证: 零权限触发Assistant | MEDIUM |
| P5 | FullRestoreEngine 路径绕过 | ❌ 主方法反编译失败，需adb restore前提 | LOW (unreachable) |
| P6 | StorageManagerService.fixupAppDir | ✅ 已验证: 零权限调用成功，但vold阻止path traversal | LOW-MEDIUM |
| P7 | AudioService 音效设置（已验证） | ✅ 完成 | LOW-MEDIUM |

---

## 已提交 / 待提交

- ✅ V-201: setCustomMediaKeyDispatcher 任意类实例化 — **已提交**
- ✅ V-202: dispatchMediaKeyEvent BAL + 音量 + 身份伪装 — **报告已生成，待提交**
- ✅ V-203: AudioService 零权限方法 — **已验证: setNavigationRepeatSoundEffectsEnabled + setHomeSoundEffectEnabled 从 untrusted_app 调用成功，状态变更已确认**
- ✅ V-204: setRequestedOrientation DoS — **已验证: system_server 40-50% CPU, 设备 UI 不可用, 报告已生成**
- ✅ V-205: NotificationChannel 存储放大 — **已验证: 5000通道×3KB = 15.6MB notification_policy.xml，零权限，27.5秒完成**
- ✅ V-206: ShortcutService PersistableBundle 持久化 — **已验证: 15 shortcuts × 500KB extras = 7.5MB shortcuts.xml，零权限，78ms完成**
- ✅ V-207: VoiceInteractionManager showSessionFromSession — **已验证: 零权限从 untrusted_app 触发 Google Assistant UI (FloatyActivity)，无 enforceIsCurrentVoiceInteractionService() 检查**
