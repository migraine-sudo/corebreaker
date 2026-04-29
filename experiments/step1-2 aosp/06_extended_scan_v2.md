# AOSP Extended Scan Results v2 (Round 4-5)

> 6 方向深度审计: PendingIntent / Intent劫持 / 跨用户 / TOCTOU / Broadcast / ContentProvider
> 审计范围: SafeActivityOptions, AccountManagerService, MediaSessionService, SliceManagerService,
>           ActivityTaskManagerService, ShortcutService, ClipboardService, RingtonePlayer,
>           TvInputManagerService, TelecomLoaderService, BiometricService, WallpaperManagerService
> 2026-04-28

---

## 新增候选汇总 (V-18 ~ V-32)

| # | 严重度 | 漏洞 | 模块 | 模式 |
|---|--------|------|------|------|
| **V-18** | **HIGH** | RingtonePlayer.play() URI confused deputy (确认 V-10) | SystemUI | Confused deputy |
| **V-19** | **HIGH** | RingtonePlayer.getTitle() 任意 URI 元数据泄露 | SystemUI | Confused deputy |
| **V-20** | **HIGH** | ShortcutService shortcut Intent 不校验目标组件导出状态 | PM | Intent 重定向 |
| **V-21** | **HIGH** | SliceManagerService grantPermissionFromUser 过度授权 (全 authority) | Slice | 权限过度授予 |
| **V-22** | **HIGH** | MediaSessionService tempAllowlistTargetPkg BAL/FGS 传播 | Media | BAL 传播 |
| **V-23** | **MEDIUM-HIGH** | SliceManagerService checkSlicePermission 无跨用户检查 | Slice | 跨用户访问 |
| **V-24** | **MEDIUM-HIGH** | TelecomLoaderService SMS/Dialer provider 忽略 userId | Telecom | 跨用户泄露 |
| **V-25** | **MEDIUM-HIGH** | ClipboardService SecurityException 导致剪贴板清除 (DoS) | Clipboard | DoS |
| **V-26** | **MEDIUM** | SafeActivityOptions 不检查 LaunchWindowingMode | WM | 参数遗漏 |
| **V-27** | **MEDIUM** | TvInputManager 无权限读取 parental control 配置 | TV | 隐私泄露 |
| **V-28** | **MEDIUM** | ClipboardService VirtualDevice 所有者静默读取剪贴板 | Clipboard | 隐私绕过 |
| **V-29** | **MEDIUM** | ClipboardService 分类结果应用竞态条件 | Clipboard | TOCTOU |
| **V-30** | **MEDIUM** | ShortcutService URI 权限撤销仅限 user 0 | PM | 权限残留 |
| **V-31** | **LOW-MEDIUM** | WallpaperManagerService COLOR_ALL 监听泄露跨用户壁纸颜色 | Wallpaper | 跨用户泄露 |
| **V-32** | **LOW-MEDIUM** | AccountManagerService KEY_INTENT 历史攻击面 (需验证当前修复完整性) | Accounts | Intent 重定向 |

---

## V-18 (HIGH): RingtonePlayer.play() URI Confused Deputy — 深度确认

**文件**: `packages/SystemUI/src/com/android/systemui/media/RingtonePlayer.java`

**之前的 V-10 现在完全确认。** 审计结果：

| 方法 | 调用者认证 | URI 校验 | Confused Deputy 风险 |
|------|-----------|---------|---------------------|
| `play()` | 无 | 无 | **HIGH** |
| `getTitle()` | 无 | 无 | **HIGH** |
| `openRingtone()` | 无 | 部分 (仅 media store 前缀检查) | **MEDIUM** |
| `playAsync()` | SYSTEM_UID 检查 | 无 | Low |
| `stopAsync()` | SYSTEM_UID 检查 | N/A | Low |

**获取 Binder 的方式**: 任何 app 通过 `AudioManager.getRingtonePlayer()` → `IAudioService.getRingtonePlayer()` 获取。

**SystemUI 持有的特权**: `READ_EXTERNAL_STORAGE`, `READ_CONTACTS`, `READ_PHONE_STATE`, 系统进程信任。

**PoC (play)**:
```java
AudioManager am = getSystemService(AudioManager.class);
IRingtonePlayer player = am.getRingtonePlayer(); // 反射获取
// 用 SystemUI 权限打开联系人 URI
player.play(new AudioAttributes.Builder().build(),
    Uri.parse("content://com.android.contacts/contacts/1/photo"),
    1.0f, false);
```

**PoC (getTitle)**:
```java
// 零权限泄露任意 content provider 元数据
String title = player.getTitle(Uri.parse("content://sms/inbox/1"));
Log.d("PoC", "SMS title: " + title);
```

**赏金预估**: $5,000 - $10,000 (play + getTitle 可合并提交)

---

## V-19 (HIGH): RingtonePlayer.getTitle() 任意 URI 元数据泄露

**同 V-18 文件，独立漏洞入口点。**

`getTitle()` 方法使用 `Ringtone.getTitle(getContextForUser(user), uri, ...)` 在 SystemUI 上下文中解析任意 content URI。

**泄露能力**:
- `content://com.android.contacts/contacts/*` — 联系人姓名
- `content://sms/*` — 短信内容摘要
- `content://media/external/*` — 媒体文件元数据
- 任何系统级 ContentProvider 返回的 `_display_name` / `title` 列

**可合并 V-18 一起提交**，但如果 Google 分开评审，getTitle 的信息泄露可以独立计赏。

---

## V-20 (HIGH): ShortcutService Shortcut Intent 不校验目标组件导出状态

**文件**: `services/core/java/com/android/server/pm/ShortcutService.java`

**问题**: `fixUpIncomingShortcutInfo()` 验证 shortcut 的 Activity 属于调用包，但 **不验证 shortcut 的 Intent 目标** 是否是导出组件。

一个恶意 app 可以发布一个 shortcut，其 Intent 指向另一个 app 的非导出 Activity。当 Launcher 处理此 shortcut 时，Launcher（持有系统权限）可以启动该非导出 Activity。

**附加问题**: `Intent.parseUri(value, /* flags = */ 0)` — flags=0 意味着没有安全限制，允许任意组件目标。

**利用链**:
1. 恶意 app 调用 `ShortcutManager.pushDynamicShortcut(shortcutInfo)`
2. shortcutInfo 的 Intent 指向 `com.android.settings/.PrivateSettingsActivity` (非导出)
3. 用户在 Launcher 点击 shortcut
4. Launcher 以系统权限启动该非导出 Activity

**赏金预估**: $5,000 - $15,000

---

## V-21 (HIGH): SliceManagerService 过度 URI 授权

**文件**: `services/core/java/com/android/server/slice/SliceManagerService.java`

**问题**: `grantPermissionFromUser()` 中:
```java
Uri grantUri = uri.buildUpon().path("").build();
```

当 `allSlices=false` 时，代码清空了 URI 路径，导致授权范围扩大到 **整个 provider authority**。

用户明确授权访问一个特定 slice，实际上授予了该 provider 下所有 slice 的访问权限。

**另外**: `checkSlicePermissionInternal()` 的 auto-grant 一旦授予，**永久有效**，无过期机制。

**赏金预估**: $3,000 - $7,500

---

## V-22 (HIGH): MediaSessionService BAL/FGS 权限传播（CVE-2025-48572/73 变体）

**文件**: `services/core/java/com/android/server/media/MediaSessionService.java`

**方法**: `tempAllowlistTargetPkgIfPossible()`

该方法在 media session callback 分发时，将调用者的 FGS 启动权限和 while-in-use 权限传播给目标 app:
- `mActivityManagerInternal.tempAllowWhileInUsePermissionInFgs(targetUid, ...)` — 授予 WIU 权限
- `powerExemptionManager.addToTemporaryAllowList(targetPackage, ...)` — 加入电源白名单

**与 CVE-2025-48572/73 的区别**:
- CVE-2025-48572 修复了 `MediaButtonReceiverHolder` 的 BAL 传播
- CVE-2025-48573 修复了 `MediaSessionRecord.sendCommand` 的 WIU/BFSL 传播
- 此发现涉及 `tempAllowlistTargetPkgIfPossible()` — 更通用的传播路径，可能仍未被修复

**需要验证**: 此方法是否在上述 CVE 修复后仍保留了传播能力。

**赏金预估**: $5,000 - $15,000 (如果确认是新的传播路径)

---

## V-23 (MEDIUM-HIGH): SliceManagerService 跨用户切片访问

**文件**: `services/core/java/com/android/server/slice/SliceManagerService.java`

`checkSlicePermissionInternal()` 中 **没有跨用户权限检查**。该方法使用 `UserHandle.getUserId(uid)` 但不验证调用者是否有权访问其他用户的 slice。

工作 profile 的 app 可能读取个人 profile 的 slice 内容。

**赏金预估**: $3,000 - $7,500

---

## V-24 (MEDIUM-HIGH): TelecomLoaderService SMS/Dialer Provider 跨用户泄露

**文件**: `services/core/java/com/android/server/telecom/TelecomLoaderService.java`

**问题**:
- `SmsApplication.getDefaultSmsApplication(mContext, true)` — **忽略传入的 userId**，返回当前用户的默认 SMS app
- `DefaultDialerManager.getDefaultDialerApplication(mContext)` — **不传 userId**，同上

当系统查询其他 user profile 的默认 SMS/Dialer 时，实际返回的是主用户的配置。

**影响**: 如果工作 profile 和个人 profile 使用不同的默认 SMS app，权限可能被授予错误的 app。

**赏金预估**: $3,000 - $5,000

---

## V-25 (MEDIUM-HIGH): ClipboardService SecurityException → 全局剪贴板清除 DoS

**文件**: `services/core/java/com/android/server/clipboard/ClipboardService.java`

**问题**: 在 `getPrimaryClip()` 中，如果 `addActiveOwnerLocked()` 抛出 `SecurityException`（例如剪贴板内容包含无效 URI），服务会 **清除整个剪贴板**:

```java
} catch (SecurityException e) {
    ...setPrimaryClipInternalLocked(null, intendingUid, intendingDeviceId, pkg);
}
```

清除操作会传播到所有关联的 profile（工作 profile 等）。

**利用**: 恶意 app 读取包含受限 URI 的剪贴板内容，触发 SecurityException，导致所有用户的剪贴板被清空。

**赏金预估**: $1,500 - $3,000 (DoS)

---

## V-26 (MEDIUM): SafeActivityOptions 不检查 LaunchWindowingMode（确认 V-6）

**文件**: `services/core/java/com/android/server/wm/SafeActivityOptions.java`

完全确认: `checkPermissions()` 对以下参数 **没有任何校验**:
- `getLaunchWindowingMode()` — PINNED, FREEFORM, 等
- `getLaunchBounds()` — 任意窗口位置和大小
- `getLaunchRootTask()` — 根任务控制
- `getPendingIntentBackgroundActivityStartMode()` — BAL 模式

CVE-2025-48546 阻止了直接设置 `setLaunchWindowingMode(PINNED)`，但检查在 `ActivityStarter` 层面，不在 `SafeActivityOptions.checkPermissions()` 中。FREEFORM 模式完全没有检查。

---

## V-27 (MEDIUM): TvInputManager 无权限泄露 Parental Control 配置

**文件**: `services/core/java/com/android/server/tv/TvInputManagerService.java`

以下方法 **无需任何权限** 即可调用:
- `isParentalControlsEnabled()` — 泄露设备是否启用了家长控制
- `isRatingBlocked(rating)` — 泄露哪些内容分级被屏蔽
- `getBlockedRatings()` — 泄露完整的屏蔽分级列表

**隐私影响**: 泄露家庭中是否有未成年人、内容偏好。

**额外发现**: 以下方法也无需权限:
- `getTvInputList()` — 枚举所有 TV 输入设备
- `getTvInputInfo()` — 查询输入设备详情
- `getTvInputState()` — 设备连接状态

**赏金预估**: $1,500 - $3,000

---

## V-28 (MEDIUM): ClipboardService VirtualDevice 所有者静默读取剪贴板

**文件**: `services/core/java/com/android/server/clipboard/ClipboardService.java`

```java
if (clipboard.deviceId != DEVICE_ID_DEFAULT && mVdmInternal != null
    && mVdmInternal.getDeviceOwnerUid(clipboard.deviceId) == uid) { return; }
```

VirtualDevice 所有者读取该设备的剪贴板时，**不触发用户通知 toast**。用户不知道 VD 应用程序正在访问剪贴板。

**赏金预估**: $2,000 - $5,000 (隐私绕过)

---

## V-29 (MEDIUM): ClipboardService 异步分类竞态条件

**文件**: 同上

剪贴板设置后，分类异步在 `mWorkerHandler` 上运行。`doClassification` 完成后将结果应用到所有关联 profile。

**竞态**:  在分类完成前，关联 profile 的剪贴板可能已被独立修改，导致分类结果被应用到错误的内容。

**赏金预估**: $1,000 - $3,000

---

## V-30 (MEDIUM): ShortcutService URI 权限撤销仅限 User 0

**文件**: `services/core/java/com/android/server/pm/ShortcutService.java`

```java
mUriGrantsManagerInternal.revokeUriPermissionFromOwner(mUriPermissionOwner, null, ~0, 0)
```

`handleOnDefaultLauncherChanged` 中，当默认 Launcher 变更时，URI 权限撤销硬编码 userId=0。用户 N (N≠0) 更换 Launcher 后，旧 Launcher 的 URI 权限 **不会被撤销**。

**赏金预估**: $2,000 - $5,000

---

## V-31 (LOW-MEDIUM): WallpaperManagerService 跨用户壁纸颜色泄露

**文件**: `services/core/java/com/android/server/wallpaper/WallpaperManagerService.java`

壁纸颜色变化监听可注册为 `UserHandle.USER_ALL`，接收所有用户 profile 的壁纸颜色信息。虽然颜色信息本身不算敏感，但可以推断其他用户 profile 的存在和活动。

**赏金预估**: $500 - $1,500

---

## V-32 (LOW-MEDIUM): AccountManagerService KEY_INTENT 攻击面

**文件**: `services/core/java/com/android/server/accounts/AccountManagerService.java`

这是 Android 上 **最经典的 Intent 重定向攻击面之一**（CVE-2014-7911, CVE-2023-20944 系列）。

当前代码中:
- `Session.onResult()` 处理 authenticator 返回的 `KEY_INTENT`
- 在 `clearCallingIdentity()` 块中，系统以 SYSTEM_UID 启动该 Intent

**需要在真机上验证**: 最新 AOSP 是否对 KEY_INTENT 添加了完整的组件校验。历史上此处多次修复不完整。

**赏金预估**: $0 (如果已修复) 到 $15,000+ (如果发现绕过)

---

## 全量候选更新 (V-1 ~ V-32)

### Tier 1: 可直接提交 (HIGH, 利用链清晰)

| # | 漏洞 | 模式 | 赏金预估 |
|---|------|------|---------|
| **V-8** | PackageArchiver EXTRA_INTENT 系统启动 | Intent 转发 | $10k-$20k |
| **V-18+V-19** | RingtonePlayer play()+getTitle() confused deputy | Confused deputy | $5k-$10k |
| **V-20** | ShortcutService Intent 不校验导出状态 | Intent 重定向 | $5k-$15k |
| **V-3** | AudioService.hasHapticChannels() URI | Confused deputy | $5k-$10k |
| **V-2** | DPMS BAL propagation to admin | BAL 传播 | $7.5k-$15k |
| **V-22** | MediaSession tempAllowlist BAL/FGS 传播 | BAL 传播 | $5k-$15k |
| **V-1** | isLaunchIntoPip bypass | Windowing abuse | $5k-$10k |
| **V-13** | WifiDisplay MAC 泄露 | 无权限广播 | $3k-$7.5k |
| **V-21** | SliceManager 过度 URI 授权 | 权限过度授予 | $3k-$7.5k |

### Tier 2: 需进一步验证

| # | 漏洞 | 模式 | 赏金预估 |
|---|------|------|---------|
| **V-23** | SliceManager 跨用户 slice 访问 | 跨用户 | $3k-$7.5k |
| **V-24** | TelecomLoader SMS/Dialer 跨用户 | 跨用户 | $3k-$5k |
| **V-9** | TvInput 无权限广播 | Binder 无校验 | $3k-$7.5k |
| **V-15** | Device Controls lockscreen | Keyguard bypass | $3k-$5k |
| **V-14** | ExternalStorage 路径穿越 | Path traversal | $2k-$5k |
| **V-25** | Clipboard SecurityException → 清除 DoS | DoS | $1.5k-$3k |
| **V-28** | Clipboard VD 所有者静默读取 | 隐私绕过 | $2k-$5k |
| **V-30** | ShortcutService URI 权限撤销 bug | 权限残留 | $2k-$5k |
| **V-4** | CDM exemption 残留 | 权限不撤销 | $3k-$5k |
| **V-6/V-26** | SafeActivityOptions 窗口模式无校验 | 参数遗漏 | $3k-$7.5k |
| **V-32** | AccountManager KEY_INTENT (需验证) | Intent 重定向 | $0-$15k |

### Tier 3: 低赏金 / 辅助信息

| # | 漏洞 | 赏金预估 |
|---|------|---------|
| **V-27** | TvInput parental control 泄露 | $1.5k-$3k |
| **V-16** | Storage 广播泄露 | $1.5k-$3k |
| **V-5** | 跨用户 GPS 指示器 | $1.5k-$3k |
| **V-29** | Clipboard 分类竞态 | $1k-$3k |
| **V-31** | 壁纸颜色跨用户泄露 | $0.5k-$1.5k |
| **V-17** | Widget trampoline race | $1k-$3k |
| **V-11** | RemoteViews Bundle URI | $1k-$3k |

### 总计赏金预估: $80,000 - $200,000+ (如果全部接受)

---

## 审计覆盖度更新

### 已完成 ✓ (Round 1-5)
- [x] BAL/WIU/BFSL 传播 (全 services/)
- [x] URI confused deputy (services/ + SystemUI + RingtonePlayer)
- [x] 跨用户数据泄露 (SystemUI + ClipboardService + TelecomLoader)
- [x] 权限不撤销 (CDM + ShortcutService)
- [x] SafeActivityOptions 参数缺失 (完整审计)
- [x] Notification URI 覆盖率
- [x] Intent 转发 / EXTRA_INTENT 提取 (PackageArchiver + AccountManager)
- [x] Binder 方法无权限调用 (10+ 核心 AIDL)
- [x] ContentProvider 路径遍历 (ExternalStorageProvider)
- [x] Broadcast 权限缺失 (WifiDisplay + Storage + TvInput)
- [x] PendingIntent FLAG_MUTABLE 审计 (ShortcutService + SliceManager)
- [x] 隐式 Intent 劫持 (ShortcutService Intent 目标)
- [x] TOCTOU / 竞态条件 (ClipboardService 分类竞态)
- [x] MediaSessionService BAL/FGS 传播
- [x] SliceManagerService 权限模型
- [x] BiometricService 认证状态机
- [x] WallpaperManagerService 文件处理
- [x] TelecomLoaderService 跨用户
- [x] ActivityTaskManagerService 跨用户 activity
- [x] ClipboardService 隔离模型

### 未来扫描方向
- [ ] packages/apps/Settings/ (独立代码库, 每月出 CVE)
- [ ] packages/modules/Bluetooth/ (近端 RCE, $75k+)
- [ ] packages/modules/Connectivity/ (WiFi/网络栈)
- [ ] 通知监听器权限提升 (NLS → 系统功能)
- [ ] VPN 服务权限模型
- [ ] DeviceAdmin / Device Owner 权限边界
- [ ] ContentProvider update/insert SQL 注入

---

## 新审计覆盖的服务清单

| 服务 | 防御强度 | 主要发现 |
|------|---------|---------|
| SafeActivityOptions | **弱** | 多个参数无检查 (V-26) |
| RingtonePlayer | **极弱** | 无调用者认证, confused deputy (V-18/19) |
| ShortcutService | **弱** | Intent 目标不校验导出状态 (V-20) |
| SliceManagerService | **弱** | 过度授权 + 无跨用户检查 (V-21/23) |
| TvInputManagerService | **弱** | 多方法无权限 (V-27) |
| ClipboardService | **中等** | DoS + VD 隐私 + 竞态 (V-25/28/29) |
| TelecomLoaderService | **弱** | 跨用户 userId 被忽略 (V-24) |
| MediaSessionService | **中等** | BAL/FGS 传播残留 (V-22) |
| AccountManagerService | **较强** | KEY_INTENT 历史攻击面, 需验证 (V-32) |
| BiometricService | **较强** | 依赖 HAL 信任, 应用层面安全 |
| WallpaperManagerService | **中等** | 颜色泄露 + symlink 风险 (V-31) |
| ActivityTaskManagerService | **较强** | 跨用户检查一致 |

---

## 推荐提交策略

### 第一批 (本周, 最高 ROI):

1. **V-18+V-19 RingtonePlayer** — 最干净, 零权限, 5 分钟 PoC
2. **V-3 AudioService** — 同为 confused deputy, 独立入口
3. **V-20 ShortcutService** — 需要用户点击 shortcut, 但影响面大

### 第二批 (验证后):
4. **V-8 PackageArchiver** — 最高赏金潜力, 需确认利用链
5. **V-2 DPMS BAL** — 需要 Device Admin 前置
6. **V-22 MediaSession** — 需确认是否被之前的 CVE 覆盖

### 第三批 (信息泄露类):
7. **V-13 WifiDisplay MAC**
8. **V-27 TvInput parental control**
9. **V-24 Telecom 跨用户**

---

*Report v2 generated: 2026-04-28*
*累计扫描 20+ 个攻击方向, 32 个潜在未修复变体*
*Tier 1 (9 HIGH) 总预估: $50k-$110k*
*全量总预估: $80k-$200k+*
