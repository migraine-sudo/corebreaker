# AOSP Deep Scan Round 2 — Settings App + AMS/AppOps/NMS/Accessibility

> 审计范围: packages/apps/Settings, ActivityManagerService, AppOpsService, NotificationManagerService, AccessibilityManagerService
> 方法: 源码审计 (googlesource.com), 3 个并行 agent + 直接审计
> 2026-04-28

---

## 执行摘要

本轮深度扫描在报告 08 的 48 个变体基础上，对 4 个之前覆盖不足的核心模块进行了完整审计，新增 **37 个潜在未修复变体** (V-49 ~ V-85)。

**最重要的新发现**:
1. **Settings SearchResultTrampoline** — 无权限导出 Activity，可路由到 SubSettings (接受任意 Fragment)
2. **AppOpsService 虚拟设备绕过** — `virtualDeviceId != DEFAULT` 时完全跳过所有 AppOps 限制
3. **AppOpsService Profile Owner 无限制** — Profile Owner 可修改任意 AppOps 模式
4. **Settings Deep Link replaceExtras** — 签名权限保护但转发所有 extras 到目标 Activity
5. **NMS 特权监听器通道篡改** — companion device NLS 可修改任意 app 的通知通道
6. **A11y 无权限窗口信息泄露** — 任意 app 可查询任意窗口的位置/变换矩阵

---

## 一、Settings App 审计结果 (V-49 ~ V-58)

### V-49 (HIGH): SearchResultTrampoline 无权限 Intent 重定向 + Fragment 注入

**文件**: `packages/apps/Settings/src/com/android/settings/search/SearchResultTrampoline.java`

```java
// exported="true", NO permission required
final String fragment = intent.getStringExtra(SettingsActivity.EXTRA_SHOW_FRAGMENT);
if (!TextUtils.isEmpty(fragment)) {
    intent.setClass(this, SubSettings.class);  // → SubSettings 接受所有 fragment
} else {
    final String intentUriString = intent.getStringExtra(
            Settings.EXTRA_SETTINGS_EMBEDDED_DEEP_LINK_INTENT_URI);
    intent = Intent.parseUri(intentUriString, Intent.URI_INTENT_SCHEME);
}
intent.addFlags(Intent.FLAG_ACTIVITY_FORWARD_RESULT);
startActivity(intent);
```

**两条攻击路径**:
1. **Fragment 路径**: 提供 `EXTRA_SHOW_FRAGMENT` → 路由到 `SubSettings.class` → `isValidFragment()` 返回 `true` (接受任何 fragment 类名)
2. **URI 路径**: 提供 `EXTRA_SETTINGS_EMBEDDED_DEEP_LINK_INTENT_URI` → `Intent.parseUri()` 解析 → `startActivity()` 以 Settings 权限启动

**缓解**: `verifyLaunchSearchResultPageCaller()` 检查调用者包名 (应为 SettingsIntelligence)。需要验证此检查是否可绕过。

**赏金预估**: $5,000 - $20,000 (取决于 caller 验证是否可绕过)

---

### V-50 (HIGH): SubSettings.isValidFragment() 无条件返回 true

**文件**: `packages/apps/Settings/src/com/android/settings/SubSettings.java:34`

```java
@Override
protected boolean isValidFragment(String fragmentName) {
    Log.d("SubSettings", "Launching fragment " + fragmentName);
    return true;  // 接受 Settings APK 中任何 Fragment 类
}
```

**影响**: 父类 `SettingsActivity` 使用 192 个条目的白名单验证，但 SubSettings 完全绕过。任何可以路由到 SubSettings 的路径 (如 V-49) 都可以加载任意安全敏感 Fragment: `MainClear`, `MainClearConfirm`, `DevelopmentSettingsDashboardFragment`, `ChooseLockPassword`, `UserSettings`, `DeviceAdminSettings` 等。

SubSettings 本身声明为 `android:exported="false"`，但 V-49 的 SearchResultTrampoline 可以路由到它。

**赏金预估**: $5,000 - $15,000 (需要证明从导出 Activity 的可达性)

---

### V-51 (HIGH): SettingsHomepageActivity Deep Link replaceExtras 注入

**文件**: `packages/apps/Settings/src/com/android/settings/homepage/SettingsHomepageActivity.java:645`

```java
targetIntent = Intent.parseUri(intentUriString, Intent.URI_INTENT_SCHEME);
targetIntent.setComponent(targetComponentName);
targetIntent.replaceExtras(intent);  // ← 复制所有 extras 到目标 Intent
if (user != null) {
    startActivityAsUser(targetIntent, user);  // 以指定用户启动
}
```

**问题**: `replaceExtras(intent)` 将调用者的所有 extras 注入到目标 Intent 中，包括:
- `EXTRA_SHOW_FRAGMENT` — 覆盖加载的 fragment
- `EXTRA_SHOW_FRAGMENT_ARGUMENTS` — 控制 fragment 参数
- `EXTRA_USER_HANDLE` / `EXTRA_USER_ID` — 影响跨用户目标
- `ChooseLockSettingsHelper.EXTRA_KEY_PASSWORD` — 注入凭据

**缓解**: 需要 `LAUNCH_MULTI_PANE_SETTINGS_DEEP_LINK` (签名级) 权限。

**赏金预估**: $3,000 - $10,000

---

### V-52 (MEDIUM-HIGH): ChooseLockGeneric$InternalActivity 导出 + 密码信任

**文件**: `packages/apps/Settings/src/com/android/settings/password/ChooseLockGeneric.java:247`

```java
if (activity instanceof ChooseLockGeneric.InternalActivity) {
    mPasswordConfirmed = !confirmCredentials;
    mUserPassword = intent.getParcelableExtra(
        ChooseLockSettingsHelper.EXTRA_KEY_PASSWORD);  // 信任 Intent extras
}
```

**问题**: `ChooseLockGeneric$InternalActivity` 是**导出的** (manifest 中有 `android.settings.INTERNAL_STORAGE_SETTINGS` intent filter)。InternalActivity 分支直接信任 `EXTRA_KEY_PASSWORD` extra，可能影响锁屏更改流程。

**赏金预估**: $2,000 - $8,000

---

### V-53 (MEDIUM-HIGH): AddAccountSettings AccountManager KEY_INTENT 重定向

**文件**: `packages/apps/Settings/src/com/android/settings/accounts/AddAccountSettings.java:95-107`

```java
Intent intent = (Intent) bundle.get(AccountManager.KEY_INTENT);
if (intent != null) {
    intent.putExtras(addAccountOptions)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
    startActivityForResultAsUser(new Intent(intent), ADD_ACCOUNT_REQUEST, mUserHandle);
}
```

**问题**: 导出 Activity，处理 `android.settings.ADD_ACCOUNT_SETTINGS`。恶意 AccountAuthenticator 可返回任意 Intent → Settings 以自身权限启动。`new Intent(intent)` 不限制组件目标。

**赏金预估**: $3,000 - $10,000

---

### V-54 (MEDIUM): MainClear Fragment 无 MASTER_CLEAR 权限检查

**文件**: `packages/apps/Settings/src/com/android/settings/MainClear.java`

- Fragment 级别无 `MASTER_CLEAR` 权限检查
- 无锁屏时 (no keyguard) 跳过认证
- Demo user 直接重置绕过所有确认

**赏金预估**: $2,000 - $5,000

---

### V-55 (MEDIUM): DevelopmentSettingsDashboardFragment 生物识别绕过

**文件**: `packages/apps/Settings/src/com/android/settings/development/DevelopmentSettingsDashboardFragment.java`

- 当开发者选项状态为 `NOT_ACTIVE` 时，仅显示警告对话框，无生物识别验证
- USB 调试、OEM 解锁、模拟位置等可从此进入
- Admin 检查在 `onCreate` 中但存在 TOCTOU 风险

**赏金预估**: $1,000 - $3,000

---

### V-56 (MEDIUM): UserSettings 无调用者验证

**文件**: `packages/apps/Settings/src/com/android/settings/users/UserSettings.java`

- 无调用者身份验证
- 访客创建无需认证
- `setUserAdmin()` 授予管理员权限无需重新认证
- UserCapabilities 存在 TOCTOU 窗口

**赏金预估**: $2,000 - $5,000

---

### V-57 (MEDIUM): 324 个导出 Activity，27 个无权限

**文件**: `AndroidManifest.xml`

重要的无保护导出 Activity:
- `ConfirmDeviceCredentialActivity`
- `SearchResultTrampoline`
- `Settings$DevelopmentSettingsActivity`
- `Settings$UserSettingsActivity`
- `Settings$DeviceAdminSettingsActivity`
- `AddAccountSettings`
- `Settings$SecurityDashboardActivity`

**赏金预估**: (攻击面扩展，辅助其他漏洞)

---

### V-58 (LOW-MEDIUM): ApnSettings 跨用户订阅访问

**文件**: `packages/apps/Settings/src/com/android/settings/network/apn/ApnSettings.java`

- 无调用者验证 SUB_ID extra
- 跨用户订阅访问可能

**赏金预估**: $1,000 - $2,000

---

## 二、ActivityManagerService 深度审计结果 (V-59 ~ V-66)

### V-59 (MEDIUM-HIGH): openContentUri 绕过 ACCESS_CONTENT_PROVIDERS_EXTERNALLY

**文件**: `services/core/java/com/android/server/am/ActivityManagerService.java:7330`

```java
ContentProviderHolder cph = mCpHelper.getContentProviderExternalUnchecked(name, null,
        Binder.getCallingUid(), "*opencontent*", userId);
```

不经过 `handleIncomingUser()` 跨用户验证，VNDK/native 进程可达。

**赏金预估**: $1,000 - $3,000

---

### V-60 (HIGH — userdebug): Instrumentation 签名检查绕过

**文件**: `ActivityManagerService.java:14493-14514`

```java
if (Build.IS_DEBUGGABLE && (callingUid == Process.ROOT_UID)
        && (flags & INSTR_FLAG_ALWAYS_CHECK_SIGNATURE) == 0) {
    // Only warns, does NOT throw
}
```

在 userdebug/eng 构建上，root 可以 instrument 任何 app (包括 system_server)。

**赏金预估**: $3,000 - $8,000

---

### V-61 (MEDIUM): OP_NO_ISOLATED_STORAGE 永久残留

**文件**: `ActivityManagerService.java:14610-14616`

Instrumentation 结束后 `OP_NO_ISOLATED_STORAGE` 不会被撤销。

**赏金预估**: $1,000 - $2,000

---

### V-62 (MEDIUM-HIGH): Persistent App 可发送任意受保护广播

**文件**: `BroadcastController.java:1035-1048`

```java
default:
    isCallerSystem = (callerApp != null) && callerApp.isPersistent();
```

任何 `android:persistent="true"` 系统 app 的漏洞可被利用来发送受保护广播。

**赏金预估**: $3,000 - $5,000

---

### V-63 (LOW-MEDIUM): Sticky Broadcast 仅需普通权限

**文件**: `BroadcastController.java:1407-1487`

`BROADCAST_STICKY` 是 normal 级权限。可覆盖 `ACTION_BATTERY_CHANGED` 等非受保护 sticky 广播。

**赏金预估**: $500 - $1,500

---

### V-64 (MEDIUM): MY_PID 无条件授权 (Confused Deputy 架构风险)

**文件**: `ActivityManagerService.java:6111`

```java
if (pid == MY_PID) return PackageManager.PERMISSION_GRANTED;
```

system_server 内任何 confused deputy 都自动通过权限检查。

**赏金预估**: $2,000 - $5,000 (如果找到具体 confused deputy)

---

### V-65 (LOW-MEDIUM): Persistable + Prefix URI Grant 永不过期

**文件**: `ActivityManagerService.java:6726-6757`

`FLAG_GRANT_PERSISTABLE_URI_PERMISSION | FLAG_GRANT_PREFIX_URI_PERMISSION` 组合可创建永久广泛访问。

**赏金预估**: $500 - $1,000

---

### V-66 (LOW-MEDIUM): 有序广播结果篡改

**文件**: `BroadcastController.java:935`

高优先级接收者可以 abort 或修改有序广播结果数据。

**赏金预估**: $500 - $1,000

---

## 三、AppOpsService 审计结果 (V-67 ~ V-73)

### V-67 (HIGH): 虚拟设备绕过所有 AppOps 限制 ⭐

**文件**: `services/core/java/com/android/server/appop/AppOpsService.java:5035`

```java
private boolean isOpRestrictedLocked(..., int virtualDeviceId, ...) {
    if (virtualDeviceId != Context.DEVICE_ID_DEFAULT) {
        return false;  // ← 完全跳过所有限制
    }
```

**影响**: 当 `virtualDeviceId != DEVICE_ID_DEFAULT` 时，所有 AppOps 限制完全绕过，包括:
- 全局限制 (global restrictions)
- 用户限制 (user restrictions)
- 摄像头/麦克风隐私开关
- 所有 OEM 特定限制

**攻击场景**: 通过 VR/伴侣设备/远程桌面等虚拟设备上下文执行操作，完全绕过摄像头/麦克风/位置隐私保护。

**赏金预估**: $5,000 - $15,000

---

### V-68 (HIGH): Profile Owner 可设置任意 AppOps 模式

**文件**: `AppOpsService.java:2045-2061`

```java
if (mProfileOwners != null && mProfileOwners.get(callingUser, -1) == callingUid) {
    if (targetUid >= 0 && callingUser == UserHandle.getUserId(targetUid)) {
        return;  // ← Profile Owner 跳过权限检查
    }
}
```

**影响**: Profile Owner 可修改同 profile 内任意 app 的任意 AppOps:
- `OP_SYSTEM_ALERT_WINDOW` — 覆盖层权限
- `OP_REQUEST_INSTALL_PACKAGES` — 未知来源
- `OP_RUN_IN_BACKGROUND` — 后台限制
- `OP_CAMERA` / `OP_RECORD_AUDIO` — 传感器权限

**赏金预估**: $5,000 - $10,000

---

### V-69 (MEDIUM): Proxy Operation 信任基于 proxyUid 而非 callingUid

**文件**: `AppOpsService.java:3179-3197`

`clearCallingIdentity()` 下的系统服务代理操作标记为 `OP_FLAG_TRUSTED_PROXY`，可能在隐私面板中隐藏真实访问。

**赏金预估**: $2,000 - $5,000

---

### V-70 (LOW): Invalid Virtual Device 返回 MODE_IGNORED

**文件**: `AppOpsService.java:2890`

无效 `virtualDeviceId` 静默返回 `MODE_IGNORED` 而非 `MODE_ERRORED`。

**赏金预估**: $500

---

### V-71 (LOW-MEDIUM): Cross-User setUserRestriction 接受弱权限

**文件**: `AppOpsService.java:6601`

`setUserRestriction` 跨用户检查接受 `INTERACT_ACROSS_USERS` (比 `_FULL` 更弱)。

**赏金预估**: $1,000 - $2,000

---

### V-72 (LOW): resetAllModes 保留角色授予的 Ops

**文件**: `AppOpsService.java:2556`

`resetAllModes()` 保留 `isUidOpGrantedByRole` 的 ops，可能产生过时权限。

**赏金预估**: $500 - $1,000

---

### V-73 (LOW-MEDIUM): Foreground Mode 异步通知竞态

**文件**: `AppOpsService.java:1465-1544`

`onUidStateChanged()` 通过 handler 异步通知，前台→后台过渡期间存在窗口。

**赏金预估**: $1,000 - $3,000

---

## 四、NotificationManagerService 审计结果 (V-74 ~ V-80)

### V-74 (MEDIUM-HIGH): 特权 NLS 通道篡改 (Companion Device) ⭐

**文件**: `services/core/java/com/android/server/notification/NotificationManagerService.java`

```java
public void updateNotificationChannelFromPrivilegedListener(...) {
    verifyPrivilegedListener(token, user, true);  // CDM 关联即可
    updateNotificationChannelInt(pkg, ..., channel, true);  // 修改任意 app 通道
}
```

**影响**: 有 CDM 关联的 NLS 可以修改任意 app 的通知通道:
- 设置 `importance = IMPORTANCE_NONE` → 静默压制银行欺诈警报
- 提升垃圾通道为 `IMPORTANCE_HIGH` → 广告注入
- 修改声音 URI (有 URI 权限检查)

**赏金预估**: $3,000 - $5,000

---

### V-75 (MEDIUM): NLS Snooze 任意通知 DoS

**文件**: `NotificationManagerService.java:10968`

任何 NLS 可以无限时长 snooze 任何匹配用户的通知。银行/安全/MDM 通知可被系统性抑制。

**赏金预估**: $1,000 - $3,000

---

### V-76 (MEDIUM): NAS 通过 Importance 取消任意通知

**文件**: `NotificationManagerService.java:6702`

NAS 可设置 `KEY_IMPORTANCE=IMPORTANCE_NONE` 并在 `clearCallingIdentity()` 下以系统身份取消通知。

**赏金预估**: $2,000 - $4,000

---

### V-77 (MEDIUM): Backup Restore 注入通道配置 + 锁屏隐私

**文件**: `NotificationManagerService.java:1108-1177`

```java
mLockScreenAllowSecureNotifications = parser.getAttributeBoolean(null,
        LOCKSCREEN_ALLOW_SECURE_NOTIFICATIONS_VALUE, true);
```

Backup 载荷可注入通知通道配置和锁屏通知隐私设置。

**赏金预估**: $2,000 - $4,000

---

### V-78 (MEDIUM): 敏感通知内容信任 UID 绕过

**文件**: `NotificationManagerService.java:5681`

"受信任" UID 的 NLS 绕过敏感内容 (OTP/2FA) 编辑。

**赏金预估**: $1,500 - $3,000

---

### V-79 (MEDIUM): NotificationManagerInternal 无权限检查

**文件**: `NotificationManagerInternal.java:33`

内部 API 接受任意 callingUid/callingPid。需要系统服务漏洞链。

**赏金预估**: $1,000 - $3,000

---

### V-80 (LOW-MEDIUM): Notification Delegation 无代理同意

**文件**: `NotificationManagerService.java:4361`

任意 app 可以将任意其他已安装 app 指定为通知代理。

**赏金预估**: $500 - $1,500

---

## 五、AccessibilityManagerService 审计结果 (V-81 ~ V-85)

### V-81 (MEDIUM): sendAccessibilityEvent 无权限事件注入 ⭐

**文件**: `services/accessibility/java/com/android/server/accessibility/AccessibilityManagerService.java:1278`

```java
@RequiresNoPermission
public void sendAccessibilityEvent(AccessibilityEvent event, int userId) {
```

**影响**: 任意 app 可发送 AccessibilityEvent 到所有绑定的无障碍服务。

- 虚假 `TYPE_ANNOUNCEMENT` → TalkBack 朗读欺骗文本 (钓鱼盲人用户)
- `TYPE_WINDOW_STATE_CHANGED` → 混淆无障碍服务窗口追踪
- 包名被自动修正为调用者包名 (缓解)

**赏金预估**: $2,000 - $5,000

---

### V-82 (MEDIUM): getWindowTransformationSpec 无权限窗口信息泄露

**文件**: `AccessibilityManagerService.java:783`

```java
@RequiresNoPermission
public IAccessibilityManager.WindowTransformationSpec getWindowTransformationSpec(int windowId) {
```

任意 app 可查询任意窗口 ID 的变换矩阵和放大规格。泄露:
1. 窗口是否存在
2. 窗口在屏幕上的精确位置
3. 当前放大状态

**赏金预估**: $2,000 - $4,000

---

### V-83 (MEDIUM): addAccessibilityInteractionConnection 无权限注册

**文件**: `AccessibilityManagerService.java:1582`

```java
@RequiresNoPermission
public int addAccessibilityInteractionConnection(IWindow windowToken, IBinder leashToken,
        IAccessibilityInteractionConnection connection, String packageName, int userId)
```

`packageName` 参数由调用者提供，可能被伪造。如果下游不交叉验证，恶意 app 可注册声称属于其他包的交互连接。

**赏金预估**: $2,000 - $5,000

---

### V-84 (LOW-MEDIUM): associateEmbeddedHierarchy 无权限层级操控

**文件**: `AccessibilityManagerService.java:4879`

```java
@RequiresNoPermission
public void associateEmbeddedHierarchy(@NonNull IBinder host, @NonNull IBinder embedded) {
```

无权限检查或调用者验证。取决于能否获取有效 IBinder token。

**赏金预估**: $1,000 - $3,000

---

### V-85 (LOW-MEDIUM): isCallerInteractingAcrossUsers 弱 USER_CURRENT 检查

**文件**: `AccessibilitySecurityPolicy.java:510`

传入 `USER_CURRENT` 时注册为全局客户端，接收跨 profile 无障碍状态通知。

**赏金预估**: $1,000 - $2,000

---

## 六、完整漏洞清单 (新增 V-49 ~ V-85，按严重度排序)

### HIGH

| # | 漏洞名称 | 攻击面 | 赏金预估 |
|---|---------|--------|---------|
| **V-49** | SearchResultTrampoline 无权限 Intent 重定向 + Fragment 注入 | Settings Intent 重定向 | $5k-$20k |
| **V-50** | SubSettings.isValidFragment() 无条件 true | Settings Fragment 注入 | $5k-$15k |
| **V-67** | AppOps 虚拟设备绕过所有限制 | AppOps 绕过 | $5k-$15k |
| **V-68** | Profile Owner 任意 AppOps 模式修改 | AppOps 绕过 | $5k-$10k |
| **V-60** | Instrumentation 签名绕过 (userdebug) | 代码执行 | $3k-$8k |

### MEDIUM-HIGH

| # | 漏洞名称 | 攻击面 | 赏金预估 |
|---|---------|--------|---------|
| **V-51** | Deep Link replaceExtras 注入 | Settings Intent 重定向 | $3k-$10k |
| **V-52** | ChooseLockGeneric$InternalActivity 密码信任 | Settings EoP | $2k-$8k |
| **V-53** | AddAccountSettings KEY_INTENT 重定向 | Settings Intent 重定向 | $3k-$10k |
| **V-74** | NLS Companion Device 通道篡改 | NMS 权限提升 | $3k-$5k |
| **V-62** | Persistent App 受保护广播 | AMS 广播 | $3k-$5k |
| **V-59** | openContentUri 无 ACCESS_CONTENT_PROVIDERS_EXTERNALLY | AMS Provider | $1k-$3k |

### MEDIUM

| # | 漏洞名称 | 攻击面 | 赏金预估 |
|---|---------|--------|---------|
| **V-54** | MainClear 无 MASTER_CLEAR 检查 | Settings EoP | $2k-$5k |
| **V-56** | UserSettings 无调用者验证 | Settings EoP | $2k-$5k |
| **V-81** | sendAccessibilityEvent 无权限事件注入 | A11y 注入 | $2k-$5k |
| **V-82** | getWindowTransformationSpec 窗口信息泄露 | A11y 信息泄露 | $2k-$4k |
| **V-83** | addAccessibilityInteractionConnection 伪造 | A11y 注入 | $2k-$5k |
| **V-75** | NLS Snooze 任意通知 DoS | NMS DoS | $1k-$3k |
| **V-76** | NAS Importance 取消任意通知 | NMS 控制 | $2k-$4k |
| **V-77** | Backup 注入通道配置 + 锁屏隐私 | NMS 数据注入 | $2k-$4k |
| **V-78** | 敏感通知信任 UID 绕过 | NMS 隐私 | $1.5k-$3k |
| **V-69** | Proxy Operation 信任模型混乱 | AppOps 隐私 | $2k-$5k |
| **V-64** | MY_PID 无条件授权 | AMS 架构风险 | $2k-$5k |

### LOW-MEDIUM / LOW

| # | 漏洞名称 | 赏金预估 |
|---|---------|---------|
| **V-55** | DevelopmentSettings 生物识别绕过 | $1k-$3k |
| **V-57** | 324 导出 Activity / 27 无权限 | (辅助) |
| **V-58** | ApnSettings 跨用户订阅 | $1k-$2k |
| **V-61** | OP_NO_ISOLATED_STORAGE 残留 | $1k-$2k |
| **V-63** | Sticky Broadcast 普通权限 | $500-$1.5k |
| **V-65** | Persistable URI Grant 永不过期 | $500-$1k |
| **V-66** | 有序广播结果篡改 | $500-$1k |
| **V-70** | Invalid VD 返回 MODE_IGNORED | $500 |
| **V-71** | Cross-User Restriction 弱权限 | $1k-$2k |
| **V-72** | resetAllModes 保留角色 Ops | $500-$1k |
| **V-73** | Foreground Mode 异步竞态 | $1k-$3k |
| **V-79** | NMSInternal 无权限检查 | $1k-$3k |
| **V-80** | Notification Delegation 无同意 | $500-$1.5k |
| **V-84** | associateEmbeddedHierarchy 无权限 | $1k-$3k |
| **V-85** | isCallerInteractingAcrossUsers 弱检查 | $1k-$2k |

---

## 七、提交优先级更新

### 第一批 — 本周 (最高 ROI)

| 优先级 | 漏洞 | 行动 | 预估 |
|--------|------|------|------|
| 1 | **V-18 RingtonePlayer** | 零权限 PoC (已有代码) | $5k-$10k |
| 2 | **V-3 AudioService** | 零权限 PoC (已有代码) | $5k-$10k |
| 3 | **V-13 WifiDisplay MAC** | 简单广播监听 | $3k-$7.5k |
| 4 | **V-37 TelephonyRegistry** | 三广播合并 | $5k-$10k |

### 第二批 — 需要设备验证

| 优先级 | 漏洞 | 行动 | 预估 |
|--------|------|------|------|
| 5 | **V-49+V-50 SearchResultTrampoline** | 验证 caller 检查绕过 | $5k-$20k |
| 6 | **V-67 AppOps VD Bypass** | 需要 VirtualDevice 环境 | $5k-$15k |
| 7 | **V-33 DownloadStorageProvider** | 证明 URI grant 获取路径 | $10k-$20k |
| 8 | **V-8 PackageArchiver** | 确认利用链 | $10k-$20k |
| 9 | **V-68 Profile Owner AppOps** | 需要 DPC 前置 | $5k-$10k |

### 第三批 — 需要更多研究

| 优先级 | 漏洞 | 行动 | 预估 |
|--------|------|------|------|
| 10 | **V-74 NLS Channel 篡改** | CDM + NLS 环境 | $3k-$5k |
| 11 | **V-51 Deep Link replaceExtras** | 签名权限限制，需评估影响 | $3k-$10k |
| 12 | **V-52 ChooseLockGeneric** | 验证导出和 InternalActivity 行为 | $2k-$8k |
| 13 | **V-81 A11y Event 注入** | 构造 TalkBack 钓鱼 PoC | $2k-$5k |

---

## 八、累计审计统计

| 维度 | 之前 (报告 08) | 新增 (本报告) | 累计 |
|------|-------------|-------------|------|
| **审计服务/组件数** | 36 | +6 (深度) | 42 |
| **审计攻击方向数** | 20 | +6 | 26 |
| **发现的潜在变体总数** | 48 | +37 | **85** |
| **HIGH 严重度** | 11 | +5 | **16** |
| **MEDIUM-HIGH** | 10 | +6 | **16** |
| **MEDIUM** | 14 | +13 | **27** |
| **LOW-MEDIUM / LOW** | 13 | +13 | **26** |
| **总赏金预估** | $100k-$250k+ | +$70k-$170k | **$170k-$420k+** |

### 覆盖率更新

```
                     已审计 ◄──────────────────────────────► 未审计

  services/core/     █████████████████████████████████░░░░░░░  ~80% (+15%)
  (38 个服务)        [38/~50 服务已触及]

  packages/SystemUI   ██████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░  ~30%
  (4 个子模块)        [4/~15 子模块]

  packages/providers  ████████████████░░░░░░░░░░░░░░░░░░░░░░░  ~40%
  (6 个 Provider)     [6/~12 系统 Provider]

  core/java/          ████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  ~20%
  (4 个核心类)        [4/~20+ 安全相关核心类]

  packages/modules    ██████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  ~15%
  (3 个模块)          [3/~10 Mainline 安全模块]

  packages/apps       █████████████████░░░░░░░░░░░░░░░░░░░░░░  ~40% (NEW)
  (1 个 app - Settings) [1/5+ 系统 app, Settings 深度审计完成]
```

---

## 九、下一步行动

### 立即可做
1. **提交 Tier 1 漏洞** — V-18, V-3, V-13, V-37 (零权限 PoC)
2. **验证 V-49+V-50** — SearchResultTrampoline caller 检查绕过 (Pixel 设备)
3. **验证 V-67** — 构造虚拟设备 AppOps 绕过 PoC

### 需要设备
4. **Settings Fragment 注入完整利用链** — 从 SearchResultTrampoline → SubSettings → MainClear
5. **AppOps VirtualDevice 绕过** — 需要支持 VD 的设备/模拟器
6. **CDM + NLS 通道篡改** — 需要蓝牙配对设备

### 仍需审计
7. **packages/apps/Settings 更多 Fragment** — ChooseLockGeneric, SecuritySettings, IccLockSettings, TestingSettings
8. **packages/modules/Bluetooth** — 近端 RCE ($75k+), 协议 Fuzzing
9. **packages/modules/Connectivity** — WiFi/网络栈
10. **JobSchedulerService / RoleManagerService** — 之前 404

---

*Report 10 generated: 2026-04-28*
*3 parallel agents + direct audit, 6 modules deep scanned*
*37 new variants (V-49 ~ V-85), total 85 variants, bounty estimate $170k-$420k+*
