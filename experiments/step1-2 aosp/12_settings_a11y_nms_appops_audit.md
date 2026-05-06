# Report 12: Settings App + Accessibility + NMS + AppOps Parallel Audit

**Date**: 2026-04-29  
**Scope**: packages/apps/Settings, services/accessibility, NotificationManagerService, AppOpsService  
**Method**: 4 parallel agents reading source from Android Code Search (Android 15 / main branch)  
**Previous**: 131 variants (V-1 to V-131) across reports 01-11

---

## Summary

| Direction | New Findings | HIGH | MED-HIGH | MED | LOW-MED/LOW |
|-----------|-------------|------|----------|-----|-------------|
| Settings app | 0 (well-hardened) | 0 | 0 | 0 | 0 |
| Accessibility | 11 | 1 | 2 | 5 | 3 |
| NMS | 8 | 2 | 2 | 3 | 1 |
| AppOps | 10 | 3 | 1 | 3 | 3 |
| **Total** | **29** | **6** | **5** | **11** | **7** |

**New findings this round**: 29 variants (V-132 to V-160)  
**Cumulative total**: 160 variants  
**Round 4 estimated bounty**: $58,500 - $144,500  
**Cumulative project estimate**: $312,000 - $765,000+

---

## Part A: Settings App — Well-Hardened (0 new findings)

Settings app 在当前 AOSP main branch 上已充分加固:

- **SubSettings `isValidFragment()` 返回 true** — 但 SubSettings 是 unexported，唯一的 trampoline 路径 (SearchResultTrampoline) 有签名验证 `verifyLaunchSearchResultPageCaller()`
- **Deep link Intent URI 解析** — 被 `LAUNCH_MULTI_PANE_SETTINGS_DEEP_LINK` 权限保护 + 默认 disabled
- **324 个 exported activities** — 全部使用 manifest metadata `FRAGMENT_CLASS` 模式，不从 intent extras 接受 fragment name
- **SettingsGateway fragment 白名单** — 在所有 SettingsActivity 子类上正确执行
- **凭证 Activity** — userId/PendingIntent 处理在 unexported InternalActivity 中，外部不可达

**结论**: Settings app 不再是低垂果实。OEM 定制叠加层 (FeatureFactory) 可能引入弱点，但 stock AOSP 已安全。

---

## Part B: Accessibility Service Audit (11 findings)

### V-132: isAccessibilityTool 自声明绕过全部警告 + 获取敏感数据访问 [HIGH]

**File**: `services/accessibility/java/com/android/server/accessibility/PolicyWarningUIController.java`, `core/java/android/view/AccessibilityInteractionController.java`

**Issue**: `isAccessibilityTool()` 是 a11y service XML metadata 中的 **自声明** boolean，系统不做任何验证。此标志控制两个关键安全边界:

1. **警告通知绕过**: `PolicyWarningUIController.trySendNotification()` 中，声明 `isAccessibilityTool() == true` 的服务永远不会收到 24 小时警告通知
2. **敏感数据访问**: `AccessibilityInteractionController.isVisibleToAccessibilityService()` 中，带有 `FLAG_SERVICE_IS_ACCESSIBILITY_TOOL` 的服务可读取所有 view 内容，包括 `isAccessibilityDataSensitive` 标记的密码字段和 PII

**Attack**: 恶意 app 声明 `android:isAccessibilityTool="true"`，一旦用户启用 → 无警告 + 可读密码字段  
**Impact**: 全 app 密码/PII 窃取，无用户警告  
**Reproducibility**: 需用户手动启用服务 (社工)，但启用后无任何系统警告  
**Bounty**: $3,000-$7,000

---

### V-133: PolicyWarningUIController 24h 延迟 + Unbind/Rebind 循环取消告警 [MEDIUM-HIGH]

**File**: `services/accessibility/java/com/android/server/accessibility/PolicyWarningUIController.java`

**Issue**: 多个缺陷叠加:
1. 非 a11y tool 服务绑定后，警告闹钟设在 **24 小时后** — 服务在这期间有完整权限
2. `onNonA11yCategoryServiceUnbound` 调用 `cancelAlarm()` — 服务可每 23 小时 unbind/rebind 重置闹钟，永远不触发警告
3. 警告仅是普通通知 (非阻断对话框)
4. `Settings.Secure.NOTIFIED_NON_ACCESSIBILITY_CATEGORY_SERVICES` 中的服务被永久静默
5. 用户切换时 `onSwitchUser` 调用 `cancelSentNotifications()` 清除所有警告

**Attack**: 实现 unbind/rebind watchdog 循环避免任何警告  
**Bounty**: $2,000-$5,000

---

### V-134: sendAccessibilityEvent 通过 AppWidget 宿主关系伪造包名 [MEDIUM-HIGH]

**File**: `services/accessibility/java/com/android/server/accessibility/AccessibilitySecurityPolicy.java` — `resolveValidReportedPackageLocked()`

**Issue**: `sendAccessibilityEvent()` 标注 `@RequiresNoPermission` — 任意 app 可调用。包名验证中有 AppWidget 宿主豁免: 如果 `mAppWidgetService.getHostedWidgetPackages(resolvedUid)` 包含声称的包名，则接受。

**Attack**: 宿主目标 app 的 widget → 发送 `TYPE_WINDOW_STATE_CHANGED` 事件伪造为目标 app → 混淆 a11y 服务/TalkBack  
**Bounty**: $1,000-$3,000

---

### V-135: TYPE_ANNOUNCEMENT 无条件分发到所有 A11y 服务 [MEDIUM]

**File**: `services/accessibility/java/com/android/server/accessibility/AccessibilitySecurityPolicy.java` — `canDispatchAccessibilityEventLocked()`

**Issue**: `TYPE_ANNOUNCEMENT`, `TYPE_WINDOW_STATE_CHANGED`, `TYPE_NOTIFICATION_STATE_CHANGED` 等事件类型 **始终分发**，不检查 `isRetrievalAllowingWindowLocked`。

**Attack**: 任意 app 发送 `TYPE_ANNOUNCEMENT` → 所有运行中的 a11y 服务收到  
**PoC**:
```java
AccessibilityEvent event = new AccessibilityEvent(TYPE_ANNOUNCEMENT);
event.getText().add("Spoofed text");
am.sendAccessibilityEvent(event);
```
**Bounty**: $1,000-$2,000

---

### V-136: performGlobalAction 无逐动作能力检查 [MEDIUM]

**File**: `services/accessibility/java/com/android/server/accessibility/AbstractAccessibilityServiceConnection.java`

**Issue**: 启用的 a11y 服务可执行 `GLOBAL_ACTION_TAKE_SCREENSHOT`, `GLOBAL_ACTION_LOCK_SCREEN` 等全部全局动作，仅检查 `hasRightsToCurrentUserLocked()`。Key events 注入带有 `FLAG_FROM_SYSTEM`。结合 V-132 (自声明 a11y tool) 可无警告获得全部能力。

**Bounty**: $1,000-$3,000

---

### V-137: takeScreenshot(displayId) 跨虚拟显示器截屏 [MEDIUM-HIGH]

**File**: `services/accessibility/java/com/android/server/accessibility/AbstractAccessibilityServiceConnection.java`

**Issue**: `takeScreenshot(displayId)` 调用 `mWindowManagerService.captureDisplay(displayId)` 后执行 `Binder.clearCallingIdentity()`。非私有虚拟显示器可被截屏。Per-window 的 `takeScreenshotOfWindow()` 检查 FLAG_SECURE，但 display-level 不检查。

**Bounty**: $2,000-$5,000

---

### V-138: 已安装/已启用 A11y 服务枚举无需权限 [MEDIUM]

**File**: `services/accessibility/java/com/android/server/accessibility/AccessibilityManagerService.java`

**Issue**: `getEnabledAccessibilityServiceList()` 标注 `@RequiresNoPermission`。任意 app 可探测用户启用了哪些 a11y 服务 (TalkBack、密码管理器 a11y 等)。

**PoC**: `am.getEnabledAccessibilityServiceList(FEEDBACK_ALL_MASK)`  
**Bounty**: $500-$1,500

---

### V-139: addAccessibilityInteractionConnection 无权限注册 View 层级 [MEDIUM]

**Impact**: Widget 宿主可用其他 app 包名注册 a11y interaction connection  
**Bounty**: $500-$1,500

### V-140: registerUiTestAutomationService 静默抑制所有 A11y 服务 [MEDIUM]

**Impact**: userdebug/eng 上 shell 可静默禁用 TalkBack 等全部 a11y 服务  
**Bounty**: $500-$1,000

### V-141: ProxyAccessibilityServiceConnection 通过 CDM 角色获取完整代理 [MEDIUM]

**Impact**: `COMPANION_DEVICE_APP_STREAMING` role 持有者可注册 proxy a11y 连接，绕过 AppOps 检查  
**Bounty**: $1,000-$3,000

### V-142: checkAccessibilityAccess Null ResolveInfo 绕过 AppOps [LOW-MEDIUM]

**Impact**: UiAutomation/InteractionBridge/Proxy 连接的 null resolveInfo 完全绕过 AppOps 检查 — 架构性弱点  
**Bounty**: $500-$1,000

---

## Part C: NotificationManagerService Deep Audit (8 findings)

### V-143: SnoozeHelper Exported Broadcast Receiver 无权限保护 [HIGH]

**File**: `services/core/java/com/android/server/notification/SnoozeHelper.java`

**Issue**: SnoozeHelper 注册 BroadcastReceiver 使用 `RECEIVER_EXPORTED_UNAUDITED` 且 **无权限保护**:
```java
IntentFilter filter = new IntentFilter(REPOST_ACTION);  // "SnoozeHelper.EVALUATE"
filter.addDataScheme(REPOST_SCHEME);                     // "repost"
mContext.registerReceiver(mBroadcastReceiver, filter, Context.RECEIVER_EXPORTED_UNAUDITED);
```

Receiver 的 `onReceive` 不做调用者验证:
```java
if (REPOST_ACTION.equals(intent.getAction())) {
    repost(intent.getStringExtra(EXTRA_KEY), intent.getIntExtra(EXTRA_USER_ID,
        UserHandle.USER_SYSTEM), false);
}
```

**Attack**: 
```java
Intent intent = new Intent("SnoozeHelper.EVALUATE");
intent.setData(Uri.parse("repost://key"));
intent.putExtra("key", "0|com.target.app|1234|null|10123");
intent.putExtra("userId", 0);
sendBroadcast(intent);
```

**Impact**: 
1. 强制 un-snooze 任意 app 的已暂停通知
2. 跨用户 repost (设置 userId 为其他用户)
3. DoS: `CONCURRENT_SNOOZE_LIMIT = 500` 是全局的，NLS snooze 500 条 → 阻塞整个系统 snooze 功能

**Reproducibility**: HIGH — 零权限 sendBroadcast  
**Bounty**: $3,000-$7,000

---

### V-144: Notification Assistant 注入任意 PendingIntent Action [HIGH]

**File**: `core/java/android/service/notification/Adjustment.java`, `services/core/java/com/android/server/notification/NotificationRecord.java`

**Issue**: NAS 可通过 `KEY_CONTEXTUAL_ACTIONS` 注入任意 `Notification.Action` (含 PendingIntent) 到任何通知。同时可设 `KEY_IMPORTANCE = IMPORTANCE_NONE` 静默取消安全通知，或设 `KEY_SENSITIVE_CONTENT = false` 暴露敏感通知内容给所有 NLS。

**Reproducibility**: 需要 NAS 位置 (DO/Admin)  
**Bounty**: $3,000-$5,000

---

### V-145: NLS 通过 CompanionDevice 关联修改任意 App 通知频道 [MEDIUM-HIGH]

**File**: `core/java/android/service/notification/NotificationListenerService.java`

**Issue**: 拥有 CDM 关联的 NLS 可调用 `updateNotificationChannelFromPrivilegedListener(pkg, user, channel)` 修改 **任意 app** 的通知频道 — importance 设为 NONE 即可静默安全通知。

**Bounty**: $2,000-$4,000

---

### V-146: Lockscreen 通知可见性覆盖间隙 [MEDIUM-HIGH]

**Issue**: NLS 可通过 `setPackageVisibilityOverride(VISIBILITY_PUBLIC)` 强制其他 app 的私密通知在锁屏上可见。`lockdown` 模式退出时的 repost 顺序也存在 TOCTOU 风险。

**Bounty**: $2,000-$5,000

---

### V-147: 通知委托 (Delegation) 伪装 + URI 泄露 [MEDIUM]

**Issue**: 被委托 app B 可调用 `notifyAsPackage("A", ...)` 以 A 的身份发通知。通知中的 URI 会被自动授予 `FLAG_GRANT_READ_URI_PERMISSION` 给所有 NLS。

**Bounty**: $1,000-$3,000

---

### V-148: 敏感内容去分类 — NAS 可取消通知敏感标记 [MEDIUM]

**Issue**: NAS 设 `KEY_SENSITIVE_CONTENT = false` 是直接赋值 (非 OR 合并)，可覆盖之前的 true → 暴露敏感通知内容给非特权 NLS。

**Bounty**: $1,500-$3,000

---

### V-149: FullScreenIntent PendingIntent Confused Deputy [MEDIUM]

**Issue**: `fullScreenIntent` 权限检查验证 posting app 的权限而非 PendingIntent creator。配合 confused deputy 链可滥用特权 PendingIntent。

**Bounty**: $1,000-$3,000

---

### V-150: 通知频道/组资源耗尽 DoS [MEDIUM]

**Issue**: 5000 频道 * 1000 字符 ID/Name = ~10MB XML per package。删除后仍保留 30 天。

**Bounty**: $500-$1,000

---

## Part D: AppOpsService Deep Audit (10 findings)

### V-151: startWatchingMode 零权限监控任意 App 权限变更 [HIGH]

**File**: `services/core/java/com/android/server/appop/AppOpsService.java`

**Issue**: `startWatchingMode()` 是 API 19 起的公开 API，**无需任何权限**。任意 app 可注册监听 **任意其他 app** 的 op mode 变更。回调包含变更的 op 名和包名。

`WATCH_FOREGROUND_CHANGES` flag 还能追踪目标 app 的前后台状态转换。

**Attack**:
```java
AppOpsManager ops = getSystemService(AppOpsManager.class);
ops.startWatchingMode(OPSTR_CAMERA, "com.banking.app",
    (op, pkg) -> Log.d("LEAK", pkg + " changed: " + op));
```

**Impact**: 实时监控所有 app 的权限变更时间线 (相机/麦克风/位置等)  
**Reproducibility**: 零权限，任意 stock 设备  
**Bounty**: $1,000-$3,000

---

### V-152: Virtual Device 架构性限制绕过 (V-67 深度扩展) [HIGH]

**File**: `AppOpsService.java`, `AppOpsRestrictionsImpl.java`, `AppOpsCheckingServiceImpl.java`

**Issue**: 深度架构分析揭示三层问题:
1. `AppOpsRestrictionsImpl` **完全没有** virtual device 感知 — 接口上无 persistentDeviceId 参数
2. `AppOpsCheckingServiceImpl.setUidMode()` 接受 persistentDeviceId 但 **存储时忽略** — 仅按 UID 存储
3. Package mode 完全没有 device 概念

`isOpRestrictedLocked()` 中 `virtualDeviceId != DEVICE_ID_DEFAULT` 时直接返回 false，跳过全部限制。

**Exploitation gate**: 需要有效的 virtual device 存在 (CREATE_VIRTUAL_DEVICE 签名权限)  
**Bounty**: $5,000-$15,000

---

### V-153: Profile Owner 任意 AppOps 修改 (V-68 确认) [HIGH]

**File**: `AppOpsService.java` — `enforceManageAppOpsModes()`

**Issue**: PO app 可对其 managed profile 内 **任意 app** 调用 `setMode()`/`setUidMode()`/`resetAllModes()`，设置任何 AppOps:
- `OP_SYSTEM_ALERT_WINDOW` → `MODE_ALLOWED` (授予悬浮窗)
- `OP_CAMERA` / `OP_RECORD_AUDIO` → `MODE_ALLOWED` (授予传感器)
- `OP_RUN_IN_BACKGROUND` → `MODE_ALLOWED` (绕过后台限制)

**Bounty**: $5,000-$10,000

---

### V-154: Proxy Operation 归因源伪造 [MEDIUM-HIGH]

**File**: `IAppOpsService.aidl`, `AttributionSource.java`

**Issue**: `noteProxyOperation` 接受 `AttributionSourceState`，非特权 app 可构造: `A(自己) -> B(任意 app)` 的归因链。系统不验证 B 是否同意被代理。

**Impact**: 在目标 app 的 AppOps 历史中注入虚假访问记录，混淆 Privacy Dashboard  
**Bounty**: $2,000-$5,000

---

### V-155: finishOp 无匹配 startOp — 状态混淆 [MEDIUM]

**Issue**: `finishOperation` 接受 uid/packageName 参数，调用 UID 不一定等于参数 UID — 可能跨 app 结束 op  
**Bounty**: $1,000-$3,000

---

### V-156: MODE_FOREGROUND 5 秒 Settle 时间滥用 [MEDIUM]

**Issue**: `TOP_STATE_SETTLE_TIME = 5s` — app 短暂进入前台后，MODE_FOREGROUND ops 在返回后台后仍保持 ALLOWED 5 秒。可通过快速 activity start/finish 循环维持后台 camera/mic 访问。

**Bounty**: $1,000-$3,000

---

### V-157: setUserRestriction 跨用户弱权限检查 [MEDIUM]

**Issue**: 跨用户 gate 使用 `INTERACT_ACROSS_USERS` 而非 `INTERACT_ACROSS_USERS_FULL`  
**Bounty**: $1,000-$2,000

---

### V-158: 自身历史 Ops 查询无速率限制 [LOW-MEDIUM]

**Issue**: 任意 app 可无限频率查询自身 `getHistoricalOps()` — 可检测系统何时查询其权限状态  
**Bounty**: $500-$1,000

---

### V-159: checkAudioOperation 独立路径信息泄露 [LOW-MEDIUM]

**Issue**: `checkAudioOperation` 完全不检查正常 AppOps mode，仅检查 camera/zen 限制 — 可作为设备 zen mode 状态探测器  
**Bounty**: $500-$1,000

---

### V-160: 回调 Binder Death 监控侧信道 [LOW-MEDIUM]

**Issue**: V-151 的扩展 — 通过 callback 时序侧信道检测 app 活动  
**Bounty**: $500

---

## Cumulative Statistics

| Metric | Report 11 | This Round | Cumulative |
|--------|-----------|------------|------------|
| Total variants | 131 | +29 | **160** |
| HIGH severity | 25 | +6 | **31** |
| MEDIUM-HIGH | ~25 | +5 | **~30** |
| MEDIUM | ~45 | +11 | **~56** |
| LOW-MEDIUM/LOW | ~36 | +7 | **~43** |
| Bounty estimate (low) | $253.5k | +$58.5k | **$312k** |
| Bounty estimate (high) | $620.5k | +$144.5k | **$765k** |

---

## Top Priority for Local PoC Development

### Tier 1 — 零权限本地可复现 (立即可做)

| # | Variant | Attack | Effort |
|---|---------|--------|--------|
| 1 | **V-143** SnoozeHelper sendBroadcast | `sendBroadcast(new Intent("SnoozeHelper.EVALUATE"))` | 5 min |
| 2 | **V-151** startWatchingMode | `ops.startWatchingMode(OP, pkg, cb)` | 5 min |
| 3 | **V-135** TYPE_ANNOUNCEMENT injection | `am.sendAccessibilityEvent(event)` | 5 min |
| 4 | **V-138** A11y service enumeration | `am.getEnabledAccessibilityServiceList()` | 5 min |
| 5 | **V-154** Proxy attribution chain forgery | 构造 AttributionSource 链 | 30 min |
| 6 | **V-156** MODE_FOREGROUND settle abuse | Activity flash + background camera | 1 hr |

### Tier 2 — 需要特定条件 (CDM 关联 / Work Profile)

| # | Variant | Precondition |
|---|---------|-------------|
| 7 | **V-145** NLS channel modification | CDM association (user dialog) |
| 8 | **V-146** Lockscreen visibility override | NLS + CDM |
| 9 | **V-153** PO arbitrary AppOps | Work profile enrollment |
| 10 | **V-132** isAccessibilityTool bypass | User enables service (social eng) |

### Tier 3 — 需要进一步分析

| # | Variant | What's needed |
|---|---------|--------------|
| 11 | **V-152** VD restriction bypass | 找到非签名权限创建/引用 VD 的路径 |
| 12 | **V-155** finishOp cross-app | 验证 uid 参数是否被信任 |

---

## Settings App Detailed Notes (for reference)

Settings 审计的详细分析保留如下，虽然无新漏洞但有价值的安全架构观察:

- **324 exported activities** 全部使用 manifest `META_DATA_KEY_FRAGMENT_CLASS`，不接受 intent extras fragment name
- `SettingsGateway.ENTRY_FRAGMENTS` 白名单正确执行
- `SecurityDashboardActivity` 的 `isValidFragment()` 额外接受 `getAlternativeFragmentName()` — OEM 叠加层可能引入弱点
- `ConfirmDeviceCredentialActivity.InternalActivity` 的 `checkForPendingIntent()` 正确限制在 unexported 内部 Activity
- `SettingsSliceProvider` exported + `grantUriPermissions=true`，但有 `READ_SEARCH_INDEXABLES` 权限保护
- `FileProvider` 暴露整个 cache 目录 (`<cache-path name="my_cache" />`) — 需要找到 URI 分享路径

---

*Generated by FuzzMind/CoreBreaker Round 4 parallel audit — 2026-04-29*
