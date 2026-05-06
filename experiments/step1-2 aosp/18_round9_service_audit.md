# Round 9: Service & Component Deep Audit

## 审计范围
1. UriGrantsManagerService — URI permission confused deputy
2. ContentService — ContentProvider 分发/同步逻辑
3. NotificationManagerService — PendingIntent/URI grant
4. ClipboardService — 跨用户/跨 profile 数据泄露
5. PendingIntentController/PendingIntentRecord — confused deputy
6. Settings app — exported components
7. SystemUI — exported components
8. AccountManagerService — KEY_INTENT redirect
9. ContextualSearchManagerService — 新服务攻击面
10. CompanionDeviceManagerService — 设备关联
11. CrossProfileAppsServiceImpl — 跨 profile 活动
12. GrammaticalInflectionService — 语法性别设置
13. HealthConnectManagerService — 健康数据

## 高价值发现

### V-193: ContentService.cancelSyncAsUser 缺少权限检查 [设备验证通过]
- **严重性**: MEDIUM (DoS)
- **位置**: ContentService.java line 622-639
- **问题**: `cancelSyncAsUser()` 只检查 `enforceCrossUserPermission`，不检查 `hasAccountAccess` / `hasAuthorityAccess`。对比 `requestSync()` (line 567) 做了双重检查。
- **影响**: 任意 app 可取消同一用户下所有 app 的同步操作。`cancelSync(null, null, null)` 取消所有同步。
- **设备验证**: Pixel 10 Android 16, shell uid 2000, cancelSync 和 cancelSyncAsUser 均成功无异常

### V-194: ContentService.onDbCorruption 零权限日志注入 [设备验证通过]
- **严重性**: LOW
- **位置**: ContentService.java line 1469-1473
- **问题**: `onDbCorruption(tag, msg, stackTrace)` 无任何权限检查。触发 `Slog.wtf()` 写入 DropBox。
- **影响**: 日志污染、DropBox 写入、userdebug 设备可能 crash system_server
- **设备验证**: Pixel 10 Android 16, shell uid 2000, 成功触发

### V-195: UriGrantsManagerService sourceUserId 不受控
- **严重性**: MEDIUM
- **位置**: UriGrantsManagerService.java line 147-167
- **问题**: `grantUriPermissionFromOwner()` 的 sourceUserId 参数由调用者直接控制，缺少跨用户校验。targetUserId 有 `handleIncomingUser` 校验。
- **影响**: 潜在的跨用户 URI 权限绕过
- **注意**: 核心检查方法 `checkGrantUriPermissionUnlocked` 反编译失败（559 指令），需要 baksmali 手动分析

### V-196: UriGrantsManager grantModes TOCTOU 竞态
- **严重性**: MEDIUM
- **位置**: UriGrantsManagerService.java line 800-814
- **问题**: `findOrCreateUriPermissionLocked` 在锁内执行，但 `grantModes()` 在锁外。与 `revokeUriPermissionLocked` 存在竞态。
- **影响**: 权限撤销后可能仍保留 URI 访问

### V-197: ContentService.addStatusChangeListener 无权限检查
- **严重性**: LOW (Info)
- **位置**: ContentService.java line 982-992
- **问题**: 注册同步状态监听器无需 `READ_SYNC_STATS` 或 `READ_SYNC_SETTINGS` 权限
- **影响**: 任意 app 可监听全局同步状态变化时间模式

### PendingIntent 跨用户重定向 (Automotive only)
- **严重性**: MEDIUM-HIGH (仅多用户可见设备)
- **位置**: ActivityManagerService.sendIntentSender() line 4112-4128
- **问题**: USER_CURRENT PendingIntent 被跨用户发送时，保留创建者 uid 但在目标用户空间执行
- **影响**: 仅在 isVisibleBackgroundUsersEnabled() 设备上（Automotive）

### KeyguardSliceProvider 锁屏信息泄露
- **严重性**: LOW (Info)
- **组件**: com.android.systemui.keyguard.KeyguardSliceProvider
- **问题**: exported=true，无权限保护。可读取日期、下一个闹钟时间、DND 状态
- **影响**: 任意 app 可获取锁屏显示的信息

## 审计后排除（无可利用漏洞）
- AccountManagerService: `checkKeyIntent` 检查严格（签名验证 + content:// 拒绝 + parcel 一致性）
- NotificationManagerService: URI grant 使用 `notificationRecord.getUid()` 验证所有权，SecurityException 被捕获
- ClipboardService: 后台写入是已知设计行为（Android 10+ 限制读不限制写）
- CrossProfileAppsServiceImpl: 严格的 profile group + permission 检查
- CompanionDeviceManagerService: 需要 CREATE_VIRTUAL_DEVICE 权限
- GrammaticalInflectionService: 需要 CHANGE_CONFIGURATION 权限
- ContextualSearchManagerService: 需要 ACCESS_CONTEXTUAL_SEARCH（signature|privileged）
- Settings Fragment injection: 已通过白名单机制缓解

## 下一步
1. 在真实 APK (untrusted_app) 中验证 V-193 cancelSync — 这是公开 SDK API (ContentResolver.cancelSync)，应该对任意 app 有效
2. 使用 baksmali 手动分析 UriGrantsManagerService.checkGrantUriPermissionUnlocked 的完整字节码
3. 审计 AppWidgetServiceImpl (5099 行) 的 widget 更新/绑定逻辑
4. 审计 JobSchedulerService 的 job 调度/取消逻辑
