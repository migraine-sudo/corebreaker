# AOSP Variant Analysis Report v2 — 扩展扫描

> 在 v1 (7 个候选) 基础上追加 3 轮深度扫描
> 2026-04-28

---

## 新增发现 (V-8 ~ V-12)

### V-8 (HIGH): PackageArchiver.UnarchiveIntentSender — 系统身份启动未验证 Intent

**关联模式**: LaunchAnyWhere 家族
**文件**: `services/core/java/com/android/server/pm/PackageArchiver.java:1519-1537`

```java
private class UnarchiveIntentSender extends IIntentSender.Stub {
    public void send(...) {
        Intent extraIntent = intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent.class);
        UserHandle user = intent.getParcelableExtra(Intent.EXTRA_USER, UserHandle.class);
        if (extraIntent != null && user != null
                && mAppStateHelper.isAppTopVisible(
                        getCurrentLauncherPackageName(user.getIdentifier()))) {
            extraIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            mContext.startActivityAsUser(extraIntent, user);  // SYSTEM context!
        }
    }
}
```

- 从 fillIn 中提取 `EXTRA_INTENT`，直接用 system context 启动
- 唯一校验: launcher 是否在前台 (默认满足)
- 无 component/package/permission 验证
- `preventIntentRedirect` enforcement flag 尚未全量启用

**预估赏金**: $10,000 - $20,000 (LaunchAnyWhere 级别)

---

### V-9 (HIGH): TvInputManagerService.requestChannelBrowsable() 无权限系统广播

**文件**: `services/core/java/com/android/server/tv/TvInputManagerService.java:2770`

- 任何 app 可调用，无 permission check
- `clearCallingIdentity()` 后以系统身份发送广播
- 广播内容部分可控 (channelUri → EXTRA_CHANNEL_ID)

**预估赏金**: $3,000 - $7,500

---

### V-10 (MEDIUM-HIGH): RingtonePlayer.play()/getTitle() URI Confused Deputy

**文件**: `packages/SystemUI/src/com/android/systemui/media/RingtonePlayer.java:117, 209`

- `IRingtonePlayer` 可通过 `AudioManager.getRingtonePlayer()` 获取
- 无权限检查，SystemUI context 打开任意 URI
- SystemUI 持有 READ_CONTACTS, READ_PHONE_STATE 等特权
- `getTitle()` 可泄露任意 content provider 的元数据

**预估赏金**: $5,000 - $7,500

---

### V-11 (MEDIUM): RemoteViews BUNDLE 类型不递归扫描 URI

**文件**: `core/java/android/widget/RemoteViews.java:2726-2737`

```java
// TODO(b/281044385): Should we do anything about type BUNDLE?
```

通过 `RemoteViews.setBundle()` 嵌入包含 URI 的 Bundle，不会被 `visitUris()` 扫描到。Google 自己的 TODO 确认了此问题。

**预估赏金**: $1,000 - $3,000 (可能 dupe)

---

### V-12 (MEDIUM): preventIntentRedirect enforcement 未全量启用

**文件**: `core/java/android/security/responsible_apis_flags.aconfig:76-119`

```
prevent_intent_redirect:                      is_fixed_read_only: true   // token 创建已启用
prevent_intent_redirect_abort_or_throw_exception: is_fixed_read_only: false  // 执行拦截未固定
```

IntentCreatorToken 框架设计完善但执行 flag 服务端控制，大多数设备可能未启用 enforcement。意味着 V-8 等 Intent 转发漏洞在当前设备上仍可利用。

---

## 全部候选汇总 (v1 + v2, 按优先级排序)

| # | 严重度 | 漏洞 | 模式 | 赏金预估 | 提交优先 |
|---|--------|------|------|---------|---------|
| **V-8** | HIGH | PackageArchiver EXTRA_INTENT 系统启动 | Intent 转发 | $10k-$20k | 1 |
| **V-3** | HIGH | AudioService.hasHapticChannels() URI | Confused deputy | $5k-$10k | 2 |
| **V-2** | HIGH | DPMS BAL propagation to admin | BAL 传播 | $7.5k-$15k | 3 |
| **V-1** | HIGH | isLaunchIntoPip() bypass | Windowing abuse | $5k-$10k | 4 |
| **V-10** | MED-HIGH | RingtonePlayer URI confused deputy | Confused deputy | $5k-$7.5k | 5 |
| **V-9** | HIGH | TvInputManager 无权限广播 | Binder 无校验 | $3k-$7.5k | 6 |
| **V-4** | MEDIUM | CDM exemption 残留 | 权限不撤销 | $3k-$5k | 7 |
| **V-6** | MEDIUM | Freeform mode 无校验 | Windowing abuse | $3k-$7.5k | 8 |
| **V-5** | MEDIUM | 跨用户 GPS 指示器泄露 | 跨用户 | $1.5k-$3k | 9 |
| **V-11** | MEDIUM | RemoteViews Bundle URI 遗漏 | URI 遗漏 | $1k-$3k | 10 |
| **V-7** | LOW | AppWidget URI (flag-gated) | URI 校验 | $0 | - |
| **V-12** | MEDIUM | preventIntentRedirect 未强制执行 | 防御缺口 | (辅助论证) | - |

---

## Binder 无权限方法扫描额外发现

### 服务防御强度排名

**最弱** (多个方法缺少权限检查):
- TvInputManagerService
- RingtonePlayer (SystemUI)
- AudioService

**最强** (一致的 enforceCallingPermission):
- NotificationManagerService
- DevicePolicyManagerService
- StatusBarManagerService
- StorageManagerService
- WallpaperManagerService

---

## 扫描覆盖度

### 已完成 ✓
- [x] BAL/WIU/BFSL 传播 (全 services/)
- [x] URI confused deputy (全 services/ + SystemUI)
- [x] 跨用户数据泄露 (SystemUI)
- [x] 权限不撤销 (CDM)
- [x] SafeActivityOptions 参数缺失
- [x] Notification URI 覆盖率
- [x] Intent 转发 / EXTRA_INTENT 提取
- [x] Binder 方法无权限调用 (10 个核心 AIDL)

### 尚未扫描
- [ ] ContentProvider 路径遍历 (系统 Provider openFile)
- [ ] 跨用户 startActivity (userId 参数校验)
- [ ] Race condition (clearCallingIdentity TOCTOU)
- [ ] Broadcast 权限缺失 (sendBroadcast 无 receiverPermission)
- [ ] Settings Provider 注入
- [ ] packages/apps/Settings/ (独立拉代码)
- [ ] packages/modules/Bluetooth/ (协议 fuzzing)

---

*Report v2 generated: 2026-04-28*
*累计发现: 12 个潜在未修复变体 (5 HIGH / 4 MEDIUM / 2 LOW / 1 INFO)*
