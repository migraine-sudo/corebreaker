# AOSP Variant Vulnerability Analysis Report v1

> 基于 2025-07 ~ 2025-12 Android Security Bulletin 的 CVE patch diff 分析
> 分析日期: 2026-04-28
> 数据源: frameworks/base (HEAD), 15+ CVE patch 逆向分析

---

## 已分析的 CVE patch (代表性样本)

| CVE | 模式 | 修复内容 |
|-----|------|---------|
| CVE-2025-48572 | BAL propagation | MediaButtonReceiverHolder 移除 BAL 到第三方 |
| CVE-2025-48573 | WIU/BFSL propagation | MediaSessionRecord.sendCommand 不再传播权限 |
| CVE-2025-48580 | Capability propagation | MediaBrowser 连接时排除能力传播 |
| CVE-2025-22420 | URI confused deputy | NotificationChannel sound URI 权限校验 |
| CVE-2025-48525 | Permission not revoked | CDM 解绑后撤销 NLS |
| CVE-2025-48594 | Shared UID cleanup | 共享 UID 包全部解绑 |
| CVE-2025-48546 | Windowing mode abuse | 禁止 setLaunchWindowingMode(PINNED) |
| CVE-2025-48589 | Cross-user data leak | Privacy indicators 只显示当前用户 |
| CVE-2025-48597 | TRUSTED_OVERLAY timing | PiP 进入确认后才授予 overlay |
| CVE-2025-32349 | Toast animation abuse | 强制默认动画时长 |
| CVE-2025-48583 | Bundle UAF | Parcel destroy vs recycle 区分 |
| CVE-2025-32350 | Activity launch type confusion | 规范化 home intent |
| CVE-2025-48627 | BAL UID confusion | startNextMatchingActivity 使用正确 UID |

---

## 6 大高频漏洞模式

1. **BAL/WIU/BFSL 权限传播** — MediaSession/MediaBrowser/BroadcastOptions 意外传播后台启动权限
2. **URI 权限未校验** — NotificationChannel/ContentProvider 接受外部 URI 但不验证调用方权限
3. **跨用户数据泄露** — Privacy indicators/系统 API 返回所有用户数据而非当前用户
4. **权限未随关系解除而撤销** — CDM/NLS/CompanionDevice 解绑后权限残留
5. **Overlay/窗口模式滥用** — Toast 动画时长、WINDOWING_MODE_PINNED、TRUSTED_OVERLAY 授予时机
6. **Activity 启动 UID 混淆** — startNextMatchingActivity/home intent 使用错误 UID

---

## 发现的 7 个潜在未修复变体

### V-1 (HIGH): isLaunchIntoPip() 绕过 PINNED 模式检查

**关联 CVE**: CVE-2025-48546
**文件**: `services/core/java/com/android/server/wm/ActivityStarter.java:2109-2113`

CVE-2025-48546 阻止了 `setLaunchWindowingMode(WINDOWING_MODE_PINNED)`，但 `ActivityOptions.setLaunchIntoPipParams()` 通过完全不同的代码路径调用 `moveActivityToPinnedRootTask()`，效果相同。`SafeActivityOptions.checkPermissions()` 中无此检查。

**赏金预估**: $5,000 - $10,000

---

### V-2 (HIGH): DevicePolicyManagerService BAL 无条件传播

**关联 CVE**: CVE-2025-48572
**文件**: `services/devicepolicy/java/com/android/server/devicepolicy/DevicePolicyManagerService.java:3134-3142`

`sendAdminCommandLocked()` 对所有 Device Admin broadcast 设置 `setBackgroundActivityStartsAllowed(true)`。任何已注册的第三方 Device Admin 均继承 BAL 权限，可从后台启动 Activity。

**赏金预估**: $7,500 - $15,000

---

### V-3 (HIGH): AudioService.hasHapticChannels() URI Confused Deputy

**关联 CVE**: CVE-2025-22420
**文件**: `services/core/java/com/android/server/audio/AudioService.java:8493`

公开 AIDL 接口，任何 app 传入任意 `content:` URI。AudioService (SYSTEM_UID) 无权限校验直接用系统 ContentResolver 打开。零权限触发。

**赏金预估**: $5,000 - $10,000

---

### V-4 (MEDIUM): CDM Disassociation Power/Network Exemption 残留

**关联 CVE**: CVE-2025-48525
**文件**: `services/companion/java/com/android/server/companion/association/DisassociationProcessor.java`

解绑时撤销了 role 但未撤销 power saver 白名单、后台计费网络访问、自动权限撤销豁免。代码中有 `// TODO: also revoke notification access` 注释确认。

**赏金预估**: $3,000 - $5,000

---

### V-5 (MEDIUM): 跨用户高功率定位状态泄露

**关联 CVE**: CVE-2025-48589
**文件**: `packages/SystemUI/src/com/android/systemui/statusbar/policy/LocationControllerImpl.java:231`

`areActiveHighPowerLocationRequests()` 使用 USER_ALL 数据不过滤用户。工作 profile 的 GPS 使用泄露到个人 profile 的状态栏。

**赏金预估**: $1,500 - $3,000

---

### V-6 (MEDIUM): WINDOWING_MODE_FREEFORM + setLaunchBounds() 无权限检查

**关联 CVE**: CVE-2025-48546
**文件**: `services/core/java/com/android/server/wm/SafeActivityOptions.java`

PINNED 被阻止了，但 FREEFORM 未检查。平板/ChromeOS/桌面模式设备可创建任意位置浮动窗口。

**赏金预估**: $3,000 - $7,500

---

### V-7 (LOW): AppWidget RemoteViews URI (flag-gated)

**文件**: `services/appwidget/java/com/android/server/appwidget/AppWidgetServiceImpl.java:2559-2612`

URI 权限检查由 feature flag 控制，未启用设备仍 vulnerable。已知问题 (b/369137473)，不适合提交。

---

*Report v1 generated: 2026-04-28*
