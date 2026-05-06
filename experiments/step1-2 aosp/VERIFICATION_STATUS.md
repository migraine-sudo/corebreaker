# AOSP VRP 设备验证状态

测试设备: Pixel, Android 16 (SDK 36), 安全补丁 2026-04-05

## 已确认并提交

| ID | 漏洞 | 严重度 | 状态 | 备注 |
|----|------|--------|------|------|
| V-415 | SettingsProvider DeviceConfig 零权限读取 | Medium | ✅ 已提交 | 250+ namespaces, 7 安全相关 flag 可读 |
| V-344/V-346 | Private Space 零权限存在性检测+状态监控 | Medium-High | ✅ 已提交 | getProfileIds 泄露 PS userId, isUserRunning 实时监控 |
| V-451/V-452 | NFC Service Hijack | High | ✅ 已提交 | (之前提交) |

## 已确认 — 待提交

| ID | 漏洞 | 严重度 | 状态 | 备注 |
|----|------|--------|------|------|
| V-395 | CredentialManager getCandidateCredentials 缺失 enforceCallingPackage | Medium | ⚠️ 确认但危害有限 | 伪造包名到达服务端（logcat 确认），但完整利用链被 WRITE_SECURE_SETTINGS 阻断。属于 defense-in-depth 问题。报告已写好: `poc-credman-impersonate/` |
| V-436 | Settings EXTRA_USER_HANDLE 跨用户 Private Space 数据访问 | High | ✅ 已确认 | 零权限 app 通过 user_handle extra 使 Settings 跨用户操作。logcat 证明 Settings 读取 extra 并以 uid 1000 启动 u11 activity。PS locked 时被 quiet mode 拦截，unlocked 时直接通过。10/10 Settings action 均受影响。报告已写好: `poc-settings-crossuser/` |
| V-376/V-377 | Accessibility 服务备份恢复绕过确认对话框 | High | ✅ 已确认 | `settings put secure enabled_accessibility_services` 直接启用 TalkBack 无确认对话框。dumpsys 确认服务被绑定+启用。备份恢复使用相同代码路径。报告已写好: `poc-a11y-backup-enable/` |
| V-425 | MediaSession2 零权限 Token 枚举 | Medium | ✅ 已确认 | `addOnSession2TokensChangedListener` 和 `getSession2Tokens` 无权限检查，而 Session1 的 `getActiveSessions` 正确要求 MEDIA_CONTENT_CONTROL/NLS。零权限 app (UID 10495) 调用成功无 SecurityException。报告已写好: `poc-mediasession2-leak/` |

## 已测试 — 不可利用

| ID | 漏洞 | 原因 | 备注 |
|----|------|------|------|
| V-435 | Settings SearchResultTrampoline Fragment 注入 | verifyLaunchSearchResultPageCaller() 在 Android 16 上正确验证调用者 | SettingsIntelligence SliceDeepLinkTrampoline 可达但硬编码目标 |
| V-349 | SystemUI ControlsRequestReceiver Cross-User | 有限 EoP | ControlsRequestDialog 能从 SystemUI 启动，但无进一步利用路径（需 work profile） |

## 新确认 — 高价值目标（2026-05-01）

| ID | 漏洞 | 严重度 | 状态 | 备注 |
|----|------|--------|------|------|
| PH-1 | getTypeAllocationCode 零权限硬件 ID 泄露 | Medium | ✅ 已确认 | 零权限 app (UID 10500) 成功读取 TAC=35815482。getImei() 正确拒绝。`poc-phone-id-leak/` |
| GPS-1 | GnssAntennaInfo 零权限 Listener 注册 | Medium-High | ✅ 已确认 | 注册成功返回 true，无 SecurityException。同模块 GnssStatus/LocationUpdates 正确要求 ACCESS_FINE_LOCATION。`poc-gnss-antenna-leak/` |
| V-464 | IRangingAdapter 7/13 方法缺失 RANGING 权限 | High | ✅ 已确认 | 零权限 OOB listener 注册 + 数据注入 + 能力枚举。报告已写好: `parcel-mismatch-scan/poc-v464-ranging/` |

## 待验证

| ID | 漏洞 | 优先级 | 备注 |
|----|------|--------|------|
| NMS-1 | PendingIntent Allowlisting 授予外部 PI 后台权限 | High | confused deputy, BAL bypass |
| V-349 (深入) | Controls Cross-User with Work Profile | Medium | 需要 work profile 环境 |

## 目录结构

```
poc-phone-id-leak/       — PH-1 (已确认，待提交)
poc-gnss-antenna-leak/   — GPS-1 (已确认，待提交)
poc-nfc-hijack/          — V-451/V-452 (已提交)
poc-deviceconfig-leak/   — V-415 (已提交)
poc-private-space-leak/  — V-344/V-346 (已提交)
poc-credman-impersonate/ — V-395 (确认，待决定是否提交)
poc-settings-crossuser/  — V-436 (已确认，待提交)
poc-a11y-backup-enable/  — V-376/V-377 (已确认，待提交)
poc-mediasession2-leak/  — V-425 (已确认，待提交)
poc-controls-crossuser/  — V-349 (有限确认)
```
