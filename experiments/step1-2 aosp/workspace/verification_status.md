# AOSP Vulnerability Verification Status

> Last updated: 2026-04-28
> Total candidates: 85 (V-1 ~ V-85)
> Prioritized for verification: 29

---

## Status Legend

| Symbol | Meaning |
|--------|---------|
| `[ ]` | Pending — not yet verified |
| `[~]` | In Progress — actively verifying |
| `[✓]` | Confirmed — exploitable, ready for VRP submission |
| `[✗]` | Rejected — not exploitable / mitigated / dupe |
| `[?]` | Partial — needs more investigation |

---

## P0 — Immediate Verification (EoP, clearest exploit chains)

| # | Vuln ID | Name | Type | Status | Device | Patch Level | Notes |
|---|---------|------|------|--------|--------|-------------|-------|
| 1 | V-8 | PackageArchiver EXTRA_INTENT system launch | EoP | `[?]` | Pixel 10 | 2026-04-05 | 代码缺陷真实,但 Binder 获取路径受限(隐式Intent被系统app优先接收) |
| 2 | V-49+V-50 | SearchResultTrampoline → SubSettings fragment injection | EoP | `[✗]` | Pixel 10 | 2026-04-05 | verifyLaunchSearchResultPageCaller() 有效拦截,SignatureVerifier 白名单阻断 |
| 3 | V-67 | AppOpsService virtual device bypass all restrictions | EoP | `[?]` | Pixel 10 | 2026-04-05 | 代码缺陷真实,但假VD ID被isValidVirtualDeviceId()拒绝,需要CREATE_VIRTUAL_DEVICE签名权限才能利用 |
| 4 | V-33 | DownloadStorageProvider RawDocumentsHelper path traversal | EoP | `[ ]` | — | — | |
| 5 | V-35 | LauncherAppsService startShortcut identity elevation | EoP | `[ ]` | — | — | |

## P1 — High Priority (EoP, simple preconditions)

| # | Vuln ID | Name | Type | Status | Device | Patch Level | Notes |
|---|---------|------|------|--------|--------|-------------|-------|
| 6 | V-2 | DPMS BAL propagation to Device Admin | EoP | `[ ]` | — | — | |
| 7 | V-20 | ShortcutService Intent no export check | EoP | `[ ]` | — | — | |
| 8 | V-22 | MediaSession tempAllowlist BAL/FGS propagation | EoP | `[ ]` | — | — | |
| 9 | V-34 | VoiceInteractionManagerService Intent injection | EoP | `[ ]` | — | — | |
| 10 | V-1 | isLaunchIntoPip() bypass PINNED check | EoP | `[ ]` | — | — | |
| 11 | V-68 | Profile Owner arbitrary AppOps modification | EoP | `[ ]` | — | — | |
| 12 | V-21 | SliceManager over-grant full authority | EoP | `[ ]` | — | — | |
| 13 | V-53 | AddAccountSettings KEY_INTENT redirect | EoP | `[ ]` | — | — | |

## P2 — High-Value Info Disclosure (zero-permission, simple PoC)

| # | Vuln ID | Name | Type | Status | Device | Patch Level | Notes |
|---|---------|------|------|--------|--------|-------------|-------|
| 14 | V-18+V-19 | RingtonePlayer play()+getTitle() confused deputy | ID+EoP | `[✓]` | Pixel 10 | 2026-04-05 | **已确认** 零权限获取Binder,getTitle()访问contacts/sms/calllog/calendar/downloads全部成功,play()打开联系人照片URI成功 |
| 15 | V-3 | AudioService.hasHapticChannels() URI | ID | `[ ]` | — | — | |
| 16 | V-13 | WifiDisplay MAC address leak | ID | `[ ]` | — | — | |
| 17 | V-37+V-38+V-41 | TelephonyRegistry 3 broadcasts | ID | `[ ]` | — | — | |

## P3 — Medium Priority (complex chains / specific env)

| # | Vuln ID | Name | Type | Status | Device | Patch Level | Notes |
|---|---------|------|------|--------|--------|-------------|-------|
| 18 | V-52 | ChooseLockGeneric$InternalActivity export + password trust | EoP | `[ ]` | — | — | |
| 19 | V-15 | Device Controls trivial lockscreen bypass | EoP | `[ ]` | — | — | |
| 20 | V-74 | NLS Companion Device channel tampering | EoP | `[ ]` | — | — | |
| 21 | V-6/V-26 | SafeActivityOptions FREEFORM no check | EoP | `[ ]` | — | — | |
| 22 | V-4 | CDM disassociation exemption residual | EoP | `[ ]` | — | — | |
| 23 | V-30 | ShortcutService URI revoke user 0 hardcoded | EoP | `[ ]` | — | — | |
| 24 | V-23 | SliceManager cross-user slice access | EoP/ID | `[ ]` | — | — | |
| 25 | V-62 | Persistent App protected broadcast | EoP | `[ ]` | — | — | |
| 26 | V-81 | A11y sendAccessibilityEvent no-perm injection | EoP | `[ ]` | — | — | |
| 27 | V-32 | AccountManager KEY_INTENT (verify current fix) | EoP | `[ ]` | — | — | |
| 28 | V-54 | MainClear no MASTER_CLEAR permission | EoP | `[ ]` | — | — | |
| 29 | V-36 | preventIntentRedirect not enforced | Systemic | `[ ]` | — | — | |

---

## Verification Log

> Append entries here as each vulnerability is verified.

#### V-18+V-19 — 2026-04-29
- **Result**: CONFIRMED
- **Device**: Pixel 10 (frankel), Android 16, patch 2026-04-05, build CP1A.260405.005, user build
- **PoC**: workspace/poc/v-18/QuickTest.java (shell dex), workspace/poc/v-18/QuickTest2.java (extended)
- **复现步骤**:
  1. 编译 QuickTest.java → dex, push 到设备
  2. `adb shell "CLASSPATH=/data/local/tmp/QuickTest.dex app_process / QuickTest"`
  3. 以 shell UID (2000) 运行，零权限
- **确认的能力**:
  - `AudioService.getRingtonePlayer()` 无权限检查，任意进程可获取 IRingtonePlayer Binder
  - `getTitle(uri)` 在以下受保护 provider 上成功调用: contacts, sms, call_log, media, calendar, downloads, telephony, user_dictionary, settings
  - `play(uri)` 成功触发 SystemUI 以自身特权打开 content://com.android.contacts/contacts/1/photo
  - SystemUI 持有 READ_CONTACTS(granted), READ_EXTERNAL_STORAGE(granted), INTERACT_ACROSS_USERS_FULL(granted)
- **信息泄露程度**: getTitle() 返回 URI path segment 而非实际内容名（Ringtone.getTitle 内部查询 title/_display_name 列，非媒体 provider 不返回这些列）。但 play() 的 confused deputy 效果完整——SystemUI 代理访问任意 content:// URI
- **VRP Report**: workspace/vrp-reports/v-18.md

---

#### V-8 — 2026-04-28
- **Result**: Partial (代码缺陷确认，利用路径受限)
- **Device**: Pixel 10, Android 16, patch 2026-04-05
- **PoC**: 未编写 (利用前提不满足)
- **分析详情**:
  - UnarchiveIntentSender.send() 从 EXTRA_INTENT 提取嵌套 Intent，以 system context 启动，无组件/权限校验
  - 但该 Binder 通过隐式 Intent (ACTION_UNARCHIVE_DIALOG) 传递，系统 PackageInstaller priority=1 优先接收
  - 第三方 app 在 Android 16 上无法可靠拦截此隐式 Intent
  - 作为代码质量问题可提交，但无法构造可靠 PoC
- **Blockers**: Binder 引用无法被非特权 app 获取
- **VRP Report**: 暂不提交，降级为 P3 研究项

---

### Template

```
#### V-XX — [date]
- **Result**: Confirmed / Rejected / Partial
- **Device**: Pixel X, Android XX, patch YYYY-MM-DD
- **PoC**: workspace/poc/v-XX/
- **Reproduction steps**: ...
- **Evidence**: (screenshot / logcat path)
- **Blockers**: (if any)
- **VRP Report**: workspace/vrp-reports/v-XX.md (if confirmed)
```

---

*Created: 2026-04-28*
