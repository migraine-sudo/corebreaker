# AOSP 代码审计进度与覆盖率报告

> 截止日期: 2026-04-28
> 项目: CoreBreaker / step1-2 AOSP Framework & System 审计

---

## 一、总体进度

| 指标 | 数值 |
|------|------|
| 审计报告数 | 9 (01~09) |
| 扫描攻击方向数 | 20+ |
| 审计服务/组件数 | 36 |
| 发现潜在变体总数 | 48 |
| HIGH 严重度 | 11 |
| MEDIUM-HIGH | 10 |
| MEDIUM | 14 |
| LOW-MEDIUM / LOW | 13 |
| 总赏金预估 | $100,000 - $250,000+ |
| Tier 1 可直接提交 | 11 个 |

---

## 二、已审计模块详情

### 2.1 services/core/java/com/android/server/ (系统服务核心) — 覆盖率 ~65%

| 模块 | 审计深度 | 产出 | 防御评估 |
|------|---------|------|---------|
| AudioService | 深度 (URI 处理) | V-3 confused deputy | 弱 |
| wm/SafeActivityOptions | 完整逐字段 | V-1, V-6, V-26 参数遗漏 | 弱 |
| wm/ActivityStarter | 深度 (BAL/Intent) | V-36 preventIntentRedirect 缺口 | 中等 |
| wm/ActivityTaskManagerService | 深度 (跨用户) | 跨用户检查一致 | 较强 |
| pm/PackageArchiver | 完整 | V-8 LaunchAnyWhere (HIGH) | 极弱 |
| pm/ShortcutService | 完整 | V-20 Intent 不校验导出, V-30 URI 撤销 | 弱 |
| pm/LauncherAppsService | 深度 | V-35 身份提升+非导出访问 | 弱 |
| pm/PackageInstallerSession | 部分 (PI) | V-40 强制 FLAG_MUTABLE | 中等 |
| pm/BroadcastHelper | 广播扫描 | 包生命周期广播无权限 | 中等 |
| media/MediaSessionService | 深度 (BAL 传播) | V-22 tempAllowlist BAL/FGS | 中等 |
| slice/SliceManagerService | 完整 | V-21 过度授权, V-23 跨用户 | 弱 |
| tv/TvInputManagerService | 完整 | V-9 无权限广播, V-27 parental 泄露 | 弱 |
| clipboard/ClipboardService | 完整 | V-25 DoS, V-28 VD 隐私, V-29 竞态 | 中等 |
| display/WifiDisplayAdapter | 广播扫描 | V-13 MAC 泄露 (HIGH) | 弱 |
| telecom/TelecomLoaderService | 完整 | V-24 跨用户 SMS/Dialer | 弱 |
| accounts/AccountManagerService | 部分 (KEY_INTENT) | V-32 历史攻击面, V-42 广播 | 较强 |
| wallpaper/WallpaperManagerService | 深度 | V-31 颜色泄露 + symlink | 中等 |
| biometrics/BiometricService | 深度 (状态机) | 依赖 HAL 信任 | 较强 |
| companion/CDM | 部分 (权限残留) | V-4 exemption 残留 | 中等 |
| devicepolicy/DPMS | 部分 (BAL) | V-2 BAL propagation (HIGH) | 较强(除BAL) |
| notification/NMS | 部分 (PI/URI) | channel URI, NLS 边界 | 较强 |
| voiceinteraction/VIMS | 深度 | V-34 contextual search 注入 | 弱 |
| power/Notifier | 广播扫描 | V-47 Screen ON/OFF instant apps | 中等 |
| am/PendingIntentRecord | 完整 | fillIn/mutable 机制分析 | 较强 |
| am/PendingIntentController | 完整 | mutable implicit PI 追踪 | 较强 |
| am/UserController | 广播扫描 | V-43 USER_STOPPED 泄露 | 中等 |
| StorageManagerService | 广播扫描 | V-16 卷信息泄露 | 中等 |
| TelephonyRegistry | 完整广播 | V-37/38/41 三个高价值泄露 | 极弱 |
| BatteryService | 广播扫描 | V-46 电池遥测 sticky | 中等 |
| UiModeManagerService | 广播扫描 | 车载/桌面模式广播 | 中等 |
| DockObserver | 广播扫描 | V-48 dock state sticky | 中等 |
| location/LocationManagerService | 广播扫描 | MODE_CHANGED 无权限 | 中等 |

### 2.2 packages/SystemUI/ — 覆盖率 ~30%

| 模块 | 审计深度 | 产出 |
|------|---------|------|
| media/RingtonePlayer | **完整逐方法** | V-18/19 confused deputy (HIGH) |
| controls/ControlActionCoordinator | 深度 | V-15 lockscreen bypass |
| statusbar/LocationController | 部分 | V-5 跨用户 GPS |
| communal/WidgetTrampoline | 部分 | V-17 race condition |

### 2.3 packages/providers/ (ContentProvider) — 覆盖率 ~40%

| Provider | 审计深度 | 产出 |
|----------|---------|------|
| DownloadProvider/RawDocumentsHelper | **完整** | V-33 零验证路径穿越 (HIGH) |
| ExternalStorageProvider | 完整 | V-14 buildFile 无 containment |
| MediaProvider | 完整 | 安全 (多层防御) |
| SettingsProvider | 部分 | 安全 |
| ContactsProvider | 部分 | 安全 |
| BugreportStorageProvider | 部分 | 安全 |

### 2.4 core/java/ (Framework 核心类) — 覆盖率 ~20%

| 模块 | 审计深度 | 产出 |
|------|---------|------|
| internal/content/FileSystemProvider | 完整 | V-44 架构性弱点 |
| provider/DocumentsProvider | 深度 | enforceTree 仅 tree URI |
| widget/RemoteViews | 部分 | V-11 Bundle URI 遗漏 |
| content/ContentProvider | 架构分析 | 无默认路径穿越防护 |

### 2.5 packages/modules/ (Mainline 模块) — 覆盖率 ~15%

| 模块 | 审计深度 | 产出 |
|------|---------|------|
| Bluetooth/BondStateMachine | 广播扫描 | V-39 配对 PIN 泄露 |
| Bluetooth/RemoteDevices | 广播扫描 | BT 设备信息泄露 |
| Wifi/ScanRequestProxy | 广播扫描 | 扫描时机泄露 |

### 2.6 packages/apps/ — 覆盖率 0%

**完全未审计**。

---

## 三、覆盖率可视化

```
                     已审计 ◄──────────────────────────────► 未审计

  services/core/     ████████████████████████████░░░░░░░░░░░░  ~65%
  (32 个服务)        [32/~50 服务已触及]

  packages/SystemUI   ██████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░  ~30%
  (4 个子模块)        [4/~15 子模块]

  packages/providers  ████████████████░░░░░░░░░░░░░░░░░░░░░░░  ~40%
  (6 个 Provider)     [6/~12 系统 Provider]

  core/java/          ████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  ~20%
  (4 个核心类)        [4/~20+ 安全相关核心类]

  packages/modules    ██████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  ~15%
  (3 个模块)          [3/~10 Mainline 安全模块]

  packages/apps       ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  ~0%
  (0 个 app)          [0/5+ 系统 app]
```

### 审计深度分布

```
  完整逐方法审计    ████████████████  12 个模块 (33%)
  针对性深度审计    ██████████████    8 个模块  (22%)
  广播模式扫描      ████████████████  10 个模块 (28%)
  部分/架构分析     ██████████        6 个模块  (17%)
```

---

## 四、已扫描攻击方向

| # | 攻击方向 | 状态 | 产出 |
|---|---------|------|------|
| 1 | BAL/WIU/BFSL 权限传播 | ✅ 完成 | V-2, V-22 |
| 2 | URI Confused Deputy | ✅ 完成 | V-3, V-18, V-19 |
| 3 | 跨用户数据泄露 | ✅ 完成 | V-5, V-23, V-24, V-31 |
| 4 | 权限未随解绑撤销 | ✅ 完成 | V-4, V-30 |
| 5 | SafeActivityOptions 参数遗漏 | ✅ 完成 | V-1, V-6, V-26 |
| 6 | Intent 转发 / EXTRA_INTENT | ✅ 完成 | V-8, V-34, V-35 |
| 7 | Binder 方法无权限调用 | ✅ 完成 | V-9, V-27 |
| 8 | ContentProvider 路径穿越 | ✅ 完成 | V-14, V-33, V-44 |
| 9 | Broadcast 无权限泄露 | ✅ 完成 | V-13, V-16, V-37-48 |
| 10 | PendingIntent FLAG_MUTABLE | ✅ 完成 | V-8, V-40 |
| 11 | 隐式 Intent 劫持 | ✅ 完成 | V-20, V-35 |
| 12 | TOCTOU / 竞态条件 | ✅ 完成 | V-17, V-29 |
| 13 | MediaSession BAL/FGS 传播 | ✅ 完成 | V-22 |
| 14 | Slice 权限模型 | ✅ 完成 | V-21, V-23 |
| 15 | Biometric 状态机 | ✅ 完成 | 安全 |
| 16 | Wallpaper 文件处理 | ✅ 完成 | V-31 |
| 17 | Clipboard 隔离模型 | ✅ 完成 | V-25, V-28, V-29 |
| 18 | Telecom 跨用户 | ✅ 完成 | V-24 |
| 19 | Activity 跨用户启动 | ✅ 完成 | 检查一致 |
| 20 | preventIntentRedirect 防御覆盖 | ✅ 完成 | V-36 |

---

## 五、高频出 CVE 但未审计的模块

### Tier 0: 每月稳定出 CVE，未触及

| 模块 | 6 月 CVE 数 | 主要漏洞类型 | 赏金范围 | 审计难度 | 推荐方法 |
|------|------------|-------------|---------|---------|---------|
| **packages/apps/Settings** | ~15 (含子模块) | EoP (权限绕过, Fragment 注入残留) | $3k-$15k | ⭐⭐ 中低 | 代码审计 |
| **packages/modules/Bluetooth** | ~8 (含 RCE) | RCE + EoP (协议解析, 状态机) | $15k-$100k | ⭐⭐⭐⭐ 高 | 协议 Fuzzing + 审计 |
| **packages/modules/Connectivity** | ~6 | EoP (WiFi 状态机, 网络策略) | $5k-$15k | ⭐⭐⭐ 中 | 代码审计 |

### Tier 1: 高频出 CVE，仅做了广播扫描

| 模块 | 当前覆盖 | 未审计攻击面 | 赏金范围 |
|------|---------|-------------|---------|
| **TelephonyRegistry / Telephony** | 仅广播 | 通话状态机、SIM 管理、IMS 协议 | $5k-$15k |
| **notification/NMS (深度)** | 仅 PI/URI | NLS 权限提升, 通知代理, 气泡, 锁屏通知 | $5k-$15k |
| **am/ActivityManagerService** | 仅部分(文件过大截断) | 进程管理, 广播分发, 权限框架, Provider 授权 | $5k-$20k |

### Tier 2: 中频出 CVE，完全未审计

| 模块 | 说明 | 赏金范围 |
|------|------|---------|
| **services/core/.../job/JobSchedulerService** | 调度器权限边界、JobInfo 参数校验 | $3k-$7k |
| **services/core/.../net/NetworkPolicyManagerService** | 网络策略/计费/VPN 旁路 | $3k-$10k |
| **services/core/.../role/RoleManagerService** | 角色授予逻辑、默认 app 切换 | $3k-$7k |
| **services/core/.../app/AppOpsService** | AppOps 绕过, 权限降级 | $3k-$10k |
| **services/core/.../content/ContentService** | 同步框架, 跨 app 数据访问 | $3k-$5k |
| **services/core/.../people/PeopleService** | 对话/联系人/通知排名 | $2k-$5k |
| **services/accessibility/** | 无障碍服务权限提升 | $5k-$15k |
| **packages/SystemUI (大部分)** | QS tiles, Keyguard, Recents, 状态栏 | $3k-$10k |

### Tier 3: 低频但高价值

| 模块 | 说明 | 赏金范围 |
|------|------|---------|
| **packages/modules/Permission** | 运行时权限框架 | $5k-$20k |
| **packages/modules/AppSearch** | 应用数据搜索 (跨 app) | $3k-$7k |
| **packages/modules/HealthFitness** | 健康数据隐私 | $3k-$7k |
| **packages/modules/AdServices** | 广告 ID / 隐私沙盒 | $3k-$10k |
| **packages/modules/OnDevicePersonalization** | 设备端 AI 数据 | $3k-$7k |

---

## 六、未审计攻击方向

| # | 攻击方向 | 关联模块 | 历史 CVE 频率 | 推荐优先级 |
|---|---------|---------|-------------|-----------|
| 1 | **Settings Fragment 注入残留** | packages/apps/Settings | 每季度 1-2 个 | 🔥🔥🔥 |
| 2 | **Bluetooth 协议状态机** | packages/modules/Bluetooth | 每季度 2-3 个(含 Critical) | 🔥🔥🔥🔥 |
| 3 | **WiFi 状态机/热点** | packages/modules/Connectivity | 每季度 1-2 个 | 🔥🔥🔥 |
| 4 | **NLS 权限提升** | notification/NMS | 每季度 1 个 | 🔥🔥 |
| 5 | **无障碍服务权限边界** | services/accessibility | 每季度 1 个 | 🔥🔥 |
| 6 | **ContentProvider SQL 注入** | 各系统 Provider | 低频但真实 | 🔥 |
| 7 | **VPN 数据拦截/绕过** | net/VpnManagerService | 低频 | 🔥 |
| 8 | **DeviceOwner/ProfileOwner 权限边界** | devicepolicy/DPMS 深度 | 低频 | 🔥 |
| 9 | **AppOps 绕过** | app/AppOpsService | 低频但高价值 | 🔥🔥 |
| 10 | **Backup/Restore 数据注入** | backup/BackupManagerService | 低频 | 🔥 |

---

## 七、下一步行动建议

### 立即可做 (不需要额外源码)

1. **提交 Tier 1 漏洞** — V-18, V-3, V-13, V-37 零权限 PoC 在 Pixel 上验证
2. **深挖 NMS** — 当前只做了表面审计, NLS 权限提升方向值得完整审计
3. **深挖 AMS** — 文件过大之前截断了, 需要分段读取完整审计

### 需要拉代码 (独立仓库)

4. **packages/apps/Settings** (~50MB) — 门槛最低的高频 CVE 来源
5. **packages/modules/Bluetooth** (~100MB) — 近端 RCE, 最高赏金
6. **packages/modules/Connectivity** (~80MB) — WiFi/网络栈

### 需要设备

7. **真机验证 TOP 5 漏洞** — Pixel 设备 + 最新补丁级别
8. **Bluetooth fuzzing** — 需要两台设备 + 蓝牙适配器

---

## 八、报告文件索引

```
experiments/step1-2 aosp/
├── 01_attack_surface_panorama.md      # 6 月 CVE 攻击面全景图
├── 02_variant_analysis_v1.md          # V-1 ~ V-7
├── 03_variant_analysis_v2.md          # V-8 ~ V-12
├── 04_poc_guide.md                    # PoC 指南 v1
├── 05_extended_scan_results.md        # V-13 ~ V-17
├── 06_extended_scan_v2.md             # V-18 ~ V-32
├── 07_poc_guide_v2.md                 # PoC 指南 v2
├── 08_comprehensive_audit_final.md    # 全量汇总 (48 个变体)
└── 09_audit_progress_and_coverage.md  # 本文档 (进度与覆盖率)
```

---

*生成时间: 2026-04-28*
*下次审计重点: Settings app + Bluetooth 模块 + NMS 深度*
