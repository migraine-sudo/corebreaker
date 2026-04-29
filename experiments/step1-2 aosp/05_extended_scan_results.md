# AOSP Extended Scan Results (Round 3)

> 4 方向并行扫描: ContentProvider / Settings / Broadcast / Cross-User
> 2026-04-28

---

## 新增候选汇总

| # | 严重度 | 漏洞 | 模块 | 模式 |
|---|--------|------|------|------|
| **V-13** | **HIGH** | WifiDisplayAdapter 广播泄露附近设备 MAC | Display | 无权限广播 |
| **V-14** | **MEDIUM** | ExternalStorageProvider.buildFile() 路径穿越 | Storage | Path traversal |
| **V-15** | **MEDIUM** | Device Controls trivial 控件 lockscreen bypass | SystemUI | Keyguard bypass |
| **V-16** | **MEDIUM** | StorageManagerService 广播泄露卷路径/UUID | Storage | 无权限广播 |
| **V-17** | **LOW-MED** | Widget trampoline 1s 超时竞争绕过 keyguard | SystemUI | TOCTOU |

---

## V-13 (HIGH): WifiDisplayAdapter 广播泄露 MAC 地址

**文件**: `services/core/java/com/android/server/display/WifiDisplayAdapter.java:446`

```java
getContext().sendBroadcastAsUser(intent, UserHandle.ALL, null, options.toBundle());
// receiverPermission = null → 任何 app 可接收
```

**泄露内容**:
- `DisplayManager.ACTION_WIFI_DISPLAY_STATUS_CHANGED`
- Extras: `WifiDisplayStatus` 含 `WifiDisplay[]` 数组
- 每个 WifiDisplay: **设备 MAC 地址** + **设备名称** + 可用性状态

**影响**:
- 无需任何权限即可被动接收
- 泄露附近 WiFi Direct 设备的 MAC 地址 (PII)
- 可用于设备指纹/跟踪/位置推断
- 违反 Android 12+ MAC 地址随机化的隐私保护目标

**PoC**:
```java
registerReceiver(new BroadcastReceiver() {
    @Override
    public void onReceive(Context context, Intent intent) {
        WifiDisplayStatus status = intent.getParcelableExtra(
            DisplayManager.EXTRA_WIFI_DISPLAY_STATUS);
        for (WifiDisplay display : status.getDisplays()) {
            Log.d("PoC", "MAC: " + display.getDeviceAddress() 
                + " Name: " + display.getDeviceName());
        }
    }
}, new IntentFilter(DisplayManager.ACTION_WIFI_DISPLAY_STATUS_CHANGED));
```

**预估赏金**: $3,000 - $7,500 (High ID, PII 泄露)

---

## V-14 (MEDIUM): ExternalStorageProvider.buildFile() 路径穿越

**文件**: `packages/ExternalStorageProvider/src/com/android/externalstorage/ExternalStorageProvider.java:556-578`

```java
private File buildFile(RootInfo root, String docId, boolean mustExist) {
    final String path = docId.substring(splitIndex + 1);
    target = new File(target, path).getCanonicalFile();  // canonicalize
    // ❌ 无 containment check (不验证结果是否仍在 root 下)
    return target;
}
```

**问题**: canonicalize 后不检查路径是否仍在 root 目录内。docId = `primary:../../etc/passwd` 会解析到 `/etc/passwd`。

**缓解因素**: 对于 tree URI，`enforceTree()` → `isChildDocument()` → `FileUtils.contains()` 会阻止。但 **direct document URI** 路径不经过 `enforceTree()`。需要已有的 URI permission grant。

**预估赏金**: $2,000 - $5,000 (需要证明绕过 enforceTree 的路径)

---

## V-15 (MEDIUM): Device Controls Trivial 控件 Lockscreen 执行

**文件**: `packages/SystemUI/src/com/android/systemui/controls/ui/ControlActionCoordinatorImpl.kt:186-206`

```kotlin
fun bouncerOrRun(action: Action) {
    if (action.authIsRequired || !allowTrivialControls) {
        // 需要认证
        dismissKeyguardThenExecute { ... }
    } else {
        // 不需要认证 — 直接在锁屏上执行!
        action.invoke()
    }
}
```

**问题**: 恶意 ControlsProviderService 将控件标记为 "trivial"，在锁屏上执行 PendingIntent 无需解锁。

**利用场景**: 恶意智能家居 app 注册 ControlsProvider → 用户添加到锁屏快捷控件 → 控件执行任意 PendingIntent。

**预估赏金**: $3,000 - $5,000

---

## V-16 (MEDIUM): StorageManagerService 广播泄露卷信息

**文件**: `services/core/java/com/android/server/StorageManagerService.java:794`

```java
mContext.sendBroadcastAsUser(intent, userVol.getOwner());
// 无 receiverPermission
```

**泄露内容**: 
- `MEDIA_MOUNTED` / `MEDIA_UNMOUNTED` actions
- StorageVolume: 挂载路径、UUID、owner userId、primary/removable flags
- `FLAG_RECEIVER_INCLUDE_BACKGROUND` — 后台 app 也收到

**预估赏金**: $1,500 - $3,000

---

## V-17 (LOW-MEDIUM): Widget Trampoline 1s 超时竞争

**文件**: `packages/SystemUI/src/com/android/systemui/communal/domain/interactor/WidgetTrampolineInteractor.kt:112-153`

**问题**: widget 在 glanceable hub 上通过 broadcast trampoline 启动 Activity。系统轮询 200ms 间隔、1s 超时检测。如果 Activity 在 1s 后才启动，keyguard dismiss 检查被跳过。

**利用场景**: 恶意 widget → 收到点击 → 延迟 1.1s → 启动 Activity → 绕过 keyguard 检查。

**预估赏金**: $1,000 - $3,000 (需要用户添加 widget)

---

## 其他扫描结论

### ContentProvider (方向 A)
- SettingsProvider: 安全 (硬编码 URI)
- HeapDumpProvider: 安全 (严格字符白名单)
- MbmsTempFileProvider: 安全 (canonical + startsWith)
- BugreportStorageProvider: 安全 (isValidExtFilename)
- **结论**: frameworks/base 内的系统 Provider 普遍防御良好，ExternalStorageProvider 是唯一有gap的

### Broadcast (方向 D)
- 除 V-13/V-16 外，IME 变更广播泄露键盘组件名、Location 模式变更无权限广播也值得注意
- 但这些多数是 Information Disclosure (赏金较低)

### 跨用户 (方向 F)
- **AOSP 防御非常一致** — 几乎所有服务都用 `handleIncomingUser()` 或 `enforceCrossUserPermission()`
- PeopleService 丢弃返回值是代码质量问题，不是安全漏洞
- **结论**: 跨用户方向已不再是低垂果实

### Settings (方向 B)
- 真正的 Settings app 不在 frameworks/base (需单独拉 `packages/apps/Settings`)
- SystemUI 内的 Settings 交互点（TunerActivity、Device Controls）有一些攻击面
- Fragment injection 的框架层防御 (`isValidFragment()`) 已到位

---

## 全量候选更新 (V-1 ~ V-17)

### Tier 1: 可直接提交 (HIGH, 利用链清晰)

| # | 漏洞 | 赏金预估 |
|---|------|---------|
| V-8 | PackageArchiver EXTRA_INTENT | $10k-$20k |
| V-3 | AudioService URI confused deputy | $5k-$10k |
| V-2 | DPMS BAL propagation | $7.5k-$15k |
| V-1 | isLaunchIntoPip bypass | $5k-$10k |
| V-13 | WifiDisplay MAC 泄露 | $3k-$7.5k |

### Tier 2: 需进一步验证

| # | 漏洞 | 赏金预估 |
|---|------|---------|
| V-10 | RingtonePlayer URI | $5k-$7.5k |
| V-9 | TvInput 无权限广播 | $3k-$7.5k |
| V-15 | Device Controls lockscreen | $3k-$5k |
| V-14 | ExternalStorage 路径穿越 | $2k-$5k |
| V-4 | CDM exemption 残留 | $3k-$5k |
| V-6 | Freeform mode 无校验 | $3k-$7.5k |

### Tier 3: 低赏金 / 辅助

| # | 漏洞 | 赏金预估 |
|---|------|---------|
| V-16 | Storage 广播泄露 | $1.5k-$3k |
| V-5 | 跨用户 GPS 指示器 | $1.5k-$3k |
| V-17 | Widget trampoline race | $1k-$3k |
| V-11 | RemoteViews Bundle URI | $1k-$3k |

### 总计赏金预估: $55,000 - $120,000+ (如果全部接受)

---

## 下一步建议

框架已扫完 8 个方向，产出 17 个候选。建议：

1. **做实 PoC** — 把 V-3, V-8, V-13 在真机上验证
2. **拉 packages/apps/Settings** — 每月稳定出 CVE 的独立仓库 (~50MB)
3. **拉 packages/modules/Bluetooth** — 近端 RCE ($75k+)
4. **拉 packages/modules/Connectivity** — WiFi/网络栈

---

*Report generated: 2026-04-28*
*累计扫描 12 个攻击方向, 发现 17 个潜在未修复变体*
*Tier 1 (5 HIGH) 总预估: $30k-$60k*
