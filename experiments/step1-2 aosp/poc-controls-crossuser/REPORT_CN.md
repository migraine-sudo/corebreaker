# V-349: SystemUI ControlsRequestReceiver 零权限跨用户 Activity 启动

## 漏洞细节

SystemUI 的 `ControlsRequestReceiver` 是一个**无权限要求的导出广播接收器**。收到广播后，它以 `UserHandle.SYSTEM` 身份启动 `ControlsRequestDialog`，不考虑发送者的用户身份。这允许工作资料或次要用户中的应用在系统用户上下文中触发 activity 启动 — 跨用户 EoP。

**根因**: 接收器对来自攻击者可控 intent 中的 **EXTRA_COMPONENT_NAME** 执行前台检查，而非实际的广播发送者。前台恶意应用只需将 `EXTRA_COMPONENT_NAME` 设为自己的包名，通过检查后触发 `startActivityAsUser(intent, UserHandle.SYSTEM)`。

**源码**: `packages/SystemUI/src/com/android/systemui/controls/management/ControlsRequestReceiver.kt`

```kotlin
// 导出，无 android:permission 属性
override fun onReceive(context: Context, intent: Intent) {
    val componentName = intent.getParcelableExtra(Intent.EXTRA_COMPONENT_NAME, ...)
    val control = intent.getParcelableExtra(ControlsProviderService.EXTRA_CONTROL, ...)

    // 前台检查使用攻击者可控的包名：
    if (isPackageForeground(context, componentName.packageName)) {
        val activityIntent = Intent(context, ControlsRequestDialog::class.java)
        // ... 从调用者复制 extras ...
        context.startActivityAsUser(activityIntent, UserHandle.SYSTEM)  // EoP!
    }
}
```

## 漏洞影响

### 受影响范围
所有支持 SystemUI Controls 的 Android 11+ 设备（设备控件）。该漏洞可从工作资料、次要用户和 Private Space 利用。

### 攻击场景
1. 安装在工作资料（userId=10）中的应用运行在前台
2. 发送广播到 `com.android.systemui/.controls.management.ControlsRequestReceiver`
3. 设置 `EXTRA_COMPONENT_NAME` = 自己的包名（通过前台检查）
4. 可选包含一个伪造的 `Control` 对象（含攻击者可控字符串）
5. SystemUI 以系统用户（userId=0）身份启动 `ControlsRequestDialog`
6. Activity **跨越用户边界**启动 — 工作资料应用触发了系统用户 UI

### 严重程度评估
- **直接影响**: 跨用户 activity 启动（EoP 边界突破）
- **ControlsRequestDialog**: 显示设备控件确认 UI，内含攻击者可控内容（控件标题、副标题、设备类型）
- **潜在升级**: 如果对话框的"添加"动作以系统用户身份执行操作且不重新验证发起者，可进一步 EoP
- **社会工程**: 攻击者可控字符串出现在系统风格对话框中

## 复现步骤

### 环境准备
1. 在测试设备上创建工作资料：
   ```bash
   adb shell pm create-user --profileOf 0 --managed TestWork
   adb shell am start-user <userId>
   ```
2. 在工作资料中安装 PoC APK：
   ```bash
   adb install --user <workUserId> poc-controls.apk
   ```

### 执行
1. 在工作资料中启动 "Controls CrossUser PoC"
2. 点击 "3. Check User Context" — 确认非主用户
3. 点击 "1. Send Broadcast (Basic)" 或 "2. Send with Control Object"
4. 观察: `ControlsRequestDialog` 在系统用户上下文中出现

### 单用户验证（有限）
在主用户上，对话框仍以系统用户身份启动（此时为同一用户）。
通过 logcat 确认：
```bash
adb logcat -s ControlsRequest SystemUI | grep -i "startActivity\|ControlsRequest"
```

**预期（漏洞存在）**: 对话框出现；logcat 显示 activity 以 SYSTEM 身份启动
**预期（已修复）**: SecurityException 或广播被静默丢弃

## Fingerprint

| 字段 | 值 |
|------|-----|
| AOSP 源码 | `packages/SystemUI/src/com/android/systemui/controls/management/ControlsRequestReceiver.kt` |
| 接收器 | `com.android.systemui.controls.management.ControlsRequestReceiver` |
| 导出状态 | `exported="true"`, 无 `android:permission` 属性 |
| 触发方式 | 携带 `Intent.EXTRA_COMPONENT_NAME` Parcelable Extra 的广播 |
| EoP 调用 | `context.startActivityAsUser(activityIntent, UserHandle.SYSTEM)` |
| 前台检查 | `isPackageForeground(context, componentName.packageName)` — 使用攻击者提供的 ComponentName |
| 对话框 | `ControlsRequestDialog`（SystemUI 内部 activity） |
| 额外数据 | `ControlsProviderService.EXTRA_CONTROL`（Parcelable，攻击者可控内容） |
| 影响版本 | Android 11+（设备控件引入） |
| 测试环境 | Pixel, Android 15 |

## 修复建议

1. 为接收器声明添加 `android:permission="android.permission.BIND_CONTROLS"`
2. 验证广播发送者身份与 ComponentName 的包名匹配：
```kotlin
if (componentName.packageName != callerPackageName) {
    Log.w(TAG, "Sender doesn't match component package")
    return
}
```
3. 移除 `UserHandle.SYSTEM` 硬编码 — 使用发送者的用户句柄
