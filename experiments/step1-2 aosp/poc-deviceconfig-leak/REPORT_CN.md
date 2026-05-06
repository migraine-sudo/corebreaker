# V-415: SettingsProvider DeviceConfig 零权限读取 — 系统全量配置泄露

## 漏洞细节

Android 的 `SettingsProvider` 将 `DeviceConfig`（服务端下发的功能开关）暴露给任意已安装应用，服务端未校验 `READ_DEVICE_CONFIG` 权限。

**根因**: `SettingsProvider.call()` 方法处理 `CALL_METHOD_GET_CONFIG`、`CALL_METHOD_LIST_CONFIG`、`CALL_METHOD_LIST_NAMESPACES_CONFIG` 请求时，直接读取配置存储，无任何权限检查。SDK客户端API上的 `@RequiresPermission(READ_DEVICE_CONFIG)` 注解仅为lint编译期警告，运行时无论 ContentProvider 框架还是 SettingsProvider 实现均不执行强制检查。

**源码**: `packages/providers/SettingsProvider/src/com/android/providers/settings/SettingsProvider.java`

```java
// 第 437-440 行 — 返回配置前无权限检查：
case Settings.CALL_METHOD_GET_CONFIG -> {
    Setting setting = getConfigSetting(name);  // 直接读存储
    return packageValueForCallResult(SETTINGS_TYPE_CONFIG, name, requestingUserId, setting, ...);
}
```

`ContentProvider.Transport.call()` 框架路径不会为 `call()` 方法调用执行 AppOps 或读写 URI 权限 — 只有 `query()`、`insert()`、`update()`、`delete()` 受标准框架权限机制保护。

## 漏洞影响

### 受影响范围
所有包含 DeviceConfig 的 Android 设备（Android 10+）。在 Android 15/16（Pixel）上测试通过。

### 攻击场景
1. 安装一个零权限应用（可伪装为任何工具/游戏类应用）
2. 运行时调用 `ContentResolver.call("content://settings", "GET_config", ...)` 读取所有 DeviceConfig 标志
3. 无 SecurityException、无用户提示、无权限要求

### 泄露内容
- **安全功能开关**：BAL 限制、权限中心、增强确认模式、生物特征检查、凭证管理器、设备策略引擎 的启用/禁用状态
- **A/B 测试状态**：内部功能灰度发布比例和条件
- **设备指纹**：各命名空间启用/禁用标志的唯一组合构成持久设备指纹
- **漏洞利用辅助**：得知哪些安全功能被禁用后，攻击者可精确构造后续EoP攻击（例如，若 `bg_activity_starts_enabled=false`，则可确认 BAL bypass 攻击不会被拦截）

### 严重程度
- **信息泄露** → **EoP 辅助** (中高)
- 泄露的信息直接帮助提权攻击，因为它揭示了哪些安全防御处于非激活状态

## 复现步骤

### 最小化验证（ADB，无需安装应用）
```bash
# 读取单个 DeviceConfig 标志：
adb shell content call --uri content://settings --method GET_config --arg "privacy/device_identifier_access_restrictions_enabled"

# 列出所有命名空间：
adb shell content call --uri content://settings --method LIST_NAMESPACES_config

# 导出某命名空间所有标志：
adb shell content call --uri content://settings --method LIST_config --arg "privacy"
```

### 应用验证
1. 编译并安装 `apk/` 项目（manifest 中 ZERO 权限声明）
2. 启动 "DeviceConfig Leak PoC"
3. 点击 "1. List All Namespaces" — 观察返回所有 DeviceConfig 命名空间
4. 点击 "2. Read Security-Critical Flags" — 观察安全功能开关的值
5. 点击 "4. Dump ALL Namespaces" — 观察完整配置导出

**预期结果（漏洞存在）**: 值正常返回，无 SecurityException
**预期结果（已修复）**: 抛出 SecurityException "需要 READ_DEVICE_CONFIG"

## Fingerprint

| 字段 | 值 |
|------|-----|
| AOSP 源码 | `packages/providers/SettingsProvider/src/com/android/providers/settings/SettingsProvider.java` |
| 漏洞方法 | `call()` 中 `CALL_METHOD_GET_CONFIG` 处理 (第437行), `CALL_METHOD_LIST_CONFIG`, `CALL_METHOD_LIST_NAMESPACES_CONFIG` |
| 内部方法 | `getConfigSetting()` (第1169行) |
| 缺失检查 | `enforceHasAtLeastOnePermission()` 或 `checkCallingPermission(READ_DEVICE_CONFIG)` |
| ContentResolver URI | `content://settings` |
| Call Method 字符串 | `"GET_config"`, `"LIST_config"`, `"LIST_namespaces_config"` |
| 应有权限 | `android.permission.READ_DEVICE_CONFIG` (signature\|privileged) |
| 实际强制 | 无（仅客户端lint注解） |
| 影响版本 | Android 10+ (DeviceConfig 引入) 至 Android 16 |
| 测试环境 | Pixel, Android 15 QPR |

## 修复建议

在 `SettingsProvider.call()` 中分发配置读取方法前添加服务端权限检查：

```java
case Settings.CALL_METHOD_GET_CONFIG -> {
    getContext().enforceCallingOrSelfPermission(
        Manifest.permission.READ_DEVICE_CONFIG,
        "getConfig requires READ_DEVICE_CONFIG");
    Setting setting = getConfigSetting(name);
    return packageValueForCallResult(...);
}
```
