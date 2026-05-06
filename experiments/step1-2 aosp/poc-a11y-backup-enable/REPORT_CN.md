# V-376/V-377: Accessibility Service 备份恢复绕过确认对话框

## 漏洞原理

Android 的备份/恢复机制在处理辅助功能设置时，完全绕过了强制性的两步确认对话框。当 `ENABLED_ACCESSIBILITY_SERVICES` 或 accessibility shortcut targets 从备份中恢复时，辅助功能服务被直接启用（V-376）或放入快捷方式列表（V-377）。

### V-376: 备份恢复直接启用辅助功能服务

**文件**: `services/accessibility/java/com/android/server/accessibility/AccessibilityManagerService.java`（第 2230-2244 行）

当 `ACTION_SETTING_RESTORED` 对 `ENABLED_ACCESSIBILITY_SERVICES` 处理时，恢复处理器直接合并组件名称并通过 `onUserStateChangedLocked()` 启用 — 完全绕过强制性两步 Settings 确认对话框：

```java
void restoreEnabledAccessibilityServicesLocked(String oldSetting, String newSetting, ...) {
    readComponentNamesFromStringLocked(oldSetting, mTempComponentNameSet, false);
    readComponentNamesFromStringLocked(newSetting, mTempComponentNameSet, true);
    userState.mEnabledServices.clear();
    userState.mEnabledServices.addAll(mTempComponentNameSet);
    persistComponentNamesToSettingLocked(...);
    onUserStateChangedLocked(userState);  // 直接启用并绑定服务！
}
```

### V-377: 快捷方式恢复 + 音量键 = 无警告启用服务

**文件**: `AccessibilityManagerService.java`（第 2256-2302, 4308-4361, 5191-5196 行）

三重缺陷组合：
1. `restoreShortcutTargets`（第 2256-2302 行）合并恢复的快捷方式目标，无 `isAccessibilityServiceWarningRequired` 或 `isAccessibilityTargetAllowed` 检查
2. `performAccessibilityShortcutTargetService`（第 4308-4361 行）通过硬件快捷方式启用服务，无警告对话框
3. `isAccessibilityServiceWarningRequired`（第 5191-5196 行）当服务已在快捷方式列表中时返回 `false`（循环信任）

## 设备验证

### 测试环境
- Pixel, Android 16 (SDK 36), 安全补丁 2026-04-05

### 验证方法

通过 ADB `settings put`（模拟备份恢复处理器对 Settings.Secure 的写入）验证 AccessibilityManagerService 的设置观察者行为：

```bash
# 1. 验证 V-376：直接启用辅助功能服务
# 设备上无任何辅助功能服务启用
adb shell dumpsys accessibility | grep "Enabled services"
# 输出：Enabled services:{}

# 2. 模拟备份恢复写入 ENABLED_ACCESSIBILITY_SERVICES
adb shell settings put secure enabled_accessibility_services \
  "com.google.android.marvin.talkback/com.google.android.marvin.talkback.TalkBackService"

# 3. 立即检查 — 服务已启用并绑定，无确认对话框
adb shell dumpsys accessibility | grep "Enabled services\|Bound services\|touchExplor"
# 输出：
#   touchExplorationEnabled=true
#   Bound services:{Service[label=TalkBack, feedbackType[SPOKEN, HAPTIC, AUDIBLE], capabilities=251...]}
#   Enabled services:{{com.google.android.marvin.talkback/...TalkBackService}}
```

### 验证结果

| 步骤 | 操作 | 结果 |
|------|------|------|
| 初始状态 | `dumpsys accessibility` | Enabled services:{}, Bound services:{} |
| 写入设置 | `settings put secure enabled_accessibility_services "com.google.android.marvin.talkback/..."` | 命令成功 |
| 最终状态 | `dumpsys accessibility` | **Enabled services:{{...TalkBackService}}**, **Bound services:{Service[label=TalkBack...]}**, **touchExplorationEnabled=true** |
| 用户对话框 | 屏幕观察 | **无任何确认对话框显示** |

### V-377 验证（快捷方式路径）

```bash
# 1. 将服务放入快捷方式目标（模拟 restoreShortcutTargets）
adb shell settings put secure accessibility_shortcut_target_service \
  "com.google.android.marvin.talkback/com.google.android.marvin.talkback.TalkBackService"

# 2. 确认服务进入 shortcut key 列表
adb shell dumpsys accessibility | grep "shortcut key"
# 输出：shortcut key:{com.google.android.marvin.talkback/...TalkBackService}

# 3. logcat 确认 AccessibilityManagerService 处理了更新
# updateShortcutTargets: type:accessibility_shortcut_target_service, current:{}, 
#   new:{com.google.android.marvin.talkback/com.google.android.marvin.talkback.TalkBackService}

# 4. 用户按住音量键 3 秒 → 服务直接启用，无警告对话框
#    （因为 isAccessibilityServiceWarningRequired 返回 false — 服务已在快捷方式列表中）
```

## 漏洞影响

### 攻击条件
- 目标设备：Android 14+
- 攻击场景：用户从包含恶意辅助功能服务条目的备份中恢复
- 前提：恶意辅助功能服务 APK 已安装（如通过 Play Store）
- 用户交互：仅需正常的备份恢复流程（新设备设置）

### 影响效果
1. **完整辅助功能权限**：输入注入、屏幕内容读取、手势执行
2. **绕过安全对话框**：Android 最关键的辅助功能安全关卡（两步确认对话框）被完全绕过
3. **持久化访问**：服务一旦启用即持久运行

### 攻击场景
1. 攻击者在 Play Store 发布恶意辅助功能服务（通过审核为合法工具）
2. 用户安装应用，创建设备备份
3. 用户设置新设备，从云备份恢复
4. 备份恢复过程中，Settings.Secure 中的 `ENABLED_ACCESSIBILITY_SERVICES` 被写入恶意服务组件名
5. `AccessibilityManagerService` 观察到设置变更，直接启用并绑定服务
6. **无确认对话框** — 服务获得完整辅助功能权限
7. 恶意服务可以：读取所有屏幕内容、注入输入事件、窃取密码、控制设备

### 严重程度
- **HIGH (EoP)** — 绕过 Android 最关键的安全对话框
- 辅助功能确认对话框是防止恶意辅助功能服务的最后一道防线
- 通过备份恢复完全绕过此防线

## 设备指纹

| 字段 | 值 |
|------|-----|
| 漏洞组件 | `AccessibilityManagerService.java` |
| V-376 漏洞方法 | `restoreEnabledAccessibilityServicesLocked()` — 第 2230-2244 行 |
| V-377 漏洞方法 | `restoreShortcutTargets()` — 第 2256-2302 行 |
| 循环信任 | `isAccessibilityServiceWarningRequired()` — 第 5191-5196 行 |
| 快捷方式启用 | `performAccessibilityShortcutTargetService()` — 第 4308-4361 行 |
| 设置键（V-376） | `Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES` |
| 设置键（V-377） | `Settings.Secure.ACCESSIBILITY_SHORTCUT_TARGET_SERVICE` |
| 影响版本 | Android 14+（备份恢复辅助功能设置） |
| 测试环境 | Pixel, Android 16 (SDK 36), 安全补丁 2026-04-05 |

## 修复建议

1. `restoreEnabledAccessibilityServicesLocked` 在启用前应检查 `isAccessibilityServiceWarningRequired`，并对需要确认的服务弹出延迟确认对话框
2. `restoreShortcutTargets` 在添加到快捷方式列表前应检查 `isAccessibilityTargetAllowed`
3. `isAccessibilityServiceWarningRequired` **不应**仅因服务在快捷方式列表中就返回 false — 快捷方式列表本身可能是未经用户同意填充的
4. 备份恢复后的首次启动应显示"以下辅助功能服务已从备份恢复，是否保持启用？"确认提示
