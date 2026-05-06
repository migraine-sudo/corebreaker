# V-344/V-346: Private Space 零权限存在性检测与状态监控

## 漏洞原理

Android 15 引入了 **Private Space（隐私空间）**——一种标记为 `PROFILE_API_VISIBILITY_HIDDEN` 的隐藏用户 profile，设计目标是任何第三方应用都无法检测其存在。然而公开 API `UserManager.getProfileIdsWithDisabled()` 在同 profile group 查询时会将 Private Space 的 userId 返回给任何零权限应用。配合 `isUserRunning()` / `isUserUnlocked()` 可实现实时行为监控。

**根因**：Google 实现 Private Space 时为内部调用创建了 `getProfileIdsExcludingHidden()`，但原有的公开 `getProfileIds()` API **未被更新**——它硬编码 `excludeHidden=false`，将隐藏 profile 暴露给任何应用。

**源码**：`services/core/java/com/android/server/pm/UserManagerService.java`

```java
// 第 1568 行 — 公开 API，excludeHidden=false：
public int[] getProfileIds(@UserIdInt int userId, boolean enabledOnly) {
    return getProfileIds(userId, null, enabledOnly, /* excludeHidden */ false);
}

// 第 1666 行 — 内部安全变体：
public int[] getProfileIdsExcludingHidden(@UserIdInt int userId, boolean enabledOnly) {
    return getProfileIds(userId, null, enabledOnly, /* excludeHidden */ true);
}
```

对于同 profile group 的查询，`isUserRunning()` 和 `isUserUnlocked()` 完全跳过权限检查（第 2805 行）：

```java
private void checkManageOrInteractPermissionIfCallerInOtherProfileGroup(...) {
    if (callingUserId == userId || isSameProfileGroupNoChecks(callingUserId, userId)) {
        return;  // 无检查 — Private Space 在同一 profile group 内！
    }
}
```

## 漏洞影响

### 攻击条件
- 目标设备：Android 15+ 且已配置 Private Space
- 攻击者：任意已安装应用，**零权限**（无用户提示、无授权弹窗）
- 安装后无需任何交互

### 影响效果
1. **存在性检测**：任何 app 可发现用户配置了 Private Space（暴露用户在隐藏某些内容的事实）
2. **实时状态监控**：轮询 `isUserRunning()`/`isUserUnlocked()` 可精确获知用户何时打开、解锁、关闭隐私空间
3. **行为模式分析**：记录时间戳可构建活动画像（"受害者在 23:47、02:13 访问隐藏应用..."）

### 无法访问的内容（边界已确认）
- 无法枚举 Private Space 中安装的应用（需要 `INTERACT_ACROSS_USERS` 权限）
- 无法读取 Private Space 内数据（联系人、文件等）
- 无法确定具体隐藏了哪些应用

### 攻击场景：Stalkerware（跟踪软件）
1. 跟踪软件伪装为工具类应用安装（零权限，无用户提示）
2. 调用 `getProfileIdsWithDisabled(0)` → 返回 `[0, 11]` — 检测到 Private Space
3. 每 2 秒轮询 `isUserRunning(UserHandle.of(11))`
4. 检测状态变化：`running=false` → `running=true, unlocked=true` → `running=false`
5. 上报攻击者：受害者每次访问 Private Space 的精确时间

### 严重程度
- **信息泄露** — 完全击败 Android 15 旗舰隐私功能的核心安全保证
- 无需任何权限或用户感知即可实现实时行为监控

## 复现步骤

### 前提条件
- Pixel 设备运行 Android 15+（已在 Android 16 SDK 36 上测试通过）
- 已配置 Private Space（设置 → 安全和隐私 → Private Space）

### 应用验证（最终验证）
1. 编译安装 `apk/` 项目（manifest 中 **零权限** 声明）
2. 启动 "Private Space Leak PoC"
3. 点击 "4. Full Chain (All Steps)"
4. 观察输出：
   - `Profile IDs returned: [0, 11]` — Private Space userId 泄露
   - `running=true, unlocked=true` — 实时状态暴露
5. 锁定 Private Space，再次点击 "4" → 观察到 `running=false`

### 最小化 ADB 验证
```bash
# 确认 Private Space 存在：
adb shell pm list users
# 输出：UserInfo{11:Private space:1010}

# 从 app 上下文（UID 10486，零权限）：
# getProfileIdsWithDisabled(0) 返回 [0, 11]
# isUserRunning(UserHandle.of(11)) 返回 true/false
# isUserUnlocked(UserHandle.of(11)) 返回 true/false
# 全部无 SecurityException
```

**预期结果（漏洞存在）**：Profile IDs 包含 Private Space userId；状态查询返回实际值
**预期结果（已修复）**：仅返回 `[0]`；对隐藏 profile 的状态查询抛出 SecurityException

## 设备指纹

| 字段 | 值 |
|------|-----|
| AOSP 源码 | `services/core/java/com/android/server/pm/UserManagerService.java` |
| 漏洞方法（检测） | `getProfileIds(int, boolean)` — 第 1568 行，硬编码 `excludeHidden=false` |
| 漏洞方法（监控） | `isUserRunning(int)` / `isUserUnlocked(int)` — 第 2578-2587 行 |
| 权限绕过 | `checkManageOrInteractPermissionIfCallerInOtherProfileGroup()` — 第 2805 行，同 profile group 直接返回 |
| 安全变体（公开API未使用） | `getProfileIdsExcludingHidden()` — 第 1666 行 |
| Private Space 用户类型 | `android.os.usertype.profile.PRIVATE` |
| Private Space 可见性 | `PROFILE_API_VISIBILITY_HIDDEN` (0x4) |
| 影响版本 | Android 15+（Private Space 引入）至 Android 16 |
| 测试环境 | Pixel, Android 16 (SDK 36), `UserInfo{11:Private space:1010}` |
| PoC App UID | 10486（普通第三方应用） |
| 所需权限 | 无 |

## 修复建议

`getProfileIds()` 应为非系统调用者过滤隐藏 profile：

```java
public int[] getProfileIds(int userId, boolean enabledOnly) {
    boolean excludeHidden = Binder.getCallingUid() >= Process.FIRST_APPLICATION_UID;
    return getProfileIds(userId, null, enabledOnly, excludeHidden);
}
```

`isUserRunning()`/`isUserUnlocked()` 应对具有 `PROFILE_API_VISIBILITY_HIDDEN` 属性的目标强制要求 `INTERACT_ACROSS_USERS` 权限，无论是否在同一 profile group 内。
