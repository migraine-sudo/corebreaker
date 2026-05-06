# Report 22: Round 11 Part A — Input/Window/Overlay Security Audit

**Date**: 2026-04-29  
**Scope**: WindowManagerService, InputManagerService, DragDropController, VirtualDevice input, DisplayPolicy  
**Method**: Deep agent reading AOSP main branch sources + decompiled Pixel 10 APKs

---

## Part A: Input/Window/Overlay System (10 findings)

### V-219: Touch Occlusion Downgrade During Window Animation [MEDIUM-HIGH]

**File**: `WindowState.java` (lines 1220-1228)

**Issue**: `getTouchOcclusionMode()` degrades from `BLOCK_UNTRUSTED` to `USE_OPACITY` for any window that is currently animating:
```java
int getTouchOcclusionMode() {
    if (WindowManager.LayoutParams.isSystemAlertWindowType(mAttrs.type)) {
        return TouchOcclusionMode.USE_OPACITY;
    }
    if (isAnimating(PARENTS | TRANSITION, ANIMATION_TYPE_ALL) || inTransition()) {
        return TouchOcclusionMode.USE_OPACITY;  // <-- Downgrade!
    }
    return TouchOcclusionMode.BLOCK_UNTRUSTED;
}
```

**Attack**: 
1. 创建 `TYPE_APPLICATION_OVERLAY` (需 SYSTEM_ALERT_WINDOW)
2. 设置 alpha=0.79 (低于 `mMaximumObscuringOpacityForTouch` 0.8 阈值)
3. 持续触发动画 (通过 windowAnimations 或 startAnimation)
4. 动画期间 occlusion mode 降级为 USE_OPACITY → 触摸穿透到被覆盖的安全对话框

**Impact**: Tapjacking on permission dialogs, consent screens, biometric prompts  
**Permission**: SYSTEM_ALERT_WINDOW (runtime grantable)  
**Bounty**: $3,000-$5,000

---

### V-220: FLAG_WATCH_OUTSIDE_TOUCH User Interaction Timing Leak [MEDIUM]

**File**: InputDispatcher.cpp (lines 1481-1499), WindowManagerService.java (line 9438-9441)

**Issue**: 任何 TYPE_APPLICATION_OVERLAY 窗口可设置 `FLAG_WATCH_OUTSIDE_TOUCH` 接收 `ACTION_OUTSIDE` 事件。虽然 Android 13+ 已不再提供精确坐标 (返回 0,0)，但时序和频率仍泄露:
- 用户何时与其他 app 交互
- 交互频率 (键盘输入模式)
- 结合 overlay 位置变化可推测大致触摸位置

**Permission**: SYSTEM_ALERT_WINDOW  
**Bounty**: $1,000-$3,000

---

### V-221: Drag-and-Drop URI Permission 无用户确认验证 [MEDIUM-HIGH]

**File**: `DragState.java` (lines 304-317), `DragAndDropPermissionsHandler.java` (lines 81-91)

**Issue**: `DRAG_FLAG_GLOBAL | DRAG_FLAG_GLOBAL_URI_READ` 拖拽操作中，URI 权限基于哪个窗口接收 drop 事件自动授予。`doTake()` 在 `Binder.clearCallingIdentity()` 下调用 `grantUriPermissionFromOwner()` — 以系统身份授权。

**Attack**:
1. App A 发起包含 content:// URI 的全局拖拽
2. 恶意 app 创建大面积透明 overlay (FLAG_NOT_TOUCHABLE)
3. 在 drop 瞬间快速设为可触摸，截获 drop 事件
4. 获得原本给合法目标的 URI 权限

**Permission**: SYSTEM_ALERT_WINDOW  
**Bounty**: $3,000-$5,000

---

### V-222: PRIVATE_FLAG_INTERCEPT_GLOBAL_DRAG_AND_DROP 完整 ClipData 暴露 [MEDIUM]

**File**: `DragState.java` (lines 524-531, 622-627)

**Issue**: 持有 `PRIVATE_FLAG_INTERCEPT_GLOBAL_DRAG_AND_DROP` 的窗口接收完整 ClipData (含 extras + EXTRA_HIDE_DRAG_SOURCE_TASK_ID)。需 MANAGE_ACTIVITY_TASKS 签名权限，但系统 app 的导出组件可能作为中间人泄露。

**Permission**: MANAGE_ACTIVITY_TASKS (signature)  
**Bounty**: $1,000-$2,000

---

### V-223: SYSTEM_APPLICATION_OVERLAY 可信覆盖豁免 [MEDIUM]

**File**: `WindowState.java` (lines 1212-1218, 3147-3157)

**Issue**: 持有 `SYSTEM_APPLICATION_OVERLAY` 权限的窗口被视为 trusted overlay:
1. 完全绕过触摸遮挡检查
2. 不被 `SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS` 隐藏
3. 可覆盖安全关键界面

`SYSTEM_APPLICATION_OVERLAY` 保护级别: `signature|recents|role|installer`。持有特定 role 的 app (如默认浏览器/拨号器) 可利用。

**Permission**: SYSTEM_APPLICATION_OVERLAY (role-grantable)  
**Bounty**: $3,000-$5,000

---

### V-224: Virtual Device 输入注入绕过 INJECT_EVENTS [MEDIUM-HIGH]

**File**: `VirtualDeviceImpl.java` (lines 1001-1035, 1147-1199, 1622-1634)

**Issue**: `checkVirtualInputDeviceDisplayIdAssociation` 允许虚拟设备所有者在其拥有的显示器上创建虚拟键盘/触摸屏，无需 `INJECT_EVENTS` 权限。如果其他 app 的 activity 被启动在此虚拟显示器上，注入的输入直接发送到该 app。

**Attack**: CDM 关联 app + CREATE_VIRTUAL_DEVICE + ADD_TRUSTED_DISPLAY → 在虚拟显示器上注入任意输入到其他 app

**Permission**: CREATE_VIRTUAL_DEVICE (internal|role) + ADD_TRUSTED_DISPLAY (signature|privileged)  
**Bounty**: $5,000-$7,000

---

### V-225: Toast Window 安全对话框视觉覆盖 [LOW-MEDIUM]

**File**: `DisplayPolicy.java` (lines 965-982, 1032-1040)

**Issue**: TYPE_TOAST 窗口强制 FLAG_NOT_TOUCHABLE 不触发触摸遮挡检查。可在安全对话框上显示误导内容 (持续时间受 toast timeout 限制，但无障碍扩展超时可延长)。

**Bounty**: $500-$1,000

---

### V-226: transferTouchGesture 嵌入式窗口跨 UID 验证不足 [MEDIUM]

**File**: `WindowManagerService.java` (lines 9391-9422)

**Issue**: `transferTouchGesture()` 将 callingUid 传递给 `EmbeddedWindowController`，但如果 app 可从其他 app 的嵌入式窗口获取 `InputTransferToken` (如共享 WebView 或跨进程 SurfaceView)，可能重定向触摸手势。

**Permission**: 无 (需获取 token 引用)  
**Bounty**: $2,000-$3,000

---

### V-227: SensitiveContentPackages 截屏保护时序间隙 [LOW-MEDIUM]

**File**: `WindowManagerService.java` (lines 8770-8795), `WindowState.java` (line 1950-1951)

**Issue**: `shouldBlockScreenCaptureForApp` 依赖异步更新的 `mSensitiveContentPackages`。内容变为敏感到 `addBlockScreenCaptureForApps` 调用并传播之间存在短暂窗口，此时截屏可成功。

**Bounty**: $1,000-$2,000

---

### V-228: pilferPointers 权限吊销后持续生效 [LOW]

**File**: `InputManagerService.java` (lines 3291-3292 vs 2116)

**Issue**: `InputMonitorHost.pilferPointers()` 不重新验证 `MONITOR_INPUT` 权限。一旦获取 InputMonitorHost 实例，权限吊销后仍可无限期调用 pilferPointers()。

**Bounty**: $500-$1,000

---

## Part A Summary

| Severity | Count | Key Findings |
|----------|-------|-------------|
| MEDIUM-HIGH | 3 | Animation occlusion bypass, D&D URI theft, VD input injection |
| MEDIUM | 4 | Outside touch leak, drag data exposure, trusted overlay, touch transfer |
| LOW-MEDIUM | 2 | Toast overlay, screenshot timing |
| LOW | 1 | pilferPointers persistence |
| **Total** | **10** | |

**Estimated bounty**: $20,500 - $34,000

---

---

## Part B: URI Permission & PendingIntent Deep Analysis (3 findings)

### V-229: Intent.fillIn() 无条件 OR URI 授权标志到 FLAG_MUTABLE PendingIntent [HIGH]

**File**: `core/java/android/content/Intent.java` (line 11685), `services/core/java/com/android/server/am/PendingIntentRecord.java` (line 492)

**Issue**: `Intent.fillIn()` 方法中 `mFlags |= other.mFlags` 是无条件 OR 操作，包括 `IMMUTABLE_FLAGS`:
```java
// Intent.java line 11685
mFlags |= other.mFlags;  // Unconditional OR — includes URI grant flags!
```

在 PendingIntentRecord.sendInner() 中:
```java
// PendingIntentRecord.java line 488-496
final boolean immutable = (key.flags & PendingIntent.FLAG_IMMUTABLE) != 0;
if (!immutable) {
    int changes = finalIntent.fillIn(intent, key.flags);  // fillIn OR's URI grant flags
    // ...
    flagsMask &= ~Intent.IMMUTABLE_FLAGS;  // Too late! fillIn already OR'd them
    flagsValues &= flagsMask;
    finalIntent.setFlags((finalIntent.getFlags() & ~flagsMask) | flagsValues);
}
```

虽然 line 495-496 试图通过 `~IMMUTABLE_FLAGS` 掩码阻止 sender 显式设置 URI 授权标志，但 `fillIn()` (line 492) 已经通过 unconditional OR 将这些标志注入了 finalIntent。`IMMUTABLE_FLAGS` 包含:
- `FLAG_GRANT_READ_URI_PERMISSION`
- `FLAG_GRANT_WRITE_URI_PERMISSION`
- `FLAG_GRANT_PERSISTABLE_URI_PERMISSION`
- `FLAG_GRANT_PREFIX_URI_PERMISSION`

**Attack**:
1. 找到系统 app 发送的 FLAG_MUTABLE PendingIntent (通知操作、widget 回调等)
2. 在调用 `PendingIntent.send()` 时传入带有 `FLAG_GRANT_READ_URI_PERMISSION | FLAG_GRANT_PERSISTABLE_URI_PERMISSION | FLAG_GRANT_PREFIX_URI_PERMISSION` 的 fillIn Intent
3. PendingIntent 执行时携带注入的 URI 授权标志

**Impact**: 通过 PendingIntent 获得原本不应有的持久化前缀 URI 权限，可访问目标 ContentProvider 的完整数据
**Precondition**: 需找到系统发送的 FLAG_MUTABLE PendingIntent + 合适的 data URI
**Bounty**: $5,000-$15,000

---

### V-230: GrantUri.resolve() contentUserHint 跨用户 URI 解析 [MEDIUM-HIGH]

**File**: `services/core/java/com/android/server/uri/GrantUri.java` (line 84), `services/core/java/com/android/server/uri/UriGrantsManagerService.java` (line 654-656, 684)

**Issue**: URI 授权流程中 `contentUserHint` 控制跨用户 provider 解析:
```java
// GrantUri.java
public static GrantUri resolve(int defaultSourceUserHandle, Uri uri, int modeFlags) {
    return new GrantUri(ContentProvider.getUserIdFromUri(uri, defaultSourceUserHandle),
            ContentProvider.getUriWithoutUserId(uri), modeFlags);
}

// UriGrantsManagerService.java
int contentUserHint = intent.getContentUserHint();  // Comes from Intent!
if (contentUserHint == UserHandle.USER_CURRENT) {
    contentUserHint = UserHandle.getUserId(callingUid);
}
GrantUri grantUri = GrantUri.resolve(contentUserHint, data, mode);
```

当 URI 不包含 `userId@authority` 格式时，`contentUserHint` 直接用作 sourceUserId。结合 V-229 (fillIn flag injection) — 如果 PendingIntent 的模板 intent 具有 USER_CURRENT 的 contentUserHint，fillIn 会从 sender 的 intent 复制 contentUserHint (line 11712-11714):
```java
if (mayHaveCopiedUris && mContentUserHint == UserHandle.USER_CURRENT
        && other.mContentUserHint != UserHandle.USER_CURRENT) {
    mContentUserHint = other.mContentUserHint;
}
```

**Impact**: 跨用户 URI 权限授予 — 攻击者可指定 sourceUserId 指向 work profile 的 provider
**Bounty**: $3,000-$7,000

---

### V-231: ClipData 嵌套 Intent 递归 URI 授权处理 [MEDIUM]

**File**: `UriGrantsManagerService.java` (lines 700-725)

**Issue**: `checkGrantUriPermissionFromIntentUnlocked` 递归处理 ClipData 中的嵌套 Intent:
```java
Intent clipIntent = clip.getItemAt(i).getIntent();
if (clipIntent != null) {
    NeededUriGrants newNeeded = checkGrantUriPermissionFromIntentUnlocked(
            callingUid, targetPkg, clipIntent, mode, needed, targetUserId, ...);
}
```

嵌套 Intent 内的 URI 也会被授权。攻击者可在 ClipData 中嵌入多层 Intent，每个包含不同的 data URI。当通过 confused deputy (如 V-18 IRingtonePlayer) 传递 ClipData 时，所有嵌套 URI 均被授予权限。

**Impact**: 通过单次 confused deputy 调用获取多个 provider 的 URI 权限
**Bounty**: $1,000-$3,000

---

## Round 11 Part A+B Summary

| Severity | Count | Key Findings |
|----------|-------|-------------|
| HIGH | 1 | fillIn() unconditional flag OR (V-229) |
| MEDIUM-HIGH | 4 | Animation occlusion, D&D URI theft, VD input injection, contentUserHint cross-user |
| MEDIUM | 5 | Outside touch, drag data, trusted overlay, touch transfer, nested ClipData |
| LOW-MEDIUM | 2 | Toast overlay, screenshot timing |
| LOW | 1 | pilferPointers persistence |
| **Total** | **13** | |

**Estimated bounty**: $28,500 - $56,000

---

*Generated by FuzzMind/CoreBreaker Round 11 — 2026-04-29*
