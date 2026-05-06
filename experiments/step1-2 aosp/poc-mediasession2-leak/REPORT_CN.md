# V-425: MediaSession2 零权限 Token 枚举 — 缺失权限检查

## 漏洞原理

`MediaSessionService.java` 中的 `addSession2TokensListener` 没有调用 `enforceMediaPermissions()`，与其 Session1 对应方法 `addSessionsListener` 形成对比。任何同用户应用都可以注册 Session2 Token 监听器和调用 `getSession2Tokens()`，无需任何权限。

**对比**：
- `addSessionsListener`（Session1）→ 要求 `MEDIA_CONTENT_CONTROL` 或 NLS
- `addSession2TokensListener`（Session2）→ **无权限检查**

```java
// 有权限检查 — Session1:
@Override
public void addSessionsListener(IActiveSessionsListener listener, ...) {
    enforceMediaPermissions(componentName, pid, uid, resolvedUserId);  // ← 有检查
    // ...
}

// 无权限检查 — Session2 (V-425):
@Override
public void addSession2TokensListener(ISession2TokensListener listener, int userId) {
    // NO enforceMediaPermissions()!
    synchronized (mLock) {
        mSession2TokensListenerRecords.add(new Session2TokensListenerRecord(listener, resolvedUserId));
    }
}
```

## 设备验证

### 测试环境
- Pixel, Android 16 (SDK 36), 安全补丁 2026-04-05
- PoC App UID: 10495，零权限

### 验证结果

| API | 权限要求 | 实际行为 |
|-----|---------|---------|
| `getActiveSessions()` (Session1) | MEDIA_CONTENT_CONTROL/NLS | ✅ SecurityException: "Missing permission to control media" |
| `addOnSession2TokensChangedListener()` (Session2) | 无 | ❌ 成功，无 SecurityException |
| `getSession2Tokens()` (Session2) | 无 | ❌ 成功，返回 token 列表 |

### 关键日志

```
# 正确保护的 Session1 API:
MediaSession2Leak: [EXPECTED] SecurityException: Missing permission to control media.

# 未保护的 Session2 API:
MediaSession2Leak: [OK] addOnSession2TokensChangedListener succeeded!
MediaSession2Leak:   → NO SecurityException — zero-perm enumeration confirmed!
MediaSession2Leak: [OK] getSession2Tokens returned 0 tokens!
```

## 漏洞影响

### 攻击条件
- 零权限应用，同一用户
- 无需任何特殊权限或用户交互

### 影响效果
1. **应用使用监控**：实时获知哪些应用创建了 MediaSession2（音乐、视频、播客等）
2. **Session2Token 信息泄露**：获取 UID、包名、session 类型
3. **用户行为模式**：通过 session 创建/销毁事件推断用户使用习惯
4. **攻击链启用器**：获取 ISession2Token binder 可能启用进一步交互

### 严重程度
- **MEDIUM (信息泄露 + 监控)** — 零权限应用行为跟踪
- 随着 Media3/Session2 采用增加，影响面持续扩大

## 设备指纹

| 字段 | 值 |
|------|-----|
| 漏洞文件 | `services/core/java/com/android/server/media/MediaSessionService.java` |
| 漏洞方法 | `addSession2TokensListener()` — 第 ~1554-1578 行 |
| 缺失检查 | `enforceMediaPermissions()` |
| 安全对比 | `addSessionsListener()` 有 `enforceMediaPermissions()` |
| 客户端 API | `MediaSessionManager.addOnSession2TokensChangedListener()`, `getSession2Tokens()` |
| 影响版本 | Android 14+ (MediaSession2 引入) |
| 测试环境 | Pixel, Android 16 (SDK 36), 安全补丁 2026-04-05 |

## 修复建议

在 `addSession2TokensListener` 中添加与 `addSessionsListener` 相同的权限检查：

```java
@Override
public void addSession2TokensListener(ISession2TokensListener listener, int userId) {
    final int pid = Binder.getCallingPid();
    final int uid = Binder.getCallingUid();
    enforceMediaPermissions(/* componentName */ null, pid, uid, userId);  // 添加此行
    // ...
}
```
