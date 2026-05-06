# V-395: CredentialManager getCandidateCredentials 缺失 enforceCallingPackage

## 漏洞原理

`CredentialManagerService.java` 中的 `getCandidateCredentials()` 方法**未调用** `enforceCallingPackage()` 来验证 `callingPackage` 参数是否与 `Binder.getCallingUid()` 匹配。这允许任何零权限应用伪装成其他包来向凭据提供者请求凭据候选信息。

相比之下，相邻的 `executeGetCredential()` 方法正确地在处理请求前验证了调用者身份。

**根因**：实现 `getCandidateCredentials` 时，开发者使用了 `constructCallingAppInfo(callingPackage, ...)` 构建调用者身份，但遗漏了所有其他凭据相关方法中都有的 `enforceCallingPackage(callingPackage, callingUid)` 检查。

**源码**：`services/credentials/java/com/android/server/credentials/CredentialManagerService.java`

```java
// 第 486-540 行 — getCandidateCredentials：无 enforceCallingPackage()
public ICancellationSignal getCandidateCredentials(
        GetCredentialRequest request,
        IGetCandidateCredentialsCallback callback,
        IBinder clientBinder,
        final String callingPackage) {
    Slog.i(TAG, "starting getCandidateCredentials with callingPackage: " + callingPackage);
    // ... 此处无 enforceCallingPackage(callingPackage, callingUid) ...
    constructCallingAppInfo(callingPackage, userId, request.getOrigin()),  // 第 508 行：使用未验证的包名
    // ...
}

// 第 543-554 行 — executeGetCredential：有 enforceCallingPackage()
public ICancellationSignal executeGetCredential(
        GetCredentialRequest request,
        IGetCredentialCallback callback,
        final String callingPackage) {
    // ...
    enforceCallingPackage(callingPackage, callingUid);  // 第 554 行：验证调用者身份
    // ...
}
```

`enforceCallingPackage` 实现（第 1106 行）：
```java
private void enforceCallingPackage(String callingPackage, int callingUid) {
    int packageUid = pm.getPackageUid(callingPackage, ...);
    if (packageUid != callingUid) {
        throw new SecurityException(callingPackage + " does not belong to uid " + callingUid);
    }
}
```

## 漏洞影响

### 攻击条件
- 目标设备：Android 14+ 且 CredentialManager 已启用
- 攻击者：任意已安装应用，**零权限**（无用户提示、无授权弹窗）
- 安装后无需任何交互

### 影响效果
1. **包名伪装**：任何应用可伪装成其他包（如 Chrome、银行 App）向凭据提供者发起请求
2. **凭据元数据泄露**：凭据提供者（Google 密码管理器）返回目标应用的凭据候选信息（用户名、凭据类型、提供者信息）
3. **钓鱼攻击赋能**：攻击者可获知目标应用保存了哪些网站/服务的凭据，实施精准钓鱼

### 无法访问的内容（边界已确认）
- 无法获取实际密码或通行密钥（需要通过系统 UI 进行用户交互）
- 无法直接执行凭据检索（`executeGetCredential` 有 enforceCallingPackage）

### 攻击场景
1. 恶意应用（零权限）安装到设备
2. 通过 raw Binder transact 调用 `getCandidateCredentials`，`callingPackage="com.android.chrome"`
3. Google 密码管理器收到来自"Chrome"的请求 → 返回 Chrome 的凭据候选列表
4. 攻击者获知：Chrome 中保存了哪些网站的密码、存在哪些账户
5. 攻击者据此构造针对性钓鱼页面

### 严重程度
- **信息泄露 + 权限提升**（身份伪装）
- 无需任何权限即可实现凭据元数据窃取
- 击败 CredentialManager 的包身份验证设计

## 复现步骤

### 前提条件
- Android 14+ 设备且 CredentialManager 已启用（在 Android 16, SDK 36, 安全补丁 2026-04-05 上测试通过）
- 至少配置一个凭据提供者（Google 密码管理器）

### 应用验证（最终验证）
1. 编译安装 `apk/` 项目（manifest 中**零权限**声明）
2. 启动 "CredMan Impersonate PoC"
3. 点击 "4. Full Chain (All Steps)"
4. 检查 logcat 输出 (`adb logcat -s CredManLeak`)：
   - Code 2 SPOOFED → 被 enforceCallingPackage 拦截（executePrepareGetCredential）
   - Code 3 → 服务端接受伪造包名
5. 验证服务端：`adb logcat | grep CredentialManager:`
   - `starting getCandidateCredentials with callingPackage: com.google.android.gms`
   - 未抛出 SecurityException

### 最小化 ADB 验证
```bash
# 1. 安装零权限 PoC
adb install poc-credman.apk

# 2. 运行应用并点击 "4. Full Chain"
adb shell am start -n com.poc.credmanleak/.MainActivity

# 3. 检查服务端日志：
adb logcat | grep "CredentialManager:"
# 预期输出：
#   starting getCandidateCredentials with callingPackage: com.google.android.gms
#   （无 "does not belong to uid" SecurityException）

# 4. 对比受保护方法（executeGetCredential）：
#   starting executeGetCredential with callingPackage: com.google.android.gms
#   → 抛出 SecurityException: com.google.android.gms does not belong to uid 10493
```

### 漏洞对比验证表：
| 方法 | Transaction Code | 伪造包名 | 结果 |
|------|-----------------|----------|------|
| `executePrepareGetCredential` | 2 | com.google.android.gms | **拦截** — enforceCallingPackage |
| `getCandidateCredentials` | 3 | com.google.android.gms | **接受** — 无 enforceCallingPackage |
| `executeGetCredential` | 1 | com.google.android.gms | **拦截** — enforceCallingPackage |

**预期结果（漏洞存在）**：getCandidateCredentials 接受伪造包名；服务端日志显示伪造的包名
**预期结果（已修复）**：方法体执行前即抛出 SecurityException

## 设备指纹

| 字段 | 值 |
|------|-----|
| AOSP 源码 | `services/credentials/java/com/android/server/credentials/CredentialManagerService.java` |
| 漏洞方法 | `getCandidateCredentials(GetCredentialRequest, IGetCandidateCredentialsCallback, IBinder, String)` — 第 486 行 |
| 缺失检查 | 第 486-540 行之间无 `enforceCallingPackage(callingPackage, callingUid)` 调用 |
| 安全对比 1 | `executeGetCredential()` 第 554 行调用 `enforceCallingPackage()` |
| 安全对比 2 | `executePrepareGetCredential()` 第 612 行调用 `enforceCallingPackage()` |
| enforceCallingPackage 实现 | 第 1106-1119 行 — 验证 `pm.getPackageUid(callingPackage) == callingUid` |
| 未验证的使用 | `constructCallingAppInfo(callingPackage, userId, origin)` 第 508 行 |
| AIDL 接口 | `android.credentials.ICredentialManager` |
| Transaction Code | FIRST_CALL_TRANSACTION + 2 (code 3) |
| 影响版本 | Android 14+（CredentialManager 引入）至 Android 16 |
| 测试环境 | Pixel, Android 16 (SDK 36), 安全补丁 2026-04-05 |
| PoC App UID | 10493（普通第三方应用） |
| 所需权限 | 无 |

## 修复建议

在 `getCandidateCredentials` 中使用 `callingPackage` 之前添加 `enforceCallingPackage`：

```java
public ICancellationSignal getCandidateCredentials(
        GetCredentialRequest request,
        IGetCandidateCredentialsCallback callback,
        IBinder clientBinder,
        final String callingPackage) {
    final int callingUid = Binder.getCallingUid();
    enforceCallingPackage(callingPackage, callingUid);  // 添加此行
    // ... 方法其余部分
}
```
