# GPS-1: GnssAntennaInfo 零权限 Listener 注册

## 状态: ✅ 已确认（注册成功，权限检查缺失）

## 设备验证

- Pixel 10, Android 16 (SDK 36), 安全补丁 2026-04-05
- PoC App UID: 10502, **零权限**

## 结果

| API | 预期行为 | 实际行为 |
|-----|---------|---------|
| `registerAntennaInfoListener()` | SecurityException | ✅ **返回 true（注册成功）** |
| `requestLocationUpdates()` (对照) | SecurityException | ✅ SecurityException |
| `registerGnssStatusCallback()` (对照) | SecurityException | ✅ SecurityException |

## 关键日志

```
GnssAntennaLeak: UID: 10502
GnssAntennaLeak: Permissions: NONE (no ACCESS_FINE_LOCATION)
GnssAntennaLeak: [VULN] registerAntennaInfoListener returned TRUE!
GnssAntennaLeak:   → Registered WITHOUT ACCESS_FINE_LOCATION!
GnssAntennaLeak: [EXPECTED] SecurityException: uid 10502 does not have android.permission.ACCESS_COARSE_LOCATION or android.permission.ACCESS_FINE_LOCATION.
GnssAntennaLeak: [EXPECTED] SecurityException for GnssStatus
```

## 影响

- Antenna info 包含：carrier frequency (MHz)、phase center offset、phase center variation corrections、signal gain corrections
- 这些数据可用于：
  1. **设备硬件指纹** — antenna 特性因设备型号而异
  2. **粗略位置推断** — gain pattern 和 phase center 随物理位置/方向变化
  3. **GNSS 干扰检测** — 暴露设备的 GNSS 接收能力
- 绕过 ACCESS_FINE_LOCATION dangerous 权限

## 严重程度

**MEDIUM-HIGH** — 绕过 dangerous 运行时权限，泄露与位置相关的硬件数据

## 对比

同模块中 `registerGnssStatusCallback()` 和 `addNmeaListener()` 都正确要求 ACCESS_FINE_LOCATION。仅 `registerAntennaInfoListener` 遗漏了权限检查。

## 修复建议

在 `GnssManagerService.addGnssAntennaInfoListener()` 中添加：
```java
mContext.enforceCallingPermission(
    Manifest.permission.ACCESS_FINE_LOCATION,
    "registerAntennaInfoListener");
```

## 注意

Callback 数据需要在室外有 GNSS 信号时才会触发。但权限检查缺失的事实在注册阶段就已确认。
