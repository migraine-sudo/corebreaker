# PH-1: getTypeAllocationCode 零权限设备标识符泄露

## 状态: ✅ 已确认

## 设备验证

- Pixel 10, Android 16 (SDK 36), 安全补丁 2026-04-05
- PoC App UID: 10500, **零权限**

## 结果

| API | 预期行为 | 实际行为 |
|-----|---------|---------|
| `getTypeAllocationCode()` | SecurityException | ✅ **返回 `35815482`** |
| `getTypeAllocationCode(0)` | SecurityException | ✅ **返回 `35815482`** |
| `getManufacturerCode()` | SecurityException | 返回 null (GSM设备不支持) |
| `getImei()` (对照) | SecurityException | ✅ SecurityException |
| `getDeviceId()` (对照) | SecurityException | ✅ SecurityException |

## 关键日志

```
PhoneIdLeak: UID: 10500
PhoneIdLeak: Permissions: NONE
PhoneIdLeak: [VULN] TAC returned: 35815482
PhoneIdLeak:   → This is the first 8 digits of IMEI!
PhoneIdLeak:   → Identifies exact device model/manufacturer
PhoneIdLeak:   → Persistent hardware identifier leaked WITHOUT permission!
PhoneIdLeak: [EXPECTED] SecurityException: getImeiForSlot: The uid 10500 does not meet the requirements to access device identifiers.
```

## 影响

- TAC (Type Allocation Code) = IMEI 前 8 位
- 唯一标识设备型号/制造商/批次
- 对同型号设备具有指纹性（不同型号 TAC 不同）
- 持久性标识符，恢复出厂设置不变
- 零权限零交互即可读取

## 严重程度

**MEDIUM** — 持久设备标识符泄露，但非个人身份信息（TAC标识型号，非个体设备）

## 修复建议

`PhoneInterfaceManager.getTypeAllocationCode()` 应调用 `enforceReadPrivilegedPhoneStatePermissionOrShell()` 或至少 `checkReadPhoneState()`

---

# PH-2: getManufacturerCode

## 状态: ❌ 未确认（返回 null）

GSM 设备不提供 MEID/ManufacturerCode。此漏洞仅影响 CDMA 设备。
