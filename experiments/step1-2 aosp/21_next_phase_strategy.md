# Phase 2 攻击策略：Intent重定向 + Binder权限扩展

**日期**: 2026-04-30
**目标设备**: Pixel 10, Android 16 (CP1A.260405.005)
**前提**: Parcel Mismatch方向已验证为低产出，转向更有效的攻击面

---

## 一、差异化策略：如何不撞洞

### 为什么会撞洞

大多数研究者的工作模式：
1. 看公开CVE → 搜索同类模式 → 提交变种
2. 扫常见关键词（exported, PendingIntent, startActivity）
3. 聚焦老牌服务（PackageManager, ActivityManager, AccountManager）
4. 只看framework.jar + SystemUI

### 我们的差异化定位

| 维度 | 常规研究者 | 我们的策略 |
|------|-----------|-----------|
| 时间线 | 挖Android 14/15已发布代码 | **瞄准Android 16新增代码**（别人还没开始看） |
| 目标 | framework.jar核心服务 | **Mainline APEX模块**（审计密度低10x） |
| 方法 | grep exported/PendingIntent | **Binder onTransact逐条审计**（找遗漏的权限检查） |
| 深度 | 单漏洞报告 | **组合链**（LOW+LOW=HIGH，如V-201+V-202） |
| 面 | 显式攻击面 | **隐式面**（非exported但可通过raw binder transact到达） |

### 三个竞争壁垒

**1. 新代码优先（Fresh Code First）**
- Android 16 新增的 `AppFunctionManager`, `CredentialManager`, `VirtualDeviceManager`
- `com.android.ondevicepersonalization`, `com.android.healthfitness` 等新Mainline模块
- 这些代码2025年才写完，几乎没被审计过

**2. 模块间接缝（Module Seam Bugs）**
- 漏洞常出现在两个模块交互的边界
- 例：Credential Manager调用Autofill Service时的信任边界
- 例：VirtualDevice与正常设备策略之间的隔离失效
- 单模块审计不会发现这类问题

**3. 非标准入口点（Non-obvious Entry Points）**
- 大多数人通过SDK API调用到服务端
- 我们直接通过raw `IBinder.transact()` 到达未经SDK暴露的transaction codes
- 类似V-452：NFC模块没暴露Java API，但Binder接口对所有app可达

---

## 二、Direction A：Intent 重定向审计

### 历史参考

| CVE | 年份 | 模式 | 影响 |
|-----|------|------|------|
| CVE-2020-0389 | 2020 | Settings中从Bundle取Intent并startActivity | LaunchAnyWhere |
| CVE-2021-0928 | 2021 | System UI从通知extra取PendingIntent | EoP |
| CVE-2022-20338 | 2022 | Intent filter绕过 | 沙盒逃逸 |
| CVE-2023-21292 | 2023 | AMS中不可信parcel的Intent取出 | LaunchAnyWhere |
| CVE-2024-0015 | 2024 | AccountManager authenticator response | LaunchAnyWhere |

### 核心模式

```
[恶意app] --Bundle(含恶意Intent)--> [系统服务] --startActivity(恶意Intent)--> [任意Activity]
```

系统服务以system/root身份运行，它启动的Activity继承其权限上下文。如果恶意app能控制系统服务启动哪个Activity，就等于以system身份启动任意组件。

### 重点审计目标

**Tier 1（Android 16新增，审计密度最低）：**
- `CredentialManagerService` — 处理credential请求/响应，包含PendingIntent回调
- `AppFunctionManagerService` — 全新服务，执行app function需要回调
- `VirtualDeviceManagerService` — 管理虚拟设备，有Intent拦截器(IVirtualDeviceIntentInterceptor)
- `OnDevicePersonalizationService` — 设备端AI推理服务

**Tier 2（Mainline模块，独立更新节奏）：**
- Bluetooth `AdapterServiceBinder` — 蓝牙配对/连接Intent处理
- HealthConnect — 健康数据权限授权UI Intent
- DeviceLock — 设备锁定/解锁控制

**Tier 3（经典目标但仍有变种空间）：**
- `NotificationManagerService` — Notification action PendingIntent
- `SliceProvider` — Slice中的PendingIntent
- `CredentialManager + Autofill` 交互边界

### 具体审计方法

1. **在services.jar中搜索 startActivity/startActivityAsUser 调用**
2. **回溯数据流：这些Intent从哪来？是否来自app可控的Bundle/Parcelable？**
3. **检查是否有 intent.setComponent() / intent.setPackage() 限制**
4. **找缺少 sanitizeIntent() 的路径**

### 关键代码位置

```
/tmp/services_dex/classes.dex  — CredentialManagerService
/tmp/services_dex/classes2.dex — AppFunctionAccessService
/tmp/services_dex/classes3.dex — (other services)
/tmp/fw_dex/classes.dex        — ICredentialManager$Stub, IAppFunctionManager$Stub
/tmp/bt_dex/classes.dex        — Bluetooth service binders
```

---

## 三、Direction B：Binder权限检查遗漏扫描

### 已证明的方法论（V-452）

```
1. 从 $Stub.onTransact() 获取所有transaction codes
2. 对每个transaction code，追踪进入实际handler方法
3. 检查handler中是否有 enforceCallingPermission / checkCallingPermission
4. 缺少权限检查的 = 零权限可调用 = 漏洞
```

### 扩展目标

| 模块 | Binder服务名 | 位置 | 预估transaction数 |
|------|-------------|------|-----------------|
| **Bluetooth** | bluetooth_manager | /tmp/bt_dex/ | ~100+ |
| **WiFi** | wifi | /system/framework/wifi-service.jar | ~80+ |
| **UWB** | uwb | APEX module | ~30+ |
| **HealthConnect** | healthconnect | APEX module | ~50+ |
| **DeviceLock** | device_lock | APEX module | ~20+ |
| **CredentialManager** | credential | services.jar | ~15 |
| **AppFunctionManager** | (new) | services.jar | ~10 |
| **OnDevicePersonalization** | ondevicepersonalization_system_service | APEX | ~20+ |

### 自动化扫描脚本需求

编写脚本对每个target service：
1. 提取 `onTransact()` 的所有case分支（transaction codes）
2. 对每个code，提取对应的handler方法名
3. 在handler方法中搜索权限检查关键词：
   - `enforceCallingPermission`
   - `enforceCallingOrSelfPermission`
   - `checkCallingPermission`
   - `checkCallingOrSelfPermission`
   - `enforcePermission`
   - `getCallingUid` + uid比对
   - `Binder.getCallingPid` + pid检查
4. 标记没有任何权限检查的handler为SUSPECT

### 优先级排序

以下模块优先扫描（新+审计少+高价值）：
1. **HealthConnect** — 健康数据是敏感数据，新模块
2. **AppFunctionManager** — 全新Android 16服务
3. **CredentialManager** — 身份认证核心
4. **OnDevicePersonalization** — AI隐私相关
5. **Bluetooth** — 体量大，历史漏洞多

---

## 四、组合攻击思路

### Chain 1: CredentialManager Intent Injection
```
恶意app → ICredentialManager.getCredential(crafted_request) 
→ CredentialManagerService处理请求
→ 构造PendingIntent回调给CredentialProvider
→ 如果PendingIntent的intent字段可控 → LaunchAnyWhere
```

### Chain 2: AppFunction + URI Grant
```
恶意app → IAppFunctionManager.executeAppFunction(crafted_request)
→ AppFunctionService执行
→ 返回结果中包含URI grants
→ 如果URI grant范围未限制 → 读取任意ContentProvider数据
```

### Chain 3: VirtualDevice Policy Bypass
```
恶意app (在VirtualDevice上) 
→ VirtualDevice的策略可能比物理设备宽松
→ 绕过物理设备上的权限限制
→ 通过IVirtualDeviceIntentInterceptor重定向Intent到物理设备Activity
```

### Chain 4: Bluetooth Binder + PendingIntent
```
恶意app → 直接transact到Bluetooth binder
→ 找到无权限检查的配对/连接API
→ 触发配对通知/对话框
→ 对话框中的PendingIntent可能被劫持
```

---

## 五、执行计划

### Phase 2a（本周）: 快速扫描出货

| 任务 | 预计时间 | 输出 |
|------|---------|------|
| 编写Binder权限检查扫描脚本 | 2h | scan_binder_perms.py |
| 扫描CredentialManager所有transactions | 1h | findings |
| 扫描AppFunctionManager | 1h | findings |
| 扫描HealthConnect | 2h | findings |
| 手动验证TOP5 findings | 3h | PoC |

### Phase 2b（下周）: Intent重定向深度审计

| 任务 | 预计时间 | 输出 |
|------|---------|------|
| 提取services.jar中所有startActivity调用点 | 2h | callsite list |
| 对每个调用点做数据流回溯 | 4h | suspect list |
| 重点审计Credential/AppFunction路径 | 4h | findings |
| PoC验证 | 4h | exploit demo |

### Phase 2c（弹性）: Mainline模块横扫

| 任务 | 预计时间 | 输出 |
|------|---------|------|
| Pull所有Mainline APEX DEX | 1h | /tmp/*_dex/ |
| Binder权限扫描全覆盖 | 4h | full report |
| 深度审计TOP findings | 6h | PoC |

---

## 六、工具链

| 工具 | 用途 | 状态 |
|------|------|------|
| dexdump -d | 反汇编DEX bytecode | ✅ 已有 |
| scan_v3.py | Parcel mismatch扫描 | ✅ 完成 |
| scan_binder_perms.py | Binder权限检查扫描 | ❌ 待编写 |
| scan_intent_redirect.py | Intent重定向模式扫描 | ❌ 待编写 |
| adb + raw transact | PoC验证 | ✅ 已验证(NFC) |
| jadx (如需) | 高级反编译 | 可选 |

---

## 七、资产清单

已拉取到本机的分析目标：
- `/tmp/fw_dex/classes{1-6}.dex` — framework.jar (23MB, 2117 Parcelables)
- `/tmp/services_dex/classes{1-3}.dex` — services.jar (23MB, 系统服务实现)
- `/tmp/bt_dex/classes.dex` — Bluetooth mainline (5MB)
- 设备在线: Pixel 10 (58241FDCR001DD)

待拉取：
- WiFi service jar
- HealthConnect APEX
- OnDevicePersonalization APEX
- UWB APEX
- DeviceLock APEX
