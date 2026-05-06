# Android Framework 高危CVE深度分析报告

> 分析日期: 2026-04-29  
> 涵盖范围: 6个Android Framework高危漏洞的原理、影响及修复方案  
> 数据来源: Android Security Bulletin + AOSP googlesource commit diff

---

## 目录

1. [CVE-2024-34731 — Binder死亡回调UAF竞态条件](#1-cve-2024-34731)
2. [CVE-2024-34737 — PiP画中画速率无限制导致窗口劫持](#2-cve-2024-34737)
3. [CVE-2024-34742 — MDM策略文件逻辑错误删除导致DoS](#3-cve-2024-34742)
4. [CVE-2024-43093 — Unicode规范化绕过路径过滤实现权限提升](#4-cve-2024-43093)
5. [CVE-2025-22431 — AppOps归因标签洪泛导致紧急呼叫阻断](#5-cve-2025-22431)
6. [CVE-2024-49740 — 视觉语音信箱无限资源消耗导致持久DoS](#6-cve-2024-49740)

---

## 1. CVE-2024-34731

### 基本信息

| 字段 | 值 |
|------|------|
| 公告月份 | 2024年8月 (2024-08-01) |
| 漏洞类型 | EoP (权限提升) |
| 严重级别 | High |
| CVSS 3.1 | 7.0 / 7.7 |
| CWE | CWE-362 (竞态条件) |
| 影响版本 | Android 12, 12L, 13, 14 |
| 用户交互 | 不需要 |

### 受影响组件

漏洞横跨**5个独立仓库**的多个原生C++组件:

1. `platform/frameworks/av` — `TranscodingResourcePolicy.cpp`（媒体转码资源策略）
2. `platform/hardware/interfaces` — `Health.cpp`/`LinkedCallback.cpp`（健康HAL）
3. `platform/hardware/interfaces` — `ProtectCallback.cpp`（神经网络HAL）
4. `platform/system/security` — `apc_compat.cpp`（Keystore2确认UI）
5. `platform/system/nfc` — `NfcAdaptation.cc`（NFC适配层）

### 漏洞原理（通俗解释）

想象你在一栋大楼里，有人给你一张名片（指针），名片上写着某个房间号。你可以随时去那个房间找人办事。但问题是——如果那个人搬走了（对象被销毁），房间被别人占用了（内存被重新分配），你拿着旧名片去找人，见到的就不是原来那个人了，你可能被骗去做危险的事情。

**技术层面：**

Android的Binder IPC框架允许注册"死亡回调"——当远程服务进程死亡时，系统会回调通知你。注册方式是：

```cpp
// 有漏洞的代码模式 —— 把this指针当cookie传进去
AIBinder_linkToDeath(binder.get(), mDeathRecipient.get(), 
                     reinterpret_cast<void*>(this));
```

然后死亡回调中：

```cpp
void BinderDiedCallback(void* cookie) {
    auto* owner = reinterpret_cast<SomeClass*>(cookie);
    owner->doSomething();  // 如果对象已经被销毁 = UAF！
}
```

**竞态窗口：**

```
时间线:
t1: 对象A注册自己(this)为死亡回调cookie
t2: 远程Binder服务崩溃，死亡通知被放入队列
t3: 对象A的析构函数被调用，内存被释放
t4: 死亡回调执行，解引用已释放的cookie → Use-After-Free!
```

虽然析构函数中调用了`AIBinder_unlinkToDeath()`来注销，但它和死亡通知的派发之间存在竞态窗口。

### 利用场景

1. 攻击者反复触发目标对象（如TranscodingResourcePolicy）的快速创建和销毁
2. 同时导致远程Binder服务崩溃（如crash resourcemanager HAL进程）
3. 竞态窗口中触发Use-After-Free
4. 如果释放的内存被攻击者控制的数据重新占用（堆喷射/堆布局），死亡回调就会解引用攻击者控制的内容
5. 由于回调在特权进程上下文中执行（system_server、HAL守护进程），可实现本地提权

### 修复方案

修复采用了三种不同策略：

**策略A（全局映射表间接寻址）：** 不再传raw指针作为cookie，而是传一个整数key。全局维护一个加锁的map，死亡回调先查map，找不到说明对象已销毁，安全跳过。

**策略B（weak_ptr + OnUnlinked回调）：** cookie持有weak_ptr，死亡回调中先lock()检查对象是否存活。

**策略C（消除cookie依赖）：** 对于不需要per-instance状态的情况，直接传nullptr。

---

## 2. CVE-2024-34737

### 基本信息

| 字段 | 值 |
|------|------|
| 公告月份 | 2024年8月 (2024-08-01) |
| 漏洞类型 | EoP (权限提升) |
| 严重级别 | High |
| CVSS 3.1 | 7.7 |
| CWE | 逻辑错误 / 资源管理缺失 |
| 影响版本 | Android 12, 12L, 13, 14 |
| Bug ID | A-283103220 |
| 用户交互 | 不需要 |

### 受影响组件

- **文件:** `services/core/java/com/android/server/wm/ActivityClientController.java`
- **功能:** 画中画(PiP)窗口的宽高比设置

### 漏洞原理（通俗解释）

画中画（PiP）是Android的一个功能——比如你在看视频时切换到其他应用，视频会缩小成一个浮动小窗口。这个小窗口的宽高比是可以由应用调整的。

**问题在于：** 系统对"修改PiP宽高比"这个操作**没有任何速率限制**。就好比一个饭店没有限制你按门铃的次数——恶意应用可以在一秒内疯狂调用几千次"修改宽高比"API，每次都让系统重新计算和渲染PiP窗口。

**后果：** 窗口管理器(WindowManager)被洪水般的resize请求淹没，导致：
- PiP窗口完全冻结，用户无法移动
- PiP窗口无法被关闭或拖走
- 这个"僵尸窗口"永久覆盖在其他应用和系统UI之上

### 为什么是"权限提升"？

一个普通应用（无需任何特殊权限），通过这个bug可以：
- 创建一个**持久的、不可消除的覆盖窗口** —— 正常情况下需要`SYSTEM_ALERT_WINDOW`权限
- 这个覆盖窗口可以用于：
  - **钓鱼攻击**：覆盖银行App的登录界面
  - **点击劫持(Tapjacking)**：在权限对话框上覆盖误导性UI
  - **拒绝服务**：让用户无法正常使用手机

### 修复方案

引入`CountQuotaTracker`限速器：

```java
// 每分钟最多60次宽高比修改
SET_PIP_ASPECT_RATIO_LIMIT = 60
SET_PIP_ASPECT_RATIO_TIME_WINDOW_MS = 60_000  // 60秒

// 超过配额直接抛异常
if (quota exceeded) {
    throw new IllegalStateException("Too many PiP aspect ratio change requests.");
}
```

在`enterPictureInPictureMode()`和`setPictureInPictureParams()`两个入口点都加上了配额检查。

---

## 3. CVE-2024-34742

### 基本信息

| 字段 | 值 |
|------|------|
| 公告月份 | 2024年8月 (2024-08-01) |
| 漏洞类型 | DoS (拒绝服务) |
| 严重级别 | High |
| CVSS 3.1 | 5.5 |
| CWE | 逻辑错误 |
| 影响版本 | Android 14 |
| Bug ID | A-335232744 |
| 用户交互 | 需要（从Android 13 QPR3升级触发） |

### 受影响组件

- **文件:** `services/devicepolicy/java/com/android/server/devicepolicy/OwnersData.java`
- **功能:** 设备管理(MDM)策略持久化

### 漏洞原理（通俗解释）

这个bug可以类比为一个"保险柜自毁"问题。

Android的企业设备管理（MDM/EMM）系统会在`device_owner_2.xml`文件中持久化设备所有者信息——谁管理这台设备、安全策略是什么、系统更新计划等等。

系统有一个`shouldWrite()`方法决定"要不要把数据写入文件"：

```java
// 修复前的有漏洞代码
boolean shouldWrite() {
    return (mDeviceOwner != null) || (mSystemUpdatePolicy != null)
            || (mSystemUpdateInfo != null);
}
```

**问题：** 这个方法只检查了3个字段是否为null，但实际上XML文件里还存储了很多其他重要数据（设备Owner类型映射、策略引擎迁移标志、冻结期等）。

**致命逻辑：** 当`shouldWrite()`返回`false`时，系统不是"跳过写入"，而是**删除现有文件**：

```java
if (!shouldWrite()) {
    // "没东西写，删掉文件吧"
    if (mFile.exists()) {
        mFile.delete();  // 关键MDM数据文件被删除！
    }
}
```

**后果链：**
1. 设备从Android 13 QPR3升级到Android 14
2. 迁移过程中，那3个字段恰好都是null（但迁移标志等其他字段有值）
3. `shouldWrite()` → false → 文件被删除
4. 重启后DevicePolicyManagerService找不到文件 → 设备不再被MDM管理
5. 所有企业安全策略、远程擦除能力、合规检查全部失效

### 修复方案

极其简洁——改为无条件写入：

```java
// 修复后
boolean shouldWrite() {
    return true;  // 总是写入，让writeInner()自己处理null字段
}
```

---

## 4. CVE-2024-43093

### 基本信息

| 字段 | 值 |
|------|------|
| 公告月份 | 2025年3月 (2025-03-01) |
| 漏洞类型 | EoP (权限提升) |
| 严重级别 | High |
| CVSS 3.1 | 7.3 |
| CWE | CWE-176 (Unicode编码处理不当) |
| 影响版本 | Android 12, 12L, 13, 14, 15 |
| Bug ID | A-341680936 |
| 在野利用 | **是 — 已被Google和CISA确认** |

### 受影响组件

- **文件:** `packages/ExternalStorageProvider/src/com/android/externalstorage/ExternalStorageProvider.java`
- **函数:** `shouldHideDocument()`

### 漏洞原理（通俗解释）

这是一个非常经典且优雅的绕过手法——**Unicode规范化攻击**。

从Android 11开始，Google通过"分区存储(Scoped Storage)"保护了三个敏感目录，禁止其他应用通过文件管理器访问：
- `Android/data/`（应用私有数据）
- `Android/obb/`（游戏资源包）
- `Android/sandbox/`

系统用一个**正则表达式**来判断路径是否属于这些受保护目录：

```java
// 有漏洞的代码
Pattern PATTERN_RESTRICTED_ANDROID_SUBTREES =
    Pattern.compile("^Android/(?:data|obb|sandbox)(?:/.+)?", CASE_INSENSITIVE);

boolean shouldHideDocument(String documentId) {
    String path = getPathFromDocId(documentId);
    return PATTERN_RESTRICTED_ANDROID_SUBTREES.matcher(path).matches();
}
```

**核心问题：** 正则匹配操作在**字符串层面**进行，而文件系统在**底层**可能对路径进行不同的解析。

**攻击手法：** 利用Unicode中的"同形字"(homoglyphs)或NFC/NFD规范化差异。例如：
- 全角字母 `Ａｎｄｒｏｉｄ` 在正则层面不匹配"Android"
- 但文件系统可能将其规范化为标准ASCII路径
- 或者利用Unicode组合字符，使路径在视觉上和文件系统解析上等同于`Android/data`，但正则无法识别

**结果：** 完全绕过Android 11以来的分区存储保护，可以读写任意应用的私有外部存储数据。

### 利用场景（已在野利用）

1. 恶意应用通过Storage Access Framework（文件选择器）请求访问
2. 构造包含Unicode变体的路径URI
3. `shouldHideDocument()`正则匹配失败，认为"这不是受保护目录"
4. 应用获得对`Android/data/<任意包名>/`的读写权限
5. 可以窃取任何应用的私有数据（凭据、token、数据库、配置文件）

### 修复方案

从"字符串匹配"改为"文件系统身份验证"：

```java
// 修复后 —— 使用inode级别的身份比对
private boolean isRestrictedPath(String rootId, String canonicalPath) {
    List<Path> restrictedPathList = Arrays.asList(
        Paths.get(rootPath, "Android", "data"),
        Paths.get(rootPath, "Android", "obb"),
        Paths.get(rootPath, "Android", "sandbox"));

    Path filePathToCheck = Paths.get(rootPath, canonicalPath);
    while (filePathToCheck != null) {
        for (Path restrictedPath : validRestrictedPathsToCheck) {
            if (Files.isSameFile(restrictedPath, filePathToCheck)) {
                return true;  // 是同一个文件系统对象！
            }
        }
        filePathToCheck = filePathToCheck.getParent();  // 逐级向上检查
    }
    return false;
}
```

`Files.isSameFile()` 比较的是底层inode，完全免疫Unicode编码、路径变体和符号链接攻击。

---

## 5. CVE-2025-22431

### 基本信息

| 字段 | 值 |
|------|------|
| 公告月份 | 2025年4月 (2025-04-01) |
| 漏洞类型 | DoS (拒绝服务) |
| 严重级别 | High (公告) / Medium (CVSS 5.5) |
| CWE | CWE-693 (保护机制失效) |
| 影响版本 | Android 13, 14, 15 |
| Bug ID | b/375623125 |
| 用户交互 | 不需要 |

### 受影响组件

- **文件:** `services/core/java/com/android/server/appop/AppOpsService.java`
- **功能:** Android权限操作(AppOps)跟踪系统

### 漏洞原理（通俗解释）

这个漏洞的后果非常严重——**可以阻止手机拨打紧急电话(如110/119/120)**。

Android的AppOps系统负责跟踪"哪个应用执行了哪些敏感操作"。每次操作都会记录一个"归因标签(attribution tag)"，用来标识是应用的哪个组件发起的操作。

漏洞涉及**三个互相关联的逻辑错误**：

**Bug 1: 代理权限验证缺失**

AppOps允许"代理调用"——应用A代表应用B执行操作。对于系统特殊UID（root、shell、media等），系统无条件信任所有归因标签：

```java
// 有漏洞的代码 —— 只检查被代理方是否是系统UID
// 完全没检查代理方(调用者)是否可信！
if (isSpecialNonAppUid(resolvedUid)) {
    return new PackageVerificationResult(UNRESTRICTED, true);
    // isAttributionTagValid = true，无条件信任
}
```

**问题：** 任何第三方应用都可以声称"我代表root/shell执行操作"，然后提交任意的、未经验证的归因标签。

**Bug 2: 信任链验证不完整**

Attribution Source可以形成链式结构。原代码只验证了链的第一个节点是否可信，后续节点直接放行。

**Bug 3: 限制解除时缺少再验证**

当某个操作限制被解除时，系统无条件恢复所有被暂停的操作，没有检查是否还有其他限制仍然有效。

### 利用场景

1. 恶意应用利用Bug 1，伪装为系统UID的代理
2. 疯狂提交海量伪造的归因标签（每个标签都是唯一的垃圾字符串）
3. AppOps系统为每个(包名, 归因标签)对分配跟踪资源
4. system_server内存被耗尽，或者查询极度缓慢
5. 电话相关的权限检查（`CALL_PHONE`、`READ_PHONE_STATE`）无法正常完成
6. **紧急呼叫无法发起** —— 直到设备重启

### 修复方案

四层防御：

| 修改 | 目的 |
|------|------|
| 新增`proxyUid`参数并检查`isSystemPackage()` | 只有系统应用才能作为可信代理 |
| 验证`attributionSource.getNext()`的信任状态 | 防止信任链中间插入不可信节点 |
| 解除限制前重新调用`isOpRestrictedLocked()` | 确保所有限制都被清除后才恢复操作 |
| `resolveUid`重命名为`resolveNonAppUid` | 代码语义明确化 |

---

## 6. CVE-2024-49740

### 基本信息

| 字段 | 值 |
|------|------|
| 公告月份 | 2025年3月 (2025-03-01) |
| 漏洞类型 | DoS (拒绝服务) |
| 严重级别 | High |
| CVSS 3.1 | 5.5 |
| CWE | CWE-400 (不受控的资源消耗) |
| 影响版本 | Android 12, 12L, 13, 14, 15 |
| Bug ID | A-308932906 |
| 用户交互 | 不需要 |

### 受影响组件

两个文件（分属两个仓库）：
1. `telephony/java/android/telephony/VisualVoicemailSmsFilterSettings.java`（frameworks/base）
2. `src/com/android/phone/PhoneInterfaceManager.java`（packages/services/Telephony）

### 漏洞原理（通俗解释）

这个漏洞就像一个"邮箱炸弹"——往系统的一个存储区域塞入无限量的垃圾数据，直到系统崩溃。

Visual Voicemail（可视语音信箱）是Android的一个电话功能。它有一个SMS过滤设置，包含两个字段：
- `clientPrefix`：一个字符串前缀
- `originatingNumbers`：一个电话号码列表

**两个独立的漏洞：**

**漏洞1 — 无输入大小限制：**

```java
// 修复前 —— 接受任意大小的输入
public Builder setClientPrefix(String clientPrefix) {
    this.clientPrefix = clientPrefix;  // 可以是几百万字符的字符串！
    return this;
}

public Builder setOriginatingNumbers(List<String> originatingNumbers) {
    this.originatingNumbers = originatingNumbers;  // 可以是几万个元素的列表！
    return this;
}
```

这些数据会通过Binder传递到电话服务进程，并被**持久化存储**。

**漏洞2 — 缺少调用者权限验证：**

正常情况下，只有默认拨号应用才能设置Visual Voicemail过滤规则。但代码中遗漏了`enforceVisualVoicemailPackage()`权限检查，导致**任何应用**都能调用这个API。

### 利用场景（持久性DoS/循环崩溃）

1. 恶意应用构造一个超大的`clientPrefix`（比如500MB的字符串）
2. 调用`enableVisualVoicemailSmsFilter()`——由于缺少权限检查，调用成功
3. 超大数据通过Binder发送给电话服务进程，并被持久化到磁盘
4. 电话进程（`com.android.phone`或`system_server`）内存耗尽，崩溃
5. **系统重启后，自动加载持久化的设置数据 → 再次崩溃 → 循环崩溃(Boot Loop)**
6. 设备变砖，需要恢复出厂设置

### 修复方案

双层防御：

**第一层 — 输入验证（frameworks/base）：**

```java
private static final int MAX_STRING_LENGTH = 256;
private static final int MAX_LIST_SIZE = 100;

public Builder setClientPrefix(String clientPrefix) {
    if (clientPrefix != null && clientPrefix.length() > MAX_STRING_LENGTH) {
        throw new IllegalArgumentException("clientPrefix too long");
    }
    // ...
}

public Builder setOriginatingNumbers(List<String> originatingNumbers) {
    if (originatingNumbers != null && originatingNumbers.size() > MAX_LIST_SIZE) {
        throw new IllegalArgumentException("too many originating numbers");
    }
    // 同时检查每个元素长度不超过256
}
```

**第二层 — 权限检查（packages/services/Telephony）：**

```java
// 新增：只有默认拨号器/系统拨号器/运营商语音信箱应用才能调用
enforceVisualVoicemailPackage(callingPackage, subId);
```

---

## 总结与规律

### 漏洞类型分布

| 类型 | 数量 | CVE |
|------|------|-----|
| 缺少速率/大小限制 | 3 | 34737, 22431, 49740 |
| 竞态条件/UAF | 1 | 34731 |
| 路径/字符串验证绕过 | 1 | 43093 |
| 逻辑错误 | 1 | 34742 |

### 共同模式

1. **信任边界问题**：系统API未验证调用者身份（34737无PiP调用限制、49740无拨号器身份验证、22431代理身份未验证）

2. **字符串匹配 vs 语义匹配**：43093使用正则做路径安全检查是反模式——应该使用文件系统级身份验证

3. **无上限资源接受**：49740和22431都是因为系统接受了任意大小/数量的输入而没有限制，导致资源耗尽

4. **原生代码生命周期管理**：34731是经典的C++对象生命周期问题——跨线程共享裸指针而非使用智能指针/间接引用

5. **条件不完整的写入逻辑**：34742的`shouldWrite()`只检查部分字段，遗漏了其他关键数据的存在性

### 对安全研究的启示

- **关注速率限制缺失**：任何允许高频调用的系统API都可能成为DoS向量
- **Unicode/编码变体**：所有基于字符串匹配的安全检查都应考虑编码绕过
- **Binder接口鉴权审计**：检查每个Binder方法是否正确验证了调用者权限
- **持久化数据的输入验证**：接受外部输入并持久化的接口必须有大小限制
- **C++异步回调中的裸指针**：是高价值漏洞狩猎目标

---

*报告结束*
