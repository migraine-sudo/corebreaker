# Safari declarativeNetRequest URL Scheme 重定向绕过 Content Security Policy

## 1. 概要

Safari/WebKit 的 `declarativeNetRequest` API 实现允许扩展通过 `regexSubstitution` 和 `transform.scheme` 字段将子资源请求重定向到任意 URL scheme（包括 `data:`）。与 Chrome 将重定向目标 scheme 限制为 `{http, https, ftp, chrome-extension}` 不同，WebKit 仅阻止 `javascript:` —— 允许 `data:`、`file:`、`blob:` 和自定义 scheme 通过。

这一缺失的限制，结合 Content Security Policy (CSP) 在内容扩展重定向应用**之前**进行评估（且事后不再重新评估）的事实，使得仅具有 `declarativeNetRequest` 权限的恶意扩展能够绕过任意网页的 CSP 并执行任意 JavaScript。

## 2. 安全边界分析

### 2.1 `declarativeNetRequest` 权限边界

`declarativeNetRequest` API 被明确设计为 `webRequest` API 的**低权限**替代方案：

| 属性 | webRequest | declarativeNetRequest |
|------|-----------|----------------------|
| 可读取请求/响应体 | 是 | 否 |
| 可同步修改请求 | 是 | 否 |
| 需要 host_permissions | 是 | **否**（重定向规则不需要） |
| 用户权限提示 | 醒目 | 极简 |
| 设计威胁模型 | "可查看所有浏览活动" | "仅能修改 URL 路由" |

Apple（及整个扩展平台）向用户传达的信息是：仅具有 `declarativeNetRequest` 权限的扩展是**安全的** —— 它们"无法读取页面内容或拦截数据"。用户安装内容拦截器时期望它们没有注入代码的能力。

### 2.2 CSP 安全边界

Content Security Policy 定义了一个按页面的边界，限制哪些来源可以提供可执行内容：

```
Content-Security-Policy: script-src https://cdn.example.com
```

含义：
- ✅ `<script src="https://cdn.example.com/lib.js">` → 允许
- ❌ `<script src="data:text/javascript;base64,...">` → 阻止
- ❌ `<script>内联代码</script>` → 阻止
- ❌ `<script src="https://evil.com/payload.js">` → 阻止

CSP 是**服务端声明的**边界。页面作者信任特定来源，并期望浏览器无论安装了什么扩展都强制执行此策略。

### 2.3 没有此漏洞时攻击者能做什么

仅具有 `declarativeNetRequest` 权限的扩展可以：
- 拦截网络请求（内容拦截）
- 将 HTTP 请求重定向到其他 HTTP/HTTPS URL
- 将 HTTP 升级为 HTTPS（`upgradeScheme`）
- 修改请求头（仅在有 host permissions 时）

扩展**不能**（设计如此）：
- 读取页面内容或 DOM
- 在页面上下文中执行 JavaScript
- 注入 content scripts
- 访问 cookies 或 storage
- 覆盖服务端定义的安全策略（CSP、CORS、X-Frame-Options）

### 2.4 此漏洞启用的能力（权限提升）

利用此漏洞，仅具有 `declarativeNetRequest` 权限的扩展获得：
- **任意 JavaScript 执行** —— 在任意页面的 origin 上下文中
- **CSP 绕过** —— 服务端定义的安全边界被违反
- **Cookie 窃取** —— 通过注入脚本访问 `document.cookie`
- **DOM 操纵** —— 对页面内容的完全读写权限
- **凭据收割** —— 注入虚假登录表单，捕获输入
- **会话劫持** —— 将会话令牌外泄到攻击者服务器

这代表了**权限边界违反**：需要 `scripting` + `<all_urls>` + `host_permissions` 的能力仅通过 `declarativeNetRequest` 就实现了。

### 2.5 为什么这不是"扩展本来就能执行 JS"

一个常见的质疑是："扩展本来就可以执行 JavaScript，所以真正的边界违反在哪里？" 回答这个问题需要理解 Safari 的分层权限模型：

| 权限等级 | 能力 | 用户提示严重程度 |
|---------|------|-----------------|
| `declarativeNetRequest` | 仅 URL 路由 —— 不能读页面，不能执行代码 | 最低（"可以拦截内容"） |
| `scripting` + `host_permissions` | 可向页面注入 content scripts | 醒目（"可以读取和修改 X 上的页面"） |
| `<all_urls>` | 对所有网站的 content script 访问 | 最严重（"可以读取和修改所有页面"） |

**边界违反 #1：扩展模型内的权限提升**

用户安装内容拦截器（仅 `declarativeNetRequest`）时，Safari 告知用户它"无法读取或修改网页内容"。这是平台的安全承诺。此漏洞打破了这一承诺 —— 扩展用一个明确排除代码执行的权限，获得了 `scripting` + `<all_urls>` 级别的能力。

**边界违反 #2：绕过服务端定义的 CSP —— 超越了即使是高权限扩展的能力**

即使是拥有 `scripting` + `<all_urls>` + `host_permissions` 完整权限的扩展，也是通过 **content scripts** 注入代码，而 content scripts 运行在**隔离 world** 中 —— 它们共享 DOM 但拥有独立的 JavaScript 执行上下文。页面的 CSP 不适用于 content scripts，但 content scripts 同样无法直接干扰页面自身的脚本执行上下文。

此漏洞更严重：注入的 `data:` URL 作为 **main world 脚本**执行 —— 它运行在页面自己的 JavaScript 上下文中，可以直接访问页面的变量、闭包和事件处理器。这等同于一个绕过了 CSP 的内联 `<script>`。没有任何合法的扩展机制提供这种级别的访问。

**双重边界违反总结：**

```
正常情况：declarativeNetRequest → 只能路由 URL（不能执行代码）
漏洞：    declarativeNetRequest → 任意 main-world JS 执行 + CSP 绕过

正常情况：scripting + host_permissions → 隔离 world 中的 content script
漏洞：    declarativeNetRequest → main-world 执行（比 content scripts 更强）
```

此漏洞同时跨越了两个边界：它将一个不能执行代码的权限提升为代码执行，并且该执行发生在 main world 而非即使高权限扩展也被限制的隔离 world 中。

## 3. 根因分析

### 3.1 五层缺失的验证

此漏洞存在是因为五个独立的安全层都未能验证重定向目标 URL 的 scheme：

**第1层：WebKit Extensions DNR 解析器** (`_WKWebExtensionDeclarativeNetRequestRule.mm:458`)
```objc
// 仅做类型检查 —— 没有 scheme 白名单
declarativeNetRequestRuleURLTransformScheme: NSString.class,
```

**第2层：WebCore 内容扩展解析器** (`ContentExtensionActions.cpp:499-505`)
```cpp
if (scheme == "javascript"_s)  // 仅阻止 javascript:
    return makeUnexpected(ContentExtensionError::JSONRedirectToJavaScriptURL);
action.scheme = WTF::move(*scheme);  // data:, file:, blob: 全部通过
```

**第3层：regexSubstitution 应用** (`ContentExtensionActions.cpp:471-473`)
```cpp
URL replacementURL(substitution);
if (replacementURL.isValid())        // 完全没有 scheme 验证
    url = WTF::move(replacementURL); // 任何有效 URL 都被接受
```

**第4层：CachedResourceLoader** (`CachedResourceLoader.cpp:1142 vs 1179`)
```cpp
// 第1142行：CSP 检查在内容扩展之前运行
if (!canRequest(type, url, ...))  // url = 原始 HTTP URL → 通过 CSP
    return error;

// ... 37 行之后 ...

// 第1179行：内容扩展将 URL 改为 data:
request.applyResults(WTF::move(results), page.ptr());

// 没有第二次 canRequest() 调用 —— CSP 永远不会被重新检查
```

**第5层：SubresourceLoader** (`SubresourceLoader.cpp:287`)
```cpp
// 此 data: URL 检查仅适用于 HTTP 3xx 服务器重定向
// 内容扩展重定向在请求发送之前发生
if (newRequest.url().protocolIsData() && ...)  // 对 CE 重定向永远不会执行
    cancel(...);
```

### 3.2 Chrome 的防御（WebKit 缺失的部分）

Chrome 在 `extensions/browser/api/declarative_net_request/indexed_rule.cc` 中验证重定向目标 scheme：

```cpp
const char* const kAllowedTransformSchemes[4] = {
    url::kHttpScheme,        // "http"
    url::kHttpsScheme,       // "https"
    url::kFtpScheme,         // "ftp"
    extensions::kExtensionScheme  // "chrome-extension"
};

bool IsValidTransformScheme(const std::optional<std::string>& scheme) {
    for (auto* kAllowedTransformScheme : kAllowedTransformSchemes) {
        if (*scheme == kAllowedTransformScheme)
            return true;
    }
    return false;  // 拒绝 data:, file:, blob: 等
}
```

WebKit 没有等效的验证。

## 4. 攻击链

### 4.1 静态规则攻击

```
┌─────────────────┐     ┌──────────────────────┐     ┌─────────────────┐
│   恶意扩展       │     │  Safari UIProcess     │     │   受害页面        │
│                 │     │  (Content Blocker)    │     │  (bank.com)      │
└────────┬─────────┘     └──────────┬───────────┘     └────────┬─────────┘
         │                          │                           │
         │  安装时仅请求             │                           │
         │  "declarativeNetRequest" │                           │
         │  权限                    │                           │
         │─────────────────────────>│                           │
         │                          │                           │
         │  静态规则:                │                           │
         │  regexFilter: cdn.js     │                           │
         │  → data:text/js;base64   │                           │
         │─────────────────────────>│  编译为 ContentRuleList    │
         │                          │                           │
         │                          │     页面加载 cdn.js        │
         │                          │<──────────────────────────│
         │                          │                           │
         │                          │  1. CSP 检查: cdn.com ✓   │
         │                          │  2. 应用 CE 重定向         │
         │                          │  3. URL → data:...        │
         │                          │  4. 没有第二次 CSP 检查     │
         │                          │                           │
         │                          │  加载 data: URL 作为脚本   │
         │                          │──────────────────────────>│
         │                          │                           │
         │                          │                  攻击者 JS 在
         │                          │                  bank.com origin 执行
         │                          │                           │
```

### 4.2 动态规则逃避

1. 扩展以 `declarativeNetRequest` 权限和空/良性规则发布到 App Store
2. 通过 Apple 审核 —— 无危险规则，最小权限
3. 安装后，service worker 调用 `updateDynamicRules()` 添加恶意规则
4. 规则目标定为流行 CDN URL（jsdelivr、cdnjs、unpkg），这些出现在许多站点的 CSP 中
5. 每个从这些 CDN 加载脚本的页面现在都会执行攻击者控制的代码

### 4.3 触发条件

攻击成功需要：
- 目标页面从匹配扩展 `regexFilter` 的 URL 加载脚本
- 该脚本 URL 被页面的 CSP 允许（通常如此 —— 页面正是因此加载它的）
- 扩展已安装并启用

## 5. 影响评估

### 5.1 直接影响

| 影响 | 描述 |
|------|------|
| CSP 绕过 | 服务端定义的 script-src 策略被完全绕过 |
| 代码执行 | 在受害页面 origin 中执行任意 JavaScript |
| Cookie 窃取 | 访问 `document.cookie`（非 HttpOnly cookies） |
| DOM 访问 | 对页面内容的完全读写 |
| 凭据窃取 | 可注入钓鱼表单、键盘记录输入 |
| 会话劫持 | 外泄令牌、发起认证 API 调用 |

### 5.2 真实攻击场景

**场景 1：静默监控（摄像头/麦克风）**

如果用户之前已对某个 origin 授权过摄像头/麦克风（如 Google Meet、Zoom Web、腾讯会议），注入的脚本可调用 `navigator.mediaDevices.getUserMedia({video: true, audio: true})` **无需任何新的权限提示**。攻击者通过用户已信任的网站静默录制视频/音频。

**场景 2：密码收割**

注入的脚本运行在页面的 main world 中。如果用户的密码管理器（Safari 自动填充、1Password 等）已自动填充了登录表单，脚本只需读取 `document.querySelector('input[type="password"]').value`。无需用户交互 —— 凭据已经在 DOM 中。

**场景 3：认证 API 滥用（银行场景）**

脚本以页面的完整 cookie jar 执行。对于银行网站：
```javascript
// HttpOnly session cookies 会随请求发送 —— 攻击者读不到但能用
fetch('/api/transfer', {
  method: 'POST',
  credentials: 'same-origin',
  body: JSON.stringify({to: 'attacker_account', amount: 10000})
});
```
攻击者以用户身份发起认证 API 调用 —— 修改密码、转账、导出数据 —— 全部无需直接读取 session cookie。

**场景 4：通过 CDN 定向实现供应链攻击**

一条针对 `cdn.jsdelivr.net` 的 DNR 规则同时影响数千个网站。任何 CSP 中包含 `script-src cdn.jsdelivr.net` 的站点（这是常见模式）都变得脆弱。攻击者实现全网规模的代码注入 —— 类似 CDN 入侵但仅需一个浏览器扩展安装。

**场景 5：地理位置追踪**

对于用户之前已授权位置访问的站点（地图、外卖、打车应用），注入的脚本调用 `navigator.geolocation.watchPosition()` 持续追踪用户物理位置并将坐标外泄给攻击者。

**关键洞察**：以上场景通过任何仅具有 `declarativeNetRequest` 权限的合法扩展机制都**不可能实现**。它们需要等同于 `scripting` + `<all_urls>` + `host_permissions` 的能力，而 Safari 在安装时会对这些权限显示醒目的安全警告。

### 5.3 规模

- 影响所有安装了**任何**具有 `declarativeNetRequest` 权限扩展的 Safari 用户
- 流行的内容拦截器（uBlock Origin Lite、AdGuard 等）都请求此权限
- 单个恶意扩展可同时针对数千个网站
- 动态规则允许延时激活（逃避初始审核）

### 5.4 严重性论证

| 因素 | 评估 |
|------|------|
| 攻击复杂度 | 低 —— 简单扩展，API 有完善文档 |
| 所需权限 | 低 —— 仅 `declarativeNetRequest`（自动授予） |
| 用户交互 | 无（初始扩展安装后） |
| 范围 | 改变 —— 打破服务端定义的 CSP 边界 |
| 机密性 | 高 —— 完全页面内容访问 |
| 完整性 | 高 —— 任意 DOM 修改 |
| 可用性 | 无 |

**CVSS 3.1 估计**：8.1（高）—— 假设"扩展安装"为低权限要求。

## 6. 受影响版本

| 版本 | 状态 | 说明 |
|------|------|------|
| Safari 15.4（2022年3月） | 首次受影响 | `redirect` 动作类型引入 |
| Safari 16.x | 受影响 | |
| Safari 17.x | 受影响 | |
| Safari 18.x | 受影响 | |
| Safari 26.x（当前） | 受影响 | 最新稳定版：26.4（2026年3月） |
| iOS Safari 15.4+ | 受影响 | 相同实现 |
| iPadOS Safari 15.4+ | 受影响 | 相同实现 |
| visionOS Safari | 受影响 | 相同实现 |

- **漏洞存在窗口**：2022年3月至今（4年以上）
- **所有平台**：macOS、iOS、iPadOS、visionOS
- WebKit trunk（截至2026年5月）仍未修补

## 7. 复现步骤

### 前提条件
- 安装了 Safari Technology Preview（或启用了"开发"菜单的 Safari）的 macOS
- Python 3（用于测试服务器）

### 步骤

1. **启动测试服务器：**
```bash
cd poc/safari-dnr-csp-bypass/test-server
python3 server.py
```

2. **信任自签名证书：**
   在 Safari 中导航到 `https://localhost:8443/`，接受证书警告。

3. **验证基线 CSP 执行：**
   导航到 `https://localhost:8443/no-extension-test`
   预期：页面显示 "CSP is blocking data: scripts correctly"
   （这确认 CSP 正确阻止直接的 data: 脚本加载）

4. **加载 PoC 扩展：**
   - Safari > 开发 > 允许未签名的扩展
   - 将 `extension/` 目录作为未打包扩展加载
   - 在 Safari > 设置 > 扩展 中启用

5. **触发漏洞：**
   导航到 `https://localhost:8443/`
   - **如果存在漏洞：** 页面内容被替换为红色 "CSP BYPASSED" 文字，显示 origin 和 cookies
   - **如果已修补：** 页面显示 "Waiting for script to load..."（脚本被阻止）

6. **验证扩展权限：**
   检查 Safari > 设置 > 扩展 > DNR CSP Bypass PoC
   该扩展仅有 "declarativeNetRequest" —— 无内容访问，无 host permissions。

## 8. 修复建议

### 修复 A：DNR 解析器中的 Scheme 白名单（主要修复）

在 `_WKWebExtensionDeclarativeNetRequestRule.mm` 中添加匹配 Chrome 限制的验证：

```objc
NSString *scheme = objectForKey<NSString>(transformDictionary, declarativeNetRequestRuleURLTransformScheme, false);
if (scheme) {
    static NSSet *allowedSchemes = [NSSet setWithObjects:@"http", @"https", @"ftp", @"safari-web-extension", nil];
    if (![allowedSchemes containsObject:scheme.lowercaseString]) {
        if (outErrorString)
            *outErrorString = [NSString stringWithFormat:
                @"Rule with id %ld specifies disallowed transform scheme '%@'. "
                @"Allowed schemes: http, https, ftp, safari-web-extension.",
                (long)_ruleID, scheme];
        return nil;
    }
}
```

### 修复 B：WebCore 中的 Scheme 验证（纵深防御）

在 `ContentExtensionActions.cpp` 的 `URLTransformAction::parse()` 中，扩展阻止列表：

```cpp
if (scheme == "javascript"_s || scheme == "data"_s || scheme == "file"_s || scheme == "blob"_s)
    return makeUnexpected(ContentExtensionError::JSONRedirectToJavaScriptURL);
```

并在 `RegexSubstitutionAction::applyToURL()` 中：

```cpp
URL replacementURL(substitution);
if (replacementURL.isValid() && !replacementURL.protocolIsJavaScript()
    && !replacementURL.protocolIsData() && !replacementURL.protocolIsFile()
    && !replacementURL.protocolIsBlob()) {
    url = WTF::move(replacementURL);
}
```

### 修复 C：内容扩展重定向后重新验证（纵深防御）

在 `CachedResourceLoader.cpp` 第1179行之后：

```cpp
request.applyResults(WTF::move(results), page.ptr());

// 对修改后的 URL 重新验证 CSP 和 SecurityOrigin
URL modifiedURL = request.resourceRequest().url();
if (modifiedURL != url && !canRequest(type, modifiedURL, request.options(), forPreload, isRequestUpgradable, request.isLinkPreload())) {
    CACHEDRESOURCELOADER_RELEASE_LOG("requestResource: Content extension redirect blocked by security check");
    return makeUnexpected(ResourceError { errorDomainWebKitInternal, 0, modifiedURL, "Redirected URL blocked by security policy"_s, ResourceError::Type::AccessControl });
}
```

**三个修复都应该应用**以实现纵深防御。

## 9. 发现方法论

### 9.1 方法：跨实现差异分析

此漏洞通过系统性比较 Chrome 和 WebKit 对同一 Web Extension API 规范的实现而发现。方法论：

1. **识别共享 API 表面**：两个浏览器从相同的 Chrome Extensions 规范实现 `declarativeNetRequest`。实现之间安全验证的差异是发现漏洞的最佳区域。

2. **映射安全关键数据流**：从以下路径追踪重定向规则：
   - 扩展 manifest → JSON 解析 → Content Rule List 编译 → 加载时 URL 修改

3. **识别验证点**：对每一层，记录什么被验证了，什么没有：
   - 第1层（DNR 解析器）：仅类型检查
   - 第2层（WebCore 解析器）：`javascript:` 被阻止，其他无
   - 第3层（应用时）：无验证
   - 第4层（请求管线）：CSP 仅在修改前检查
   - 第5层（子资源加载器）：仅 HTTP 重定向路径

4. **与 Chrome 验证器比较**：发现 Chrome 的 `kAllowedTransformSchemes` 限制为4个安全值。在 WebKit 中搜索等效物 —— 未找到。

5. **端到端验证利用路径**：确认通过 `ResourceLoader::loadDataURL()` 加载的 `data:` URL 在页面上下文中执行，无额外安全检查。

### 9.2 关键洞察模式："先检查后修改" 反模式

根本漏洞模式是：
```
security_check(original_url);  // 通过 —— URL 是合法的
url = modify(original_url);    // 攻击者转换为危险 URL
load(url);                     // 无重新检查 —— 危险 URL 被加载
```

这类似于 TOCTOU（检查时间/使用时间）漏洞，但应用于 URL 安全验证。"检查"和"使用"在同一函数中，但被内容扩展转换步骤分隔。

### 9.3 分析的源文件

| 文件 | 角色 |
|------|------|
| `_WKWebExtensionDeclarativeNetRequestRule.mm` | DNR 规则解析（WebKit Extensions） |
| `ContentExtensionActions.cpp` | URL 转换/重定向应用（WebCore） |
| `ContentExtensionsBackend.cpp` | Content rule list 处理管线 |
| `CachedResourceLoader.cpp` | 带 CSP 检查的子资源加载 |
| `SubresourceLoader.cpp` | 重定向处理 |
| `ResourceLoader.cpp` | Data URL 加载 |
| `SecurityOrigin.cpp` | canDisplay() 实现 |
| Chrome `indexed_rule.cc` | Chrome 的 scheme 验证（比较） |
| Chrome `constants.cc` | `kAllowedTransformSchemes` 定义 |

### 9.4 逐步发现过程

**第一步：选择攻击面**

从 Safari Web Extensions 的 IPC 消息列表（`WebExtensionContext.messages.in`）出发，枚举所有扩展可调用的接口。`declarativeNetRequest` 因为标注为"低权限"引起注意 —— 低权限 API 往往缺乏安全审计。

**第二步：找到 Chrome 的防御代码**

先看 Chrome 怎么实现的。在 `indexed_rule.cc` 里发现了一个显眼的白名单：

```cpp
const char* const kAllowedTransformSchemes[4] = {
    "http", "https", "ftp", "chrome-extension"
};
```

这说明 Chrome 团队**认为不限制 scheme 是危险的**，专门写了防御。

**第三步：去 WebKit 找等价物**

带着"WebKit 有没有同样的限制？"这个问题，查看：
- `_WKWebExtensionDeclarativeNetRequestRule.mm` → 只做类型检查，没有白名单
- `ContentExtensionActions.cpp` → 只阻止 `javascript:`，其他全放行

**答案：没有等价物。**

**第四步：追踪 data: URL 是否真能执行**

光能重定向到 `data:` 不够，还要确认它能绕过 CSP 执行。追踪加载流程：
- `CachedResourceLoader.cpp:1142` — CSP 检查原始 URL ✓
- `CachedResourceLoader.cpp:1179` — 扩展改 URL 为 data:
- 之后没有第二次 CSP 检查 ← **漏洞确认**

**第五步：确认没有其他防御层拦截**

检查 `SubresourceLoader.cpp:287` 的 data: URL 拦截 → 只对 HTTP 3xx 服务器重定向生效，对内容扩展重定向无效。防御者的死胡同。

**核心方法论一句话：**

> 一个厂商的安全加固 = 另一个厂商的漏洞线索。Chrome 加了限制说明"这里有风险"，WebKit 没加说明"这里有洞"。

整个发现过程不到一天。关键是知道**去哪里找**和**找什么**。

### 9.5 时间线

- **2026-05-05**：Safari Web Extensions IPC 初始攻击面映射
- **2026-05-06**：下载 `_WKWebExtensionDeclarativeNetRequestRule.mm`，识别缺失的 scheme 验证
- **2026-05-06**：追踪 WebCore 内容扩展管线，确认所有层都无 scheme 检查
- **2026-05-06**：找到 Chrome 的 `kAllowedTransformSchemes` —— 确认这是已知需要的防御
- **2026-05-06**：验证 `CachedResourceLoader.cpp` 中的 CSP 检查顺序 —— 确认先检查后修改模式
- **2026-05-06**：记录完整攻击链并编写 PoC

## 10. 参考

- [Chrome declarativeNetRequest API](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest)
- Chrome 源码：`extensions/browser/api/declarative_net_request/indexed_rule.cc`
- Chrome 源码：`extensions/browser/api/declarative_net_request/constants.cc`
- WebKit 源码：`Source/WebCore/contentextensions/ContentExtensionActions.cpp`
- WebKit 源码：`Source/WebCore/loader/cache/CachedResourceLoader.cpp`
- WebKit bug tracker 注释：SubresourceLoader.cpp:286 "FIXME: Ideally we'd fail any non-HTTP(S) URL"
