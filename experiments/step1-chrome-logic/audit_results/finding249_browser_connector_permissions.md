# Finding 249: BrowserConnectorHostClient 权限提升

## 日期: 2026-05-01

## 发现

`Target.exposeDevToolsProtocol` 创建的 `BrowserConnectorHostClient` 有多个权限问题：

### Bug 位置
`content/browser/devtools/protocol/target_handler.cc:185-231`

### 问题 1: MayAccessAllCookies() 硬编码 true（与 Finding 245 同模式）

```cpp
// target_handler.cc:208
bool MayAccessAllCookies() override { return true; }
```

`BrowserConnectorHostClientPermissions` 结构体（176-180 行）只追踪 `allow_unsafe_operations`，cookie 权限没有被纳入继承机制。

### 问题 2: 多个权限方法缺失覆写，回退到危险默认值

`BrowserConnectorHostClient` 没有覆写以下方法，全部回退到基类默认值：

| 方法 | 默认值 | 问题 |
|------|--------|------|
| `IsTrusted()` | `true` | page_host_client_ 获得完整 trusted 权限 |
| `MayAttachToURL()` | `true` | 可以附加到任何 URL 包括 WebUI |
| `MayReadLocalFiles()` | `true` | 可以读取本地文件 |
| `MayWriteLocalFiles()` | `true` | 可以写入本地文件 |

### 攻击路径

`ExposeDevToolsProtocol` 创建 `BrowserToPageConnector`：
- `browser_host_client_` 附加到 browser agent host（228-229 行）
- `page_host_client_` 附加到 page agent host（230-231 行）

`page_host_client_` 以默认权限创建，但获得：
- `IsTrusted()=true` → 访问所有 CDP domains
- `MayReadLocalFiles()=true` → 读取本地文件
- `MayWriteLocalFiles()=true` → 写入本地文件
- `MayAccessAllCookies()=true` → 访问所有 cookie

### 利用前提

`ExposeDevToolsProtocol` 需要 `AccessMode::kBrowser`。

**关键问题**: 哪些客户端有 kBrowser 访问模式？
- `--remote-debugging-port` 连接 → 本地调试，已经是 trusted
- `--remote-debugging-pipe` 连接 → Puppeteer/ChromeDriver，已经是 trusted
- 有没有更低权限的客户端可以调用 `Target.exposeDevToolsProtocol`？

### 评估

如果只有 trusted 客户端能调用 `ExposeDevToolsProtocol`，则实际影响有限。
但 `inherit_permissions` 参数的存在暗示设计者意图做权限传播（目前只实现了 `AllowUnsafeOperations`），其他权限的缺失传播可能是遗漏。

### 可利用性: 待确认（需要验证谁能调用 ExposeDevToolsProtocol）

## 下一步
- 确认扩展是否能通过 Target domain 间接调用 ExposeDevToolsProtocol
- 检查 kBrowser 访问模式的获取条件
