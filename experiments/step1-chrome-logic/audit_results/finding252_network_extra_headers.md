# Finding 252: Network.setExtraHTTPHeaders — 任意 HTTP 头注入

## 日期: 2026-05-01

## 漏洞详情

### 位置
`content/browser/devtools/protocol/network_handler.cc:2782`

### 问题
`Network.setExtraHTTPHeaders` 无 `is_trusted_` 检查。

untrusted 扩展客户端可以向被调试页面的所有请求注入任意 HTTP 头。

### 影响
- 注入 `Authorization: Bearer xxx` 头 → 冒充用户访问第三方 API
- 操纵 `Origin` / `Referer` 头 → CSRF 类攻击
- 注入自定义安全头 → 绕过服务端安全检查
- 覆盖 `Cookie` 头 → session fixation

### 与 declarativeNetRequest 的对比
- MV3 扩展的 declarativeNetRequest API 有严格限制（不能修改某些安全头）
- CDP 的 Network.setExtraHTTPHeaders 没有这些限制
- 这绕过了 Chrome 对扩展网络修改能力的限制

### 待验证
- 确认哪些头可以被设置（是否能覆盖 Origin、Cookie、Authorization）
- 确认是否影响所有请求还是仅主框架

## 可利用性评估: HIGH
- 如果能注入 Authorization 头，等于直接获得用户对第三方服务的凭证
