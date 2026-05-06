# Finding 251: Page.reload scriptToEvaluateOnLoad — 持久化脚本注入

## 日期: 2026-05-01

## 漏洞详情

### 位置
`content/browser/devtools/protocol/page_handler.cc:756`

### 问题
`Page.reload` 接受 `scriptToEvaluateOnLoad` 参数，无 `is_trusted_` 检查。

untrusted 扩展客户端可以注入在每次页面加载时自动执行的 JavaScript，运行在 main world（非 isolated world），拥有页面 origin 的完整权限。

### 与 content scripts 的区别
- Content scripts 运行在 isolated world，不能直接访问页面的 JS 变量
- `scriptToEvaluateOnLoad` 运行在 main world，完全等同于页面自己的脚本
- 绕过了扩展 content script 的隔离模型

### 影响
- 注入的脚本在页面 origin 上下文中运行
- 可以访问页面的所有 JS 对象、变量、原型链
- 可以 hook 原生 API（XMLHttpRequest.prototype.send 等）
- 配合 CSP bypass 可以做到完全持久化

### 与 Runtime.evaluate 的区别
- Runtime.evaluate 是一次性执行
- scriptToEvaluateOnLoad 在每次 reload 后自动重新执行
- 如果用户手动刷新页面，脚本仍然注入

### 待验证
- 确认 Page.reload 的 scriptToEvaluateOnLoad 对 untrusted 客户端可用
- 验证脚本确实在 main world 执行

## 可利用性评估: MEDIUM-HIGH
- 实际增量危害需要和 CSP bypass/cookie theft 组合
- 但 main world 执行本身就打破了扩展隔离模型
