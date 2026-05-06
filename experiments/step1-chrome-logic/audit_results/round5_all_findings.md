# 第五轮审计 — 非 debugger 攻击面

## 日期: 2026-05-01

## Agent 结果汇总

### Agent A: Privacy Sandbox — 等待完成

### Agent B: Permission/Policy 传播
| Finding | 描述 | 可利用性 | 需要 |
|---------|------|---------|------|
| BFCache CSP 过期 | BFCache 恢复后 CSP 不刷新 | 低 | 服务端改 CSP + 用户回退导航 |
| Prerender BroadcastChannel | 预渲染页面可通过 BroadcastChannel 通信 | 低 | same-origin |
| **Prerender 激活安全检查不完整** | crbug.com/340416082，Android WebView 跳过 initiator_origin 检查 | **中-高** | Android WebView |
| **StorageAccess + BFCache** | SAA grant 过期但 BFCache 恢复后仍保留 | **中** | 控制第三方 embed |
| Prerender Mojo GrantAll | 激活时不重新检查权限 | 中 | 预渲染期间权限被撤销 |

### Agent C: Extension API
| Finding | 描述 | 可利用性 | 需要 |
|---------|------|---------|------|
| DNR modifyHeaders 无 forbidden header | set 操作可改 Cookie/Origin/Host | 低（可能 by design） | host_permissions |
| MAIN world 无额外权限门控 | 和 ISOLATED 相同权限检查 | 低（design concern） | host_permissions |
| offscreen reason 不强制执行 | 声明 AUDIO 原因但可做任意操作 | 低 | — |
| **多个 SW 同时存在** | CHECK 被注释掉 (crbug/40936639) | 中 | 竞争条件 |
| 空 URL subframe 权限绕过 | 浏览器端跳过检查依赖 renderer | 低 | — |
