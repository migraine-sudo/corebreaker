# Finding 246 — Page.setBypassCSP 分析记录

## 日期: 2026-05-01

## 漏洞事实

- `Page.setBypassCSP` 在 `page_handler.cc:1844-1847` 无 `IsTrusted()` 检查
- 扩展（untrusted client）可以调用此命令完全禁用目标页面 CSP
- 已在 Chrome stable + github.com 上验证成功
- PoC 位于 `audit_results/poc/csp_bypass_extension/`

## 验证结果（github.com）

```
[4] Inline script BLOCKED by CSP          ← bypass 前 CSP 生效
[5] Page.setBypassCSP SUCCEEDED!          ← 命令被接受
[7] Inline script: true, eval(): true     ← bypass 后 CSP 完全失效
```

## 深度分析：实际危害评估

### 为什么危害可能被评为 Low

核心问题：**debugger 权限本身已经非常强大**

1. `Runtime.evaluate` 可在页面上下文执行任意代码
2. 执行结果通过 CDP 通道返回扩展（不走网络，不受 CSP 限制）
3. 扩展自身的 `fetch()` 不受目标页面 CSP 约束
4. 因此 "CDP 读数据 → 扩展自己外发" 完整链路不需要绕 CSP

### CSP bypass 的实际增量价值

仅在以下场景有额外价值：
- **Detach 后持久化**：绕 CSP 后注入的 `<script>` 标签可在 debugger 断开后继续运行并外泄数据
- 但攻击者也可以用 `Runtime.evaluate` 注入 event listener 实现类似持久化（只是不能用 `<script>` 标签方式）

### CSP 的本来用途

CSP 主要防的是 **XSS 漏洞被利用后的损害扩散**，不是防恶意扩展。对于已经有 debugger 权限的扩展，CSP 本身不是安全边界。

## 论证角度分析

| 论点 | 强度 | Google 可能的反驳 |
|------|------|-----------------|
| Trust model violation | 中 | "正确，但影响有限" |
| 权限声明不匹配 | 中 | "debugger 警告已覆盖" |
| 持久化 + 隐蔽性 | 弱 | "攻击者有其他方式持久化" |
| 数据外泄 | 无效 | "CDP 通道已经能做" |
| 已有 CDP 命令黑名单先例 | 中 | 这是最难反驳的 |

## 结论

- **代码正确性**: 确实是 bug（trust model 不一致）
- **实际安全影响**: Low — debugger 权限本身已覆盖大部分攻击能力
- **VRP 预期评级**: Low 或 WontFix
- **决策**: 记录但不优先提交，集中精力在 Finding 245（cookie escalation，真实权限提升）

## VRP 报告文件（已生成备用）

- `vrp_finding246_csp_bypass_cn.md` — 中文报告
- `vrp_finding246_csp_bypass_en.md` — 英文报告
- `poc/csp_bypass_extension/` — 完整 PoC（已验证）
