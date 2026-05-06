# Safari Web Extensions 安全研究

## 状态：待启动

从 ouroboros 的 JSC 审计迁移过来的新方向。详细规划见 `PLAN.md`。

## 攻击面概览

WebKit Extensions 代码量 ~54K 行/282 文件，在 WebKit checkout 中：
- `Source/WebKit/UIProcess/Extensions/` — 77 files, ~28K lines（UIProcess 侧处理器，权限系统）
- `Source/WebKit/WebProcess/Extensions/` — 127 files, ~17K lines（WebProcess 侧 API）
- `Source/WebKit/Shared/Extensions/` — 78 files, ~6K lines（共享类型，序列化）

## 主攻方向

1. **IPC 信任边界**：85+ IPC 消息从 WebContent→UIProcess，每条有 validator
2. **Privileged Identifier 伪造**：content script 能否获取 privileged ID
3. **权限状态机**：7 级 PermissionState，复杂 grant/deny 逻辑
4. **Content Script 隔离**：DOMWrapperWorld 隔离绕过
5. **DeclarativeNetRequest**：规则解析注入
6. **Script Injection**：ScriptingExecuteScript world 参数
7. **Native Messaging**：JSON payload 到 host app

## Apple Bounty 对应

| 漏洞类型 | 预期奖金 |
|----------|----------|
| Extension 权限提升获取敏感数据 | $100K |
| Content script 隔离绕过 | $10K |
| Native messaging sandbox escape | $100K-300K |
| WebContent sandbox escape（via extension IPC） | $300K |

## 依赖

- WebKit 源码（ouroboros 的 `targets/jsc/` 中已有）
- Safari 浏览器（手动验证）
- 无需额外构建（逻辑审计为主，非 memory corruption）
