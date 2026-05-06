# Safari Web Extensions 安全研究规划

## Context

38 轮 JSC 源码审计 ROI 递减（仅产出 1 个 info leak），需要开辟新攻击面。Safari Web Extensions 是高价值目标：代码新（2021+ 引入）、竞争少、逻辑 bug 比内存 bug 更易找、Apple Bounty 对权限绕过/$100K+。

WebKit Extensions 代码量 ~54K 行/282 文件，已在现有 WebKit checkout (`targets/jsc/`) 中。主攻击面是 WebContent→UIProcess 的 85+ IPC 消息，每条有 validator 控制访问权限。

## 实施计划（按优先级排序）

### Step 1: 知识库建设（最高优先，审计质量依赖此）

创建 `knowledge/safari-extensions/` 目录：

| 文件 | 内容 |
|------|------|
| `architecture-overview.md` | 三进程架构、IPC 流、validator 层级、privileged identifier 机制、DOMWrapperWorld 隔离 |
| `ipc-attack-surface.md` | 85+ IPC 消息分类：按 validator 类型（isLoaded / isLoadedAndPrivilegedMessage / per-API）、参数复杂度、状态修改能力 |
| `permission-model.md` | PermissionState 7 级枚举、grant/deny 状态机、privileged identifier 分配和校验逻辑 |
| `safari-chrome-diff.md` | Safari vs Chrome 实现差异（Safari 用 ObjC UIProcess handler，Chrome 用 C++ browser process）——差异处出 bug |
| `cve-patterns/known-extension-vulns.md` | Chrome/Firefox 已知扩展 CVE 模式，用于变体搜索 |

**数据源**：直接从 `targets/jsc/Source/WebKit/*/Extensions/` 源码提取 + `WebExtensionContext.messages.in` IPC 定义。

### Step 2: `/ext-audit` 交互式审计技能

创建 `.claude/skills/ext-audit/skill.md`：

**审计流程**：
1. 加载目标在 IPC 信任边界中的位置
2. IPC 消息验证审计：validator 是否匹配 API 能力？参数反序列化是否安全？
3. 权限状态机审计：TOCTOU、revoke 后残留、grant 条件绕过
4. Content script 隔离审计：DOMWrapperWorld 强制执行、跨世界通道
5. 跨 API 交互：组合两个 API 绕过单 API 的检查

**输出格式**：location + finding + confidence + test_extension（manifest.json + JS 文件）

### Step 3: `hunt-supervisor.py` 引擎配置化

引入 `EngineProfile` 类替换 6 个 JSC 硬编码点：

| 耦合点 | 当前（JSC） | 扩展版 |
|--------|-------------|--------|
| `JSC_SUBSYSTEMS` | DFG/FTL/B3/Runtime/Heap... | IPC Handlers / Permission / Content Script / DNR / Scripting / Storage / Native Messaging |
| `source_prefix` | `targets/jsc/` | `targets/jsc/`（同一 checkout） |
| `source_path_pattern` | `Source/JavaScriptCore/` | `Source/WebKit/.*/Extensions/` |
| Audit grep patterns | `CheckInBounds\|putDirect\|butterfly...` | `isLoaded\|isLoadedAndPrivilegedMessage\|hasPermission\|privilegedIdentifier\|executeScript\|matchPattern...` |
| Attack strategies | JIT type confusion, re-entrancy, GC... | 权限检查绕过、IPC 参数注入、隔离世界逃逸、DNR 规则操纵、native messaging 数据逃逸 |
| SUPERVISOR_IDENTITY | JIT 优化专家 | IPC 边界 + 权限绕过专家 |

**CLI**：`python3 scripts/hunt-supervisor.py --engine extensions --once`

### Step 4: `bootstrap.py` 扩展目标队列

新增 `--engine extensions` 模式，生成初始 audit-queue：

**P0 目标（priority 10）**：
- `WebExtensionContext.messages.in` — 85 IPC 消息定义，validator 分配
- `WebExtensionContextAPITabsCocoa.mm` — Tabs API（21 消息，privileged-only）
- `WebExtensionContextAPIRuntimeCocoa.mm` — Runtime API（消息传递核心）

**P1 目标（priority 8-9）**：
- `WebExtensionContext.cpp` — 权限 validator 实现（1929 行）
- `WebExtensionContextAPIScriptingCocoa.mm` — 脚本注入 API
- `WebExtensionContextProxyCocoa.mm` — WebProcess 侧代理

**P2 目标（priority 7）**：
- `WebExtensionDeclarativeNetRequestSQLiteStore.cpp` — DNR SQLite
- `WebExtensionStorageSQLiteStore.cpp` — 存储 SQLite
- `WebExtensionMatchPattern.cpp` — URL 匹配模式解析

### Step 5: GENERATE 适配

扩展模式下输出格式从独立 JS 变为扩展测试包：
- `manifest.json`（最小权限声明）
- `background.js`（测试特权 API）
- `content_script.js`（测试隔离绕过）

保存为目录：`fuzzers/corpus/generated/iter{NNN}-ext-test-{N}/`

### Step 6: FUZZ 阶段 → 手动验证队列

扩展无法在 CLI 自动测试。FUZZ 阶段改为：
- 生成 `logs/session_*/manual-verification-queue.md`
- 列出所有待验证扩展 + Safari 加载步骤
- 用户手动在 Safari 中验证（类似 TypedArray 漏洞的验证方式）

## 关键攻击方向（审计优先级）

1. **Privileged Identifier 伪造**：content script 能否获取/猜测 privileged identifier → 访问 tabs/windows/scripting API
2. **IPC validator 不一致**：某些 API 用 `isLoaded`（弱）而应该用 `isLoadedAndPrivilegedMessage`（强）
3. **跨 API 权限提升**：通过 A API（有权限）修改状态 → B API（无权限）利用修改后的状态
4. **Content Script → Main World 逃逸**：DOMWrapperWorld 隔离是否在所有路径上强制执行
5. **DeclarativeNetRequest 规则注入**：恶意规则能否劫持其他扩展或页面的网络请求
6. **ScriptingExecuteScript world 参数**：能否注入到 "main" world 执行特权代码
7. **Safari-Chrome 差异利用**：Chrome 安全但 Safari 实现不同的地方

## 验证方式

- Step 1-2 完成后：用 `/ext-audit` 交互审计 `WebExtensionContext.messages.in`，验证能否产出 findings
- Step 3-4 完成后：`python3 scripts/bootstrap.py --engine extensions && python3 scripts/hunt-supervisor.py --engine extensions --once --dry-run`
- Step 5-6 完成后：完整循环 `python3 scripts/hunt-supervisor.py --engine extensions --once`，检查 manual-verification-queue.md 生成

## 文件清单

| 操作 | 路径 |
|------|------|
| 新建 | `knowledge/safari-extensions/architecture-overview.md` |
| 新建 | `knowledge/safari-extensions/ipc-attack-surface.md` |
| 新建 | `knowledge/safari-extensions/permission-model.md` |
| 新建 | `knowledge/safari-extensions/safari-chrome-diff.md` |
| 新建 | `knowledge/safari-extensions/cve-patterns/known-extension-vulns.md` |
| 新建 | `.claude/skills/ext-audit/skill.md` |
| 修改 | `scripts/hunt-supervisor.py`（EngineProfile 抽象 + 6 耦合点替换） |
| 修改 | `scripts/bootstrap.py`（`--engine extensions` + 扩展目标队列） |
