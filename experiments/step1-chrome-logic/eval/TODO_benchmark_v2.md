# Benchmark v2 待办：高难度数据集重建

## 目标
从 10 case (recall=60%) 升级到 ~25 case，按难度分层，仅使用已通过 Google 评审的公开漏洞。

## 数据来源（已搜集完毕）

### Hard Tier (8, weight=2.0) — 多组件推理

| ID | Bug | 赏金 | 来源 | 源码位置 |
|----|-----|------|------|---------|
| H1 | IPCZ Transport::Deserialize 缺少 enum 验证 + 信任传递 | $250,000 | VRP/Micky | `mojo/core/ipcz_driver/transport.cc:665` |
| H2 | XSLT document() SOP 绕过 | — | Bentkowski (CVE-2023-4357) | `third_party/blink/renderer/core/xml/xslt_processor_libxslt.cc` |
| H3 | IndexedDB Put() 在 COMMITTING 状态缺少 IsAcceptingRequests() | — | STAR Labs (CVE-2021-30633, ITW) | `content/browser/indexed_db/instance/transaction.cc:435` |
| H4 | crossOriginIsolated crash 后恢复绕过 COEP | $3,000 | NDevTK (crbug 40056434) | 需重建 BrowsingContextState |
| H5 | COOP opener 切断未传播到 parent.opener 链 | $2,000 | NDevTK (crbug 40059056) | 需重建 opener severance 逻辑 |
| H6 | Android intent:// URL 参数验证不足 (ITW) | — | TAG (CVE-2022-2856) | 需重建 ExternalNavigationHandler |
| H7 | Perfetto ExtensionIsTrusted + externally_connectable 过宽 | $5,000 | NDevTK | `chrome/browser/extensions/api/debugger/debugger_api.cc:227` |
| H8 | ChromeOS filesystem:chrome:// 获得 WebUI 权限 | $10,000 | Eryilmaz (CVE-2023-4369) | 需重建 WebUIConfig origin 逻辑 |

### Medium Tier (7, weight=1.5) — 单组件逻辑

| ID | Bug | 赏金 | 来源 |
|----|-----|------|------|
| M1 | showSaveFilePicker suggestedName 扩展 %ENV% | $10,000 | Pulikowski (CVE-2022-0337) |
| M2 | Service Worker redirect 到 data: URL 绕过导航策略 | $4,000 | NDevTK (crbug 379337758) |
| M3 | about:blank 空文档不继承 owner sandbox flags | $2,500 | NDevTK (crbug 40057525) |
| M4 | history.length 不增长 → 跨域 URL oracle | $5,000 | NDevTK (CL 2983325) |
| M5 | COOP null origin popup 阻止但未切断 window 引用 | $3,000 | NDevTK (b/40057526) |
| M6 | ChromeVox clickNodeRef 无 origin 检查 → SOP bypass | $5,000 | NDevTK |
| M7 | Drive extension externally_connectable 含 HTTP → RCE | $3,134 | NDevTK |

### Easy Tier (3, weight=1.0) — 保留现有

| ID | Bug | 来源 |
|----|-----|------|
| E1 | DCHECK-only guard (原 C1) | CL 7735722 |
| E2 | CSP 字符串匹配绕过 (原 C2) | CL 7656988 |
| E3 | LNA frame tree 遍历不完整 (原 C3) | CL 7681373 |

### Adversarial (7) — 不应被报为漏洞

- A1-A5: 保留现有
- A6: DCHECK→CHECK 加固（防御加深，非新 bug）
- A7: renderer 侧无 CORS preflight 但 NetworkService 独立处理

## 构建每个条目的步骤

1. 从 chromium-src 读源码（已确认文件存在）
2. 移除修复代码，重建漏洞版本（40-80行 hard / 25-40行 medium）
3. 写 root_cause_keywords (5-8 个关键词)
4. 写 context（描述信任模型/攻击面，但不直接说明 bug）
5. 设定 weight 和 difficulty

## score.py 改动

- 新增 `weight` 字段，加权 depth_score
- 新增 per-tier recall (recall_hard / recall_medium / recall_easy)
- overall = Recall * (1-FPR) * Weighted_Mean_Depth

## 需要删除的旧条目

- C4 (self_r605): 自挖洞，未通过 Google 评审
- C5 (self_f253): 自挖洞，未通过 Google 评审

## 预估工作量

- Hard tier: ~2h（需要仔细读源码+重建）
- Medium tier: ~1h
- Adversarial + score.py: ~30min
- 总计: ~3.5h

## 参考资料

- NDevTK writeups: https://ndevtk.github.io/writeups/
- IPCZ fix CLs: 6497400, 6516455, 6517315
- STAR Labs IndexedDB: https://starlabs.sg/blog/2022/01-the-cat-escaped-from-the-chrome-sandbox/
- CVE-2022-0337 PoC: https://github.com/Puliczek/CVE-2022-0337-PoC-Google-Chrome-Microsoft-Edge-Opera
- CVE-2023-4369: https://0x44.xyz/blog/cve-2023-4369/
