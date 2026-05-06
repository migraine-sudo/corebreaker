# Chrome Extension Security Audit Plan

## 历史漏洞模式分析 (CVE/VRP 学习总结)

### 统计概览

| 攻击模式 | CVE 数量 | 活跃年代 | 2024-2025 仍在出 |
|----------|---------|---------|------------------|
| Extension → WebUI/privileged page 注入 | 20+ | 2018-2025 | YES |
| Site isolation bypass via extension | 6+ | 2020-2024 | YES |
| SOP bypass via extension bindings/prototype | 8+ | 2016-2017 | Fixed (binding rewrite) |
| Navigation restriction bypass | 10+ | 2018-2025 | YES |
| File access restriction bypass | 8+ | 2017-2025 | YES |
| WebRequest/DNR permission model flaw | 7+ | 2015-2025 | YES |
| UI spoofing for install/permission | 5+ | 2016-2025 | YES |
| Sandbox escape via extension platform | 6+ | 2020-2022 | Reduced |

### 最高危 CVE (CVSS >= 9.0)

| CVE | CVSS | Year | 模式 |
|-----|------|------|------|
| CVE-2022-0466 | 9.6 | 2022 | Sandbox escape via Extensions Platform |
| CVE-2021-21132 | 9.6 | 2021 | Sandbox escape via DevTools + extension |
| CVE-2020-15963 | 9.6 | 2020 | Sandbox escape via extension policy enforcement |

---

## 八大攻击类别详解

### 类别 1: Extension Privilege Escalation

**代表 CVE:**
- CVE-2025-3069 (Chrome < 135) — 网页触发扩展提权，无需安装恶意扩展
- CVE-2024-6778 (Chrome < 126) — DevTools race condition，恶意扩展注入脚本到 WebUI
- CVE-2025-0443 (Chrome < 132) — 需用户 UI gesture，数据验证不足

**失效防御层:** Permission boundary enforcement (扩展进程 vs 浏览器进程)

**审计重点:** 
- 寻找扩展 API 调用中对 `chrome://` / `devtools://` 页面的访问检查遗漏
- 关注 ViewType 枚举覆盖不完整

### 类别 2: Extension API Bypasses (Web → Extension)

**代表 CVE:**
- CVE-2016-1622 — Object.defineProperty override extension behavior
- CVE-2016-1676 — binding.js prototype manipulation 突破 isolated world
- CVE-2016-5173 — Object.prototype 泄露到 page context

**状态:** 2016 年 binding 重写后基本消除，但逻辑层面仍可能有

### 类别 3: Content Script Isolation Failures

**关键模式:**
- postMessage handler 缺 origin 验证 (CVE-2026-2345 Proctorio)
- Content script 访问 cross-origin CSS (CVE-2025-68467 Dark Reader)
- Storage API origin validation 绕过 (CVE-2022-4913)

**审计重点:** Content script → extension messaging 的 origin 信任链

### 类别 4: DeclarativeNetRequest (DNR) Abuse

**状态:** NVD 无专门 CVE，可能未被充分探索
- DNR `modifyHeaders` 可删除 CSP/HSTS/X-Frame-Options
- 单条 redirect rule 匹配 `*://*/*` 即可重定向所有流量
- 与 Service Worker 的 fetch 事件交互未被审视

### 类别 5: Extension Messaging Vulnerabilities

**代表 CVE:**
- CVE-2018-16064 — messaging path 输入验证不足
- CVE-2018-6138 — 跨扩展 messaging 触发导航绕过

**关键攻击面:**
- `externally_connectable` 配置过宽 → web page 向扩展发命令
- `chrome.runtime.sendMessage` sender 验证不充分
- Service worker 重启后 messaging channel 状态不一致

### 类别 6: WebRequest/DNR Permission Model Flaws

**代表 CVE:**
- CVE-2015-1297 — webRequest 未验证请求来源
- CVE-2024-0811 (Chrome < 121) — cross-origin data leak
- CVE-2025-8581 (Chrome < 139) — cross-origin data leak，需 UI gesture

**审计重点:** Host permission 边界检查覆盖不完整

### 类别 7: Extension Install/Update Attacks

**代表 CVE:**
- CVE-2024-0333 (Chrome < 120) — MITM CRX 下载替换恶意版本 (无需用户交互!)
- CVE-2025-0446 — UI spoofing 诱导安装

**关键:** CRX 签名验证 + 更新通道完整性

### 类别 8: ManifestV3 Migration Gaps

**代表 CVE:**
- CVE-2024-10229 (Chrome < 130) — MV3 era site isolation bypass
- CVE-2025-9866 (Chrome < 140) — MV3 CSP bypass via crafted HTML
- CVE-2022-0466 (CVSS 9.6) — Sandbox escape via Extensions Platform

**MV3 特有攻击面:**
1. Service Worker 生命周期 → 安全状态不一致 (idle termination / wake-up)
2. Offscreen documents → extension origin 执行能力
3. web_accessible_resources 新 per-resource matching → 配置过宽
4. DNR + 残留 webRequest 交互
5. Side Panel API → 新的 trust boundary

---

## 审计目标优先级 (基于源码分析)

### Priority 1: Extension Navigation Throttle — blob/filesystem URL 异常

**位置:** `extension_navigation_throttle.cc:243-256`

**假设:** 非扩展页面可以导航到拥有 `webView` 权限的扩展的 `blob:chrome-extension://` URL。
检查逻辑只验证 **目标扩展** 有 webview 权限，不验证 **发起者** 是否为该扩展的 webview。

**原则匹配:** 原则 3 (条件覆盖不完整)
**严重度:** Medium-High
**用户交互:** 无需
**防御层:** Navigation throttle + ProcessMap (需验证 ProcessMap 是否独立阻止)

### Priority 2: Offscreen Document ViewType 能力差异

**位置:** `offscreen_document_host.cc` + 所有 API permission checks

**假设:** 某些 API 权限检查按 ViewType 分支处理，但 `kOffscreenDocument` 未被正确处理，
可能继承了比预期更多的能力。

**原则匹配:** 原则 3 (enum 值覆盖)
**严重度:** Medium
**用户交互:** 需安装扩展

### Priority 3: Service Worker 权限传播竞态

**位置:** `service_worker_host.cc:325-348`

**假设:** `UpdateExtensionPermissions()` 在 worker idle/restart 周期中可能传播失败，
导致已 revoke 的权限在重启后的 worker 中仍然可用。

**原则匹配:** 原则 4 (Lazy binding 时序)
**严重度:** Medium-High
**用户交互:** 无需

### Priority 4: SidePanelHelper Dispatch Boundary (2026 新代码)

**位置:** `side_panel_helper.h/cc`

**假设:** `SidePanelHelper` 创建 `ExtensionFunctionDispatcher` 为 side panel WebContents 提供
extension function dispatch 能力。如果恶意页面能注入内容到 side panel，则获得扩展权限。

**原则匹配:** 原则 2 (新 API 流入旧代码)
**严重度:** Medium
**用户交互:** User gesture

### Priority 5: Offscreen DCHECK-only Incognito Guard

**位置:** `offscreen_document_manager.cc:118-127`

**假设:** Spanning-mode 扩展在 incognito 中创建 offscreen document 的检查仅 DCHECK 保护。
Release build 中可能在错误的 BrowserContext 创建。

**原则匹配:** 原则 5 (DCHECK-only = 无效检查)
**严重度:** Low-Medium

### Priority 6: MV2 Force-Install Bypassing MV3 Deprecation

**位置:** `standard_management_policy_provider.cc:180-185`

**假设:** 企业策略 force-install 的 MV2 扩展绕过 MV2 弃用限制，
保留 MV3 本应移除的能力 (persistent background page, webRequest blocking)。

**原则匹配:** 原则 1 (不一致)

### Priority 7: DNR + Service Worker Fetch 交互 (未探索领域)

**位置:** `extensions/browser/api/declarative_net_request/`

**假设:** DNR redirect rules 与 extension service worker 的 fetch event handler 交互中，
可能存在优先级或时序问题导致安全头被移除但 service worker 仍处理了原始请求。

---

## 执行计划

### Round 1 (首轮): Extension Navigation Throttle

```
Step 2 (60% time):
- 精读 extension_navigation_throttle.cc 全文
- 列出所有安全检查及其触发条件
- 画出 blob/filesystem URL 导航的完整决策树
- 找出 ProcessMap check 与 navigation throttle check 的交互

Step 3:
- 假设: 创建一个有 webView 权限的扩展 A
- 从普通网页导航到 blob:chrome-extension://{A_ID}/...
- 预期: navigation throttle 的 has_webview_permission 检查通过

Step 4:
- 写 PoC (最小扩展 + 触发页面)
- 验证 ProcessMap check 是否独立阻止
```

### Round 2: Offscreen Document Capability Audit

```
Step 2:
- 列出所有按 ViewType 分支的 API permission checks
- 验证 kOffscreenDocument 是否在每个分支中正确处理
- 交叉验证 "reason" enum 与实际能力限制

Step 3:
- 假设: 特定 API 对 offscreen document 的 ViewType 检查遗漏
- 使 offscreen document 调用不应可用的 API

Step 4:
- 写 PoC 扩展验证
```

### Round 3: Service Worker Permission Race

```
Step 2:
- 精读 service_worker_host.cc 的权限更新路径
- 理解 worker idle/terminate/restart 完整流程
- 找出权限同步的 timing window

Step 3:
- 假设: rapid enable/disable cycle 中权限状态不一致
- 构造 revoke 后 worker restart 仍持有旧权限的场景

Step 4:
- 写 PoC 验证
```

---

## 需要的准备工作

1. [ ] 确保本地有最新 Chromium extension 相关源码
2. [ ] 设置扩展开发环境 (chrome://extensions → Developer mode)
3. [ ] 准备本地 HTTPS 测试服务器 (mkcert)
4. [ ] 创建基础扩展模板 (MV3, 含常用权限声明)
5. [ ] 确认 Chrome Canary 版本 (最新代码匹配)

---

## 已知约束

- Gate 1: 必须有 PoC 才能报告
- Gate 2: 每轮最多 1 个子系统
- Gate 3: 需要确认无 defense-in-depth (多层防御全绕过)
- Gate 4: 找不一致性，不找缺失检查
