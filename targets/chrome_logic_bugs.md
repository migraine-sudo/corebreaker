# Chrome 逻辑漏洞目标清单

> 基于 2025-2026 年 Chrome VRP 实际公告数据，聚焦**逻辑漏洞**（非内存安全），适合代码审计而非 fuzzing。

## 一、攻击面概览

Chrome 逻辑漏洞占全部 CVE 的 39.9%，赏金占 18.5%（$237,000）。单价均值 $3,338，远低于内存安全的 $18,604，但**门槛低、无需 fuzzer 基础设施、纯代码审计 + 浏览器测试即可**。

2026 年逻辑漏洞产出最密集的类型是 **Policy Bypass**，多位研究员反复出成果。

---

## 二、第一梯队 — 高回报目标

### 2.1 Policy Bypass（策略绕过）

**奖金**: $2,000–$7,000 / 个
**难度**: 中
**2026 年爆发最密集的类型**

| CVE | 严重性 | 组件 | 报告者 | 日期 | 奖金 |
|-----|--------|------|--------|------|------|
| CVE-2026-6313 | **High** | CORS | Google (内部) | 2026-04-02 | TBD |
| CVE-2026-6312 | **High** | Passwords | Google (内部) | 2026-03-31 | TBD |
| CVE-2026-5891 | Medium | Browser UI | Tianyi Hu | 2026-02-25 | TBD |
| CVE-2026-5911 | Low | ServiceWorkers | lebr0nli | 2026-02-19 | TBD |
| CVE-2026-5903 | Low | IFrameSandbox | @Ciarands | 2026-02-11 | TBD |
| CVE-2026-5901 | Low | DevTools | Povcfe (玄武) | 2026-01-29 | TBD |
| CVE-2026-5900 | Low | Downloads | Luan Herrera | 2026-01-13 | TBD |
| CVE-2026-5881 | Medium | LocalNetworkAccess | asnine | 2025-10-22 | TBD |
| CVE-2026-5875 | Medium | Blink | Lyra Rebane | 2025-07-08 | $4,000 |

**审计方法**:
- 重点读 `content/browser/` 中的策略检查函数
- 搜索 `ShouldAllowXXX()`, `IsNavigationAllowed()`, `CanAccessXXX()` 模式
- 关注 ServiceWorker / IFrame sandbox / Downloads 的策略执行路径
- 测试跨 origin 场景下策略是否被正确 enforce

**关键源码目录**:
```
content/browser/service_worker/
content/browser/renderer_host/
third_party/blink/renderer/core/frame/
chrome/browser/download/
```

### 2.2 Security UI 欺骗（Incorrect Security UI）

**奖金**: $1,000–$3,000 / 个
**难度**: 低
**持续产出，门槛最低**

| CVE | 严重性 | 组件 | 报告者 | 日期 |
|-----|--------|------|--------|------|
| CVE-2026-5882 | Medium | Fullscreen | Anonymous | 2026-02-02 |
| CVE-2026-5899 | Low | History Navigation | Islam Rzayev | 2026-01-11 |
| CVE-2026-5880 | Medium | Browser UI | Anonymous | 2025-06-14 |
| CVE-2026-5878 | Medium | Blink (UI) | Shaheen Fazim | 2024-09-06 |

**审计方法**:
- 在**页面转换、导航取消、fullscreen 进出、弹窗关闭**等 timing window 中寻找 UI 状态不一致
- 测试 `history.pushState()` + `location.replace()` + `window.open()` 组合
- Fullscreen API + 页面导航的交互
- 关注 `beforeunload` / `unload` 事件期间的 UI 状态

**关键源码目录**:
```
chrome/browser/ui/views/location_bar/
chrome/browser/ui/views/frame/
content/browser/renderer_host/navigation_controller_impl.cc
ui/views/widget/
```

---

## 三、第二梯队 — 稳定产出

### 3.1 Extensions 系统

**奖金**: $2,000–$4,000 / 个
**难度**: 中

- Manifest V3 迁移引入了新的权限模型和逻辑
- Extensions API 输入验证不足是常见模式
- Luan Herrera、Alesandro Ortiz 年年在此出成果

**审计方向**:
- `chrome.runtime`, `chrome.tabs`, `chrome.webRequest` 等 API 的权限检查
- Content Script 与页面隔离是否完善
- Extension 更新/安装流程中的验证
- Manifest V3 Service Worker 生命周期边界

**关键源码目录**:
```
extensions/browser/api/
chrome/browser/extensions/
extensions/renderer/
```

### 3.2 DevTools Protocol

**奖金**: $1,000–$4,000 / 个
**难度**: 中

- 2025 年 4 个 Inappropriate implementation（$1K–$4K）
- 2026 年玄武实验室又找到 Policy bypass
- DevTools 协议暴露了大量内部功能，容易出现权限检查遗漏

**审计方向**:
- Chrome DevTools Protocol (CDP) 命令的权限检查
- `Runtime.evaluate`, `Network.setRequestInterception` 等敏感命令
- DevTools 页面与目标页面之间的隔离

**关键源码目录**:
```
content/browser/devtools/
third_party/blink/renderer/core/inspector/
```

### 3.3 Downloads 保护绕过

**奖金**: $1,000–$3,000 / 个
**难度**: 低

- 被低估的目标，Luan Herrera 年年找到
- 下载危险文件时的警告绕过
- MIME type / Content-Disposition 处理逻辑

**审计方向**:
- 文件扩展名 / MIME type 检测绕过
- Safe Browsing 警告的绕过条件
- `Content-Disposition` header 解析边界
- 拖拽下载、Blob URL 下载等非标准路径

**关键源码目录**:
```
chrome/browser/download/
components/download/
components/safe_browsing/
```

---

## 四、第三梯队 — 新兴攻击面（代码年轻，review 不足）

### 4.1 WebML / WebNN API

**奖金**: $4,000+ / 个（已有逻辑漏洞实例）
**状态**: 2026 年新出现，已有输入验证不足漏洞

```
third_party/blink/renderer/modules/ml/
services/webnn/
```

### 4.2 Fenced Frames (Privacy Sandbox)

**奖金**: $2,000+ / 个
**状态**: Privacy Sandbox 新特性，实现不成熟

```
content/browser/fenced_frame/
third_party/blink/renderer/core/html/fenced_frame/
```

### 4.3 Digital Credentials API

**奖金**: 未知（全新 API）
**状态**: 刚上线，代码审计覆盖率极低

```
content/browser/webid/digital_credentials/
```

### 4.4 Background Fetch API

**奖金**: $4,000（2025-05 实例）

```
content/browser/background_fetch/
```

### 4.5 File System Access API

**奖金**: $2,000（2025-05 实例）

```
content/browser/file_system_access/
```

---

## 五、活跃研究员参考

| 研究员 | 专注领域 | 特点 |
|--------|---------|------|
| **Luan Herrera** (@lbherrera_) | Extensions / Downloads Policy bypass | 深度专注，持续多年 |
| **Hafiizh** | Frames / Omnibox / SplitView UI | 多点开花，UI 层面 |
| **Alesandro Ortiz** | Navigation / Extensions / DevTools | 高危逻辑漏洞 |
| **Khalil Zhani** | Permission Prompts / Omnibox | 权限系统 |
| **Povcfe (玄武)** | DevTools / PDF Policy bypass | 深度审计 |
| **asnine** | LocalNetworkAccess | 新 feature |
| **lebr0nli** | ServiceWorker | Policy bypass |

---

## 六、不推荐方向

| 方向 | 原因 |
|------|------|
| Site Isolation / OOPIF bypass | Google 内部安全团队重点盯防，外部难出成果 |
| V8 逻辑漏洞 | 竞争极其激烈，Google Big Sleep AI 也在找 |
| Mojo IPC 逻辑漏洞 | 需要深度理解 Chrome 多进程架构，学习曲线陡 |

---

## 七、建议起步路径

1. **先从 Security UI 欺骗入手** — 门槛最低，Fullscreen + Navigation timing window
2. **同时审计 Downloads 保护绕过** — 代码量小，逻辑清晰
3. **逐步深入 Policy Bypass** — ServiceWorker / IFrame sandbox 是 2026 热点
4. **关注新 API** — WebML、Fenced Frames、Digital Credentials 代码年轻
