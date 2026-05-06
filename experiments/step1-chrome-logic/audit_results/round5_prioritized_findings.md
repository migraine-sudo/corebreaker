# 第五轮审计 — 最终优先级排序

## 日期: 2026-05-01

## 关键筛选标准
1. 从普通网页可利用（不需要扩展/debugger）
2. 影响 Chrome stable
3. 有具体安全影响（不是 defense-in-depth）
4. 不太可能被别人先报（低撞洞风险）

## Tier 1: 最值得报的

### Finding 253: Topics API random topic 过滤泄露真实 topic 观察状态
- **来源**: Privacy Sandbox Agent
- **位置**: `components/browsing_topics/epoch_topics.cc:175-214`
- **问题**: 5% random topic 的 should_be_filtered 标志继承自真实 topic 的域名集，而非 random topic 本身
- **影响**: 第三方追踪器可以通过统计跨 epoch 的 topic 接收率，区分"我在用户真实 topic 的观察集中" vs "我不在"
- **可利用性**: HIGH — 纯统计攻击，任何嵌入的第三方都能做
- **前提**: 无特殊权限，仅需 document.browsingTopics() 调用
- **VRP 类型**: Privacy violation / Information disclosure

### Finding 254: Topics API model_version 作为 epoch 标识符
- **来源**: Privacy Sandbox Agent  
- **位置**: `components/browsing_topics/browsing_topics_service_impl.cc:512-523`
- **问题**: 返回的 topic 包含 config_version + taxonomy_version + model_version，组合起来可识别 epoch
- **影响**: 串通的网站可以将 topic 映射到特定 epoch，跨 epoch 追踪 topic 持久性，重建浏览历史
- **可利用性**: MEDIUM-HIGH — 需要多站串通
- **前提**: 无

### Finding 255: Shared Storage selectURL 跨域用户偏好泄露
- **来源**: Privacy Sandbox Agent
- **位置**: `content/browser/shared_storage/shared_storage_worklet_host.cc:773-800`
- **问题**: 跨域 worklet 被用户禁用时返回空 URL，不运行 worklet，行为时序与正常路径不同
- **影响**: 时序侧信道泄露用户是否对特定 origin 禁用了 Shared Storage
- **可利用性**: MEDIUM
- **前提**: 无

## Tier 2: 可能值得报的

### Finding 256: Fenced Frame 自动 beacon 发送未分区 cookie
- **位置**: `content/browser/fenced_frame/fenced_frame_reporter.cc:685-713`
- **问题**: IsolationInfo 用 CreateTransient(无 nonce)，自动 beacon 附带未分区 cookie
- **影响**: 报告端点可跨站关联用户（3PC 存在时）
- **可利用性**: MEDIUM（但 3PCD 后影响减小）

### Finding 257: Prerender 激活安全检查不完整 (crbug/340416082)
- **位置**: `content/browser/preloading/prerender/prerender_host.cc:1107-1109`
- **问题**: Android WebView 上 initiator_origin 检查被跳过
- **可利用性**: MEDIUM（仅 Android WebView）
- **风险**: 已知 crbug，可能被追踪

### Finding 258: StorageAccess + BFCache grant 过期后不驱逐
- **位置**: `content/browser/back_forward_cache/back_forward_cache_impl.cc:242`
- **问题**: SAA grant 页面允许进入 BFCache，grant 过期后恢复不检查
- **可利用性**: MEDIUM（攻击者不能强制 BFCache 导航）

## Tier 3: 价值有限
- DNR modifyHeaders 无 forbidden header（可能 by design）
- Prerender Mojo GrantAll（窗口窄）
- offscreen reason 不强制（CWS review 是门控）
- BFCache CSP 过期（by design）
