# Finding 254 深度分析: Topics API model_version 作为 epoch 标识符

## 结论先行: 严重程度评估

**判定: 低危 / 设计如此 (By Design) -- 不构成可利用的安全漏洞**

原因: model_version 在同一 Chrome 版本的整个生命周期内是**静态的**, 不会因 epoch 切换而改变。只有当 OptimizationGuide 推送新模型时才会变化, 这通常跨越多个 epoch。因此, 在正常使用场景下, colluding sites **无法**通过 version 三元组区分 topic 来自哪个 epoch。

---

## 1. 版本信息返回的精确机制

### 1.1 API 返回结构

在 `browsing_topics_service_impl.cc:511-522` 中, 每个返回的 topic 携带:

```
version = "chrome.{config_version}:{taxonomy_version}:{model_version}"
```

具体构造:
```cpp
result_topic->config_version = "chrome." + NumberToString(candidate_topic.config_version());
result_topic->model_version = NumberToString(candidate_topic.model_version());
result_topic->taxonomy_version = NumberToString(candidate_topic.taxonomy_version());
result_topic->version = config_version + ":" + taxonomy_version + ":" + model_version;
```

Mojo 接口 (`browsing_topics.mojom`) 定义的 `EpochTopic` 结构体将这四个字段全部暴露给 JS:
- `topic` (int32)
- `version` (string) -- 组合版本
- `config_version` (string)
- `model_version` (string)
- `taxonomy_version` (string)

### 1.2 版本来源追溯

每个 epoch 的版本信息在 `BrowsingTopicsCalculator::OnGetTopicsForHostsCompleted()` (calculator.cc:553-557) 中确定:

```cpp
EpochTopics(std::move(top_topics_and_observing_domains),
            padded_top_topics_start_index,
            CurrentConfigVersion(),                                    // config_version
            blink::features::kBrowsingTopicsTaxonomyVersion.Get(),    // taxonomy_version
            model_version,                                             // model_version (from ModelInfo)
            calculation_time_, is_manually_triggered_);
```

- **config_version**: 来自 `CurrentConfigVersion()`, 由编译时 Feature Flags 决定, 当前为 `kInitial=1` 或 `kUsePrioritizedTopicsList=2`
- **taxonomy_version**: 来自 `blink::features::kBrowsingTopicsTaxonomyVersion`, 编译时常量
- **model_version**: 来自 `annotator_->GetBrowsingTopicsModelInfo()->GetVersion()`, 由 OptimizationGuide 服务端下发的 ML 模型决定

---

## 2. model_version 是否在 epoch 间变化?

### 2.1 model_version 的实际更新频率

`model_version` 来自 `optimization_guide::ModelInfo::GetVersion()`, 这是 OptimizationGuide 服务器下发的 BERT 分类模型的版本号 (int64)。

**关键事实:**

1. **模型通过 OptimizationGuide 组件更新推送**, 不是每个 epoch 计算时重新拉取。模型更新频率由 Google 服务端控制, 通常是**数周到数月**一次更新。

2. **同一 Chrome 版本周期内, 模型版本通常保持不变**。即使有多个 epoch (默认每周一个 epoch), 只要 OptimizationGuide 没有推送新模型, model_version 就不会改变。

3. 在 `annotator_impl.cc:463-509` 中, `OnModelUpdated()` 只在新模型到达时触发:
   ```cpp
   void AnnotatorImpl::OnModelUpdated(
       optimization_guide::proto::OptimizationTarget optimization_target,
       base::optional_ref<const optimization_guide::ModelInfo> model_info) {
       // 只在模型实际更新时调用
       version_ = model_metadata->version();
       // ...
   }
   ```

4. 单元测试中使用的 `model_version = 5000000000` 在多个 epoch 测试中保持不变 (见 `browsing_topics_service_impl_unittest.cc:1495`), 这反映了设计意图。

### 2.2 何时 model_version 会在活跃 epoch 间不同?

**唯一可能的场景**: Chrome 在多个 epoch 的保留期内接收了一次 OptimizationGuide 模型更新。这时:
- 旧 epoch 的 model_version = 旧值
- 新 epoch 的 model_version = 新值

单元测试 `NumVersionsInEpochs_ThreeVerisons_ClearedTopics` (unittest:2061-2125) 刻意构造了每个 epoch 不同 model_version 的场景 (1,2,3,4), 但这是**测试用例**, 不是正常运行行为。

`NumVersionsInEpochs()` 函数 (service_impl.cc:544-565) 的存在本身就说明 Chrome 团队**意识到**版本可能不同, 并用它来度量跨 epoch 版本差异:
```cpp
std::set<std::pair<int, int64_t>> distinct_versions;
for (const EpochTopics* epoch : browsing_topics_state_.EpochsForSite(main_frame_domain)) {
    if (epoch->HasValidVersions()) {
        distinct_versions.emplace(epoch->taxonomy_version(), epoch->model_version());
    }
}
return distinct_versions.size();
```

---

## 3. Colluding Sites 能否利用 version 关联 epoch?

### 3.1 正常情况 (同一 Chrome 版本周期)

**不能。** 在同一 Chrome 版本周期内:
- `config_version` 相同 (都是 1 或 2)
- `taxonomy_version` 相同 (编译时常量)
- `model_version` 相同 (模型未更新)

所有 epoch 返回的 `version` 字段完全一致, 例如 `"chrome.1:1:5000000000"`。攻击者无法通过 version 区分 topic 来自哪个 epoch。

### 3.2 模型更新跨越 epoch 边界时

**理论上可以, 但信息极为有限。** 如果模型在某两个 epoch 之间更新:
- Epoch 1-2 的 topic: `version = "chrome.1:1:OLD_MODEL"`
- Epoch 3 的 topic: `version = "chrome.1:1:NEW_MODEL"`

攻击者可以推断: "version=OLD 的 topic 来自较早的 epoch, version=NEW 的 topic 来自较新的 epoch"。但:

1. **模型更新是全局事件**: 所有用户同时经历, 不提供用户级别的区分能力
2. **只能区分模型更新前后两个组, 不能精确到具体 epoch**: 如果有 3 个活跃 epoch 且只发生一次模型更新, 攻击者只能把它们分成两组
3. **攻击者已经知道模型更新时间**: 模型版本号是公开信息, 攻击者自己也能观察到
4. **这不比 epoch 数量本身泄露更多信息**: 如果返回了 3 个不同 topic, 攻击者已经知道它们来自不同 epoch

### 3.3 config_version 变化的场景

`config_version` 在 Feature Flag 切换时改变 (如启用 prioritized_topics_list)。这同样是全局事件, 且配置版本向前向后兼容 (`AreConfigVersionsCompatible()` 在 browsing_topics_state.cc:53-82)。

### 3.4 关键的排序行为

`browsing_topics_service_impl.cc:525-536` 中对结果按 version 排序:
```cpp
std::sort(topics.begin(), topics.end(),
    [](const auto& left, const auto& right) {
        if (left->version != right->version)
            return left->version < right->version;
        return left->topic < right->topic;
    });
```

然后去重:
```cpp
topics.erase(std::unique(topics.begin(), topics.end()), topics.end());
```

这意味着:
1. 如果多个 epoch 返回相同 topic + 相同 version, 会被合并为一个 -- 进一步减少可区分性
2. 排序打乱了 epoch 的时间顺序 -- 即使版本不同, 也不暴露时间先后 (除非攻击者已知版本号的时间映射)

---

## 4. 这是 Bug 还是 By Design?

### 4.1 设计意图分析

Topics API 规范 (W3C PATCG draft) **明确规定** 返回 version 信息。Mojo 接口中的注释说明:

```
// The version that identifies the taxonomy and the algorithm used to
// calculate `topic`. This consists of `config_version`, `model_version`, and
// `taxonomy_version`.
```

版本信息的设计目的是:
1. **让调用者知道 topic 的含义**: 不同 taxonomy 版本中, 同一 topic ID 可能代表不同类别
2. **让调用者知道分类算法**: 不同 model_version 的分类准确度和类别映射可能不同
3. **让服务端正确解释 topic**: 广告竞价服务器需要知道 taxonomy 版本来查询 topic 含义

**这是标准 API 协议的必要组成部分, 不是 bug。**

### 4.2 与 Finding 253 的对比

Finding 253 (已分析) 关注的是 `should_be_filtered` 对随机 topic 的泄露, 这是一个真正的实现缺陷 -- 设计意图 (噪声保护) 被实现错误所破坏。

Finding 254 不同: version 信息是**设计上就暴露的**, 且在正常情况下**不提供 epoch 区分能力**。

---

## 5. 攻击场景的实际可行性评估

### 5.1 Finding 的原始声明

> "The combination can identify which epoch a topic came from. Colluding sites can map topics to specific epochs, track topic persistence across epochs, and reconstruct browsing history."

### 5.2 逐条反驳

1. **"identify which epoch a topic came from"**
   - 错误。在正常情况下所有活跃 epoch 共享相同的 version 三元组。version 不能区分 epoch。

2. **"track topic persistence across epochs"**
   - Topics API 本身就暴露了跨 epoch 信息: 如果同一 topic 在多次 API 调用中出现, 调用者本来就知道用户持续对该类别感兴趣。这不是 version 字段的额外泄露。

3. **"reconstruct browsing history"**
   - 严重夸大。即使在极端场景 (模型更新跨 epoch) 下, 攻击者最多能把 topics 分成两组 (旧模型 / 新模型)。这远远不足以 "重建浏览历史"。

### 5.3 唯一值得关注的边缘场景

如果 Chrome 同时推送了模型更新 + taxonomy 版本更新 + config 版本更新 (三者同时变化), 每个活跃 epoch 可能有唯一的 version 组合。但这种情况:
- 极为罕见 (需要三种独立的更新恰好发生在不同 epoch 边界)
- 仍然是全局事件, 不提供用户级区分
- Chrome 的兼容性检查 (`AreConfigVersionsCompatible`) 在版本不兼容时会**清空所有 epoch**, 阻止跨版本 epoch 共存

---

## 6. BrowsingTopicsState 的 epoch 数据结构

`BrowsingTopicsState` (browsing_topics_state.h) 维护:

```cpp
base::circular_deque<EpochTopics> epochs_;  // 最多 kNumberOfEpochsToExpose + 1 个
base::Time next_scheduled_calculation_time_;
HmacKey hmac_key_;  // 每用户唯一, 用于 domain hashing
```

每个 `EpochTopics` 存储:
- `top_topics_and_observing_domains_` -- 该 epoch 的 top 5 topics + 观察域
- `padded_top_topics_start_index_` -- 真实 topic 与填充 topic 的分界
- `config_version_`, `taxonomy_version_`, `model_version_` -- 版本三元组
- `calculation_time_` -- epoch 计算时间 (不暴露给 API 调用者)
- `from_manually_triggered_calculation_` -- 是否手动触发 (不持久化)

关键: **`calculation_time_` 不暴露给 API 调用者**。这是 epoch 的真实时间标识, 但它只在内部使用 (topic 选择、过期管理), 不通过 `EpochTopic` mojo 结构传递给网页。

---

## 7. 最终评估

| 维度 | 评估 |
|------|------|
| 版本信息暴露 | By Design -- API 规范要求 |
| model_version 跨 epoch 变化 | 正常情况下不变化; 仅在模型更新时变化 (全局、稀有事件) |
| epoch 区分能力 | 正常情况: 无; 极端情况: 仅能分两组, 信息量极低 |
| 用户级追踪能力 | 无 -- 所有用户经历相同的版本变化 |
| 比 API 本身泄露更多信息 | 否 -- topic 本身已暴露跨 epoch 兴趣持续性 |
| VRP 报告价值 | **不建议提交** -- 属于 API 设计范畴, 不是实现缺陷 |

### 与真正漏洞的本质区别

- **Finding 253** (should_be_filtered 泄露): 实现**违背**了设计意图 (噪声保护), 产生了设计上不应存在的 binary oracle --> 真漏洞
- **Finding 254** (version 暴露): 实现**符合**设计意图, 信息暴露是 API 协议的一部分, 且在正常运行条件下不提供 epoch 区分能力 --> 不是漏洞

**建议**: 不提交此 finding。如果一定要利用 Topics API 的 epoch 关联问题, 应该关注更有信息量的侧信道 (如 topic 返回数量、topic 值的时间稳定性模式), 而非已经 by-design 暴露且信息量极低的 version 字段。
