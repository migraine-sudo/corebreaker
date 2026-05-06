# Chrome Audit Ablation Benchmark

消融测试系统：用已知漏洞作为 ground truth，测量审计方法论的检出能力。

## 快速开始

```bash
# 运行完整 benchmark (需要 claude CLI)
./eval/run_benchmark.sh baseline

# 用不同模型
./eval/run_benchmark.sh baseline --model opus

# 修改 CLAUDE.md 后运行消融测试
./eval/run_benchmark.sh no_principle3

# 对比所有实验结果
python3 eval/score.py --compare eval/results/

# 重新评分已有结果 (不重新调用 Claude)
./eval/run_benchmark.sh --score-only baseline
```

## 文件结构

```
eval/
├── ground_truth.jsonl      # 10 entries: 5 core (已知漏洞) + 5 adversarial (非漏洞)
├── score.py                # 评分脚本
├── run_benchmark.sh        # 运行器
├── prompt_template.md      # Claude prompt 模板
├── results/                # 实验结果
│   ├── baseline/
│   │   ├── metadata.json   # 实验元数据
│   │   ├── raw_outputs/    # 每个 case 的 Claude 原始输出
│   │   ├── results.json    # 完整评分结果
│   │   └── scores.txt      # 一行摘要 (用于 git commit message)
│   └── latest -> baseline  # symlink 到最新
└── README.md
```

## 评分维度

| 维度 | 范围 | 含义 |
|------|------|------|
| detection | 0-3 | 是否定位到漏洞 (0=未提及, 3=精确定位) |
| root_cause | 0-2 | 是否理解根因 |
| exploitability | 0-1 | 利用性判断是否正确 |
| fix_quality | 0-2 | 修复建议质量 |
| depth_score | 0-8 | 以上总和 |

## 聚合指标

- **Recall**: detection≥2 的 entry 占比
- **Mean Depth**: 平均 depth_score / 8
- **FPR**: adversarial set 中被误报的比例
- **Overall**: Recall × (1-FPR) × Mean_Depth

## Git 工作流

每次修改 CLAUDE.md 后:
1. `./eval/run_benchmark.sh <experiment_name>`
2. 检查 scores.txt — 是否 regression
3. `git commit` 包含分数

```
git commit -m "ablation: no_principle3 recall=0.60 depth=0.55 fpr=0.20 overall=0.26

Changes: Removed principle 3 (enum condition coverage)
Effect: recall -20% (C4 missed), confirms principle 3 is critical"
```

## 成本

- Sonnet: ~$0.80/轮 (10 cases × ~$0.08 each)
- Opus: ~$8/轮

默认用 Sonnet，重要对比用 Opus。
