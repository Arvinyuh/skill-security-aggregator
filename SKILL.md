# Skill Security Aggregator

综合安全评分聚合器。调用 Layer1、Layer2、Layer3 三个独立 Skill，计算最终安全评分。

## 架构

```
┌─────────────────────────────────────────────────────────────┐
│              Security Aggregator                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐        │
│  │ Layer1      │   │ Layer2      │   │ Layer3      │        │
│  │ Regex Scan  │   │ Prompt Eval │   │ RAG Scan    │        │
│  │ (100分)     │   │ (100分)     │   │ (100分)     │        │
│  └──────┬──────┘   └──────┬──────┘   └──────┬──────┘        │
│         │                 │                 │               │
│         └────────┬────────┴─────────────────┘               │
│                  │                                          │
│                  ▼                                          │
│         ┌───────────────┐                                  │
│         │  Aggregator   │                                  │
│         │  计算综合评分   │                                  │
│         └───────────────┘                                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## 评分体系

| Layer | Skill | 分值范围 | 权重 |
|-------|-------|----------|------|
| Layer1 | skill-layer1-regex-scan | 0-100 | 35% |
| Layer2 | skill-layer2-prompt-eval | 0-100 | 35% |
| Layer3 | skill-layer3-rag | 0-100 | 30% |

## 综合评分计算

```
综合分数 = Layer1 × 0.35 + Layer2 × 0.35 + Layer3 × 0.30
```

## 风险等级

| 分数范围 | 风险等级 | 建议 |
|----------|----------|------|
| 86-100 | ✅ SAFE | 安全，可安装 |
| 71-85 | 🟢 LOW | 低风险，建议审查 |
| 51-70 | 🟡 MEDIUM | 中等风险，需要审查 |
| 31-50 | 🔴 HIGH | 高风险，建议不安装 |
| 0-30 | 🚨 CRITICAL | 危险，拒绝安装 |

## 使用方法

### 命令行

```bash
python scripts/aggregator.py /path/to/skill
python scripts/aggregator.py /path/to/skill --verbose
python scripts/aggregator.py /path/to/skill --format json
```

### Python API

```python
from scripts.aggregator import aggregate_score, AggregatedResult

# 聚合评分
result: AggregatedResult = aggregate_score("/path/to/skill")

# 访问结果
print(f"综合分数: {result.total_score}/100")
print(f"风险等级: {result.risk_level}")
print(f"Layer1 分数: {result.layer1_score}/100")
print(f"Layer2 分数: {result.layer2_score}/100")
print(f"Layer3 分数: {result.layer3_score}/100")
```

## 输出示例

```
═══════════════════════════════════════════════════════════════
              SKILL SECURITY AGGREGATED REPORT
═══════════════════════════════════════════════════════════════
Skill: example-skill
Path: /path/to/example-skill
Scanned: 2024-01-01T00:00:00
───────────────────────────────────────────────────────────────

LAYER SCORES:
┌─────────────┬──────────┬───────┐
│ Layer       │ Score    │ Weight│
├─────────────┼──────────┼───────┤
│ Layer1      │ 85/100   │ 35%   │
│ Layer2      │ 72/100   │ 35%   │
│ Layer3      │ 90/100   │ 30%   │
└─────────────┴──────────┴───────┘

WEIGHTED CALCULATION:
  85 × 0.35 + 72 × 0.35 + 90 × 0.30 = 81.45

───────────────────────────────────────────────────────────────

FINAL SCORE: 81/100
RISK LEVEL: 🟢 LOW
RECOMMENDATION: 建议审查后安装

═══════════════════════════════════════════════════════════════
```

## 单独运行各层

```bash
# 仅运行 Layer1
python ../skill-layer1-regex-scan/scripts/regex_scanner.py /path/to/skill

# 仅运行 Layer2
python ../skill-layer2-prompt-eval/scripts/prompt_evaluator.py /path/to/skill

# 仅运行 Layer3
python ../skill-layer3-rag/scripts/rag_scanner.py /path/to/skill
```

## 适用场景

- 完整的 Skill 安全评估
- CI/CD 集成
- 批量扫描
- 安全合规报告
