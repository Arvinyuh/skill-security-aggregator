"""
Skill Security Aggregator
综合安全评分聚合器
调用 Layer1、Layer2、Layer3 三个独立 Skill，计算最终安全评分
"""

import os
import sys
import json
import re as _re
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum
from datetime import datetime


def _normalize_path(path_str: str) -> Path:
    """规范化路径，兼容 Windows/MSYS/Git Bash 路径格式"""
    p = path_str.replace('\\', '/')
    m = _re.match(r'^/([a-zA-Z])/(.*)$', p)
    if m:
        drive = m.group(1).upper()
        rest = m.group(2)
        return Path(f'{drive}:\\{rest.replace("/", os.sep)}')
    return Path(path_str)


class RiskLevel(Enum):
    """风险等级"""
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ═══════════════════════════════════════════════════════════════════════════════
# Skill 路径配置
# ═══════════════════════════════════════════════════════════════════════════════

SKILL_PATHS = {
    "layer1": Path(__file__).parent.parent.parent / "skill-layer1-regex-scan" / "scripts" / "regex_scanner.py",
    "layer2": Path(__file__).parent.parent.parent / "skill-layer2-prompt-eval" / "scripts" / "prompt_evaluator.py",
    "layer3": Path(__file__).parent.parent.parent / "skill-layer3-rag" / "scripts" / "rag_scanner.py",
}


@dataclass
class LayerScore:
    """各层评分结果"""
    layer_name: str
    score: float
    weight: float
    details: Dict = field(default_factory=dict)
    raw_output: str = ""
    error: Optional[str] = None


@dataclass
class AggregatedResult:
    """聚合结果"""
    skill_name: str = ""
    skill_path: str = ""
    total_score: float = 100.0
    risk_level: RiskLevel = RiskLevel.SAFE
    recommendation: str = ""

    # 各层分数
    layer1_score: float = 100.0
    layer2_score: float = 100.0
    layer3_score: float = 100.0

    # 各层详情
    layer1_details: Dict = field(default_factory=dict)
    layer2_details: Dict = field(default_factory=dict)
    layer3_details: Dict = field(default_factory=dict)

    # 原始输出
    layer1_raw: str = ""
    layer2_raw: str = ""
    layer3_raw: str = ""

    # 错误信息
    errors: List[str] = field(default_factory=list)

    # 元数据
    scan_time: str = ""
    execution_time: float = 0.0


class SecurityAggregator:
    """安全评分聚合器"""

    def __init__(self):
        # 权重配置
        self.weights = {
            "layer1": 0.35,  # Regex Scan
            "layer2": 0.35,  # Prompt Eval
            "layer3": 0.30,  # RAG Scan
        }

    def _get_python_executable(self) -> str:
        """获取 Python 解释器路径"""
        return sys.executable or "python"

    def _run_skill(self, skill_path: Path, skill_dir: Path, args: List[str] = None) -> Tuple[str, Optional[str]]:
        """运行独立的 Skill 脚本

        Args:
            skill_path: Skill 脚本路径
            skill_dir: Skill 目录路径
            args: 额外的命令行参数

        Returns:
            (stdout, error)
        """
        if not skill_path.exists():
            return "", f"Skill script not found: {skill_path}"

        cmd = [self._get_python_executable(), str(skill_path)]
        if args:
            cmd.extend(args)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,  # 2分钟超时
                encoding='utf-8',
                errors='ignore',
                cwd=str(skill_dir)
            )

            if result.returncode in [0, 1, 2]:
                # 这些返回码都是有效的
                return result.stdout, None
            else:
                return result.stdout, f"Exit code: {result.returncode}"

        except subprocess.TimeoutExpired:
            return "", "Timeout after 120 seconds"
        except Exception as e:
            return "", str(e)

    def _parse_json_output(self, output: str) -> Optional[Dict]:
        """解析 JSON 输出"""
        try:
            # 尝试直接解析
            return json.loads(output)
        except json.JSONDecodeError:
            # 尝试提取 ```json 代码块
            import re
            match = re.search(r'```json\s*(.*?)\s*```', output, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(1))
                except:
                    pass
        return None

    def _parse_score_from_text(self, output: str, default: float = 100.0) -> float:
        """从文本输出中提取分数"""
        import re

        # 匹配各种分数格式
        patterns = [
            r'SCORE:\s*(\d+(?:\.\d+)?)\s*/\s*100',
            r'Score:\s*(\d+(?:\.\d+)?)\s*/\s*100',
            r'([\d.]+)\s*/\s*100',
        ]

        for pattern in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return float(match.group(1))

        return default

    def aggregate(self, skill_path: Path, verbose: bool = False) -> AggregatedResult:
        """聚合评分

        Args:
            skill_path: Skill 目录路径
            verbose: 是否输出详细信息

        Returns:
            AggregatedResult: 聚合结果
        """
        import time
        start_time = time.time()

        result = AggregatedResult(
            skill_name=skill_path.name,
            skill_path=str(skill_path),
            scan_time=datetime.now().isoformat()
        )

        # 确保 skill 路径存在（兼容 MSYS/Git Bash 路径）
        if not skill_path.exists():
            normalized = _normalize_path(str(skill_path))
            if normalized.exists():
                skill_path = normalized
            result.errors.append(f"Skill path not found: {skill_path}")
            return result

        # 执行 Layer1 - Regex Scan
        if verbose:
            print("Running Layer1: Regex Scanner...")

        layer1_path = SKILL_PATHS["layer1"]
        if layer1_path.exists():
            output, error = self._run_skill(layer1_path, skill_path.parent.parent, [str(skill_path)])
            result.layer1_raw = output

            if error:
                result.errors.append(f"Layer1 error: {error}")
                result.layer1_score = 50.0  # 失败时给中等分
            else:
                # 解析 JSON 或从文本提取分数
                json_data = self._parse_json_output(output)
                if json_data:
                    result.layer1_score = float(json_data.get('score', 100.0))
                    result.layer1_details = json_data
                else:
                    result.layer1_score = self._parse_score_from_text(output)
        else:
            result.errors.append(f"Layer1 not found: {layer1_path}")
            result.layer1_score = 50.0

        # 执行 Layer2 - Prompt Eval (纯 SKILL.md 模式)
        if verbose:
            print("Running Layer2: Prompt Evaluator...")

        layer2_path = SKILL_PATHS["layer2"]
        if layer2_path.exists():
            # 脚本模式
            output, error = self._run_skill(layer2_path, skill_path.parent.parent, [str(skill_path)])
            result.layer2_raw = output

            if error:
                result.errors.append(f"Layer2 error: {error}")
                result.layer2_score = 50.0
            else:
                json_data = self._parse_json_output(output)
                if json_data:
                    result.layer2_score = float(json_data.get('score', 100.0))
                    result.layer2_details = json_data
                else:
                    result.layer2_score = self._parse_score_from_text(output)
        else:
            # SKILL.md 模式 - 纯人工/Prompt 评估
            layer2_skill_md = SKILL_PATHS["layer2"].parent.parent / "SKILL.md"
            if layer2_skill_md.exists():
                result.errors.append("Layer2: 纯 SKILL.md 协议模式，需要手动评估")
                result.errors.append("  → 请阅读 skill-layer2-prompt-eval/SKILL.md 中的评估协议")
                result.layer2_score = 50.0  # 待手动评估后更新
                result.layer2_details = {"mode": "manual", "protocol": "SKILL.md"}
            else:
                result.errors.append(f"Layer2 not found: {layer2_path} and no SKILL.md")
                result.layer2_score = 0.0

        # 执行 Layer3 - RAG Scan
        if verbose:
            print("Running Layer3: RAG Scanner...")

        layer3_path = SKILL_PATHS["layer3"]
        if layer3_path.exists():
            output, error = self._run_skill(layer3_path, skill_path.parent.parent, [str(skill_path)])
            result.layer3_raw = output

            if error:
                result.errors.append(f"Layer3 error: {error}")
                result.layer3_score = 50.0
            else:
                json_data = self._parse_json_output(output)
                if json_data:
                    result.layer3_score = float(json_data.get('score', 100.0))
                    result.layer3_details = json_data
                else:
                    result.layer3_score = self._parse_score_from_text(output)
        else:
            result.errors.append(f"Layer3 not found: {layer3_path}")
            result.layer3_score = 50.0

        # 计算加权总分
        result.total_score = (
            result.layer1_score * self.weights["layer1"] +
            result.layer2_score * self.weights["layer2"] +
            result.layer3_score * self.weights["layer3"]
        )

        # 确定风险等级
        result.risk_level, result.recommendation = self._get_risk_level(result.total_score)

        # 记录执行时间
        result.execution_time = time.time() - start_time

        return result

    def _get_risk_level(self, score: float) -> Tuple[RiskLevel, str]:
        """根据分数确定风险等级"""
        if score >= 86:
            return RiskLevel.SAFE, "安全，可安装"
        elif score >= 71:
            return RiskLevel.LOW, "低风险，建议审查后安装"
        elif score >= 51:
            return RiskLevel.MEDIUM, "中等风险，需要人工审查"
        elif score >= 31:
            return RiskLevel.HIGH, "高风险，建议不安装"
        else:
            return RiskLevel.CRITICAL, "危险，拒绝安装"

    def get_report(self, result: AggregatedResult) -> str:
        """生成文本报告"""
        risk_emoji = {
            RiskLevel.SAFE: "✅",
            RiskLevel.LOW: "🟢",
            RiskLevel.MEDIUM: "🟡",
            RiskLevel.HIGH: "🔴",
            RiskLevel.CRITICAL: "🚨"
        }

        # 计算各层贡献
        l1_contrib = result.layer1_score * self.weights["layer1"]
        l2_contrib = result.layer2_score * self.weights["layer2"]
        l3_contrib = result.layer3_score * self.weights["layer3"]

        lines = [
            "=" * 64,
            "         SKILL SECURITY AGGREGATED REPORT",
            "=" * 64,
            f"Skill: {result.skill_name}",
            f"Path: {result.skill_path}",
            f"Scanned: {result.scan_time}",
            f"Execution time: {result.execution_time:.2f}s",
            "-" * 64,
            "",
            "LAYER SCORES:",
            "┌─────────────┬──────────┬────────┬──────────┐",
            "│ Layer       │ Score    │ Weight │ Contrib  │",
            "├─────────────┼──────────┼────────┼──────────┤",
            f"│ Layer1      │ {result.layer1_score:6.1f}/100 │ 35%   │ {l1_contrib:6.1f}    │",
            f"│ Layer2      │ {result.layer2_score:6.1f}/100 │ 35%   │ {l2_contrib:6.1f}    │",
            f"│ Layer3      │ {result.layer3_score:6.1f}/100 │ 30%   │ {l3_contrib:6.1f}    │",
            "└─────────────┴──────────┴────────┴──────────┘",
            "",
            "WEIGHTED CALCULATION:",
            f"  {result.layer1_score:.1f} × 0.35 + {result.layer2_score:.1f} × 0.35 + {result.layer3_score:.1f} × 0.30 = {result.total_score:.2f}",
            "",
            "-" * 64,
            "",
        ]

        # 添加错误信息
        if result.errors:
            lines.append("ERRORS:")
            for error in result.errors:
                lines.append(f"  ⚠️  {error}")
            lines.append("")

        lines.extend([
            "=" * 64,
            f"FINAL SCORE: {result.total_score:.0f}/100",
            f"RISK LEVEL: {risk_emoji.get(result.risk_level, '')} {result.risk_level.value}",
            f"RECOMMENDATION: {result.recommendation}",
            "=" * 64,
        ])

        return "\n".join(lines)

    def get_json_report(self, result: AggregatedResult) -> str:
        """生成 JSON 报告"""
        data = {
            "skill": {
                "name": result.skill_name,
                "path": result.skill_path
            },
            "scan_time": result.scan_time,
            "execution_time": result.execution_time,
            "weights": self.weights,
            "scores": {
                "layer1": {
                    "score": result.layer1_score,
                    "weight": self.weights["layer1"],
                    "contribution": result.layer1_score * self.weights["layer1"]
                },
                "layer2": {
                    "score": result.layer2_score,
                    "weight": self.weights["layer2"],
                    "contribution": result.layer2_score * self.weights["layer2"]
                },
                "layer3": {
                    "score": result.layer3_score,
                    "weight": self.weights["layer3"],
                    "contribution": result.layer3_score * self.weights["layer3"]
                }
            },
            "total_score": result.total_score,
            "risk_level": result.risk_level.value,
            "recommendation": result.recommendation,
            "errors": result.errors,
            "details": {
                "layer1": result.layer1_details,
                "layer2": result.layer2_details,
                "layer3": result.layer3_details
            }
        }
        return json.dumps(data, indent=2, ensure_ascii=False)


# ═══════════════════════════════════════════════════════════════════════════════
# 入口函数
# ═══════════════════════════════════════════════════════════════════════════════

def aggregate_score(skill_path: str, verbose: bool = False) -> AggregatedResult:
    """聚合指定 Skill 的安全评分

    Args:
        skill_path: Skill 目录路径
        verbose: 是否输出详细信息

    Returns:
        AggregatedResult: 聚合结果
    """
    aggregator = SecurityAggregator()
    return aggregator.aggregate(Path(skill_path), verbose=verbose)


def main():
    """命令行入口"""
    import argparse

    parser = argparse.ArgumentParser(description="Skill Security Aggregator")
    parser.add_argument("path", help="Path to skill folder")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--json", "-j", action="store_true", help="Output JSON format")
    parser.add_argument("--output", "-o", help="Output file path")

    args = parser.parse_args()

    result = aggregate_score(args.path, verbose=args.verbose)

    aggregator = SecurityAggregator()
    if args.json:
        output = aggregator.get_json_report(result)
    else:
        output = aggregator.get_report(result)

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"Report saved to: {args.output}")
    else:
        print(output)

    # 返回码
    if result.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
        exit(2)
    elif result.risk_level == RiskLevel.MEDIUM:
        exit(1)
    else:
        exit(0)


if __name__ == "__main__":
    main()
