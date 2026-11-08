#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/compare_evals.py — 对比两份评测报告（A/B 净效果）。

用途：改了闸门/知识库/提示词之后，要能一眼看出**哪个指标动了、动了多少**，
而不是只看单次运行的绝对值。本项目已有 `--rescore` 离线重打分，
两份报告可以来自同一批模型输出，因此对比是干净的。

用法::

    python tools/compare_evals.py logs/eval_gate_off.json logs/eval_gate_on.json
    python tools/compare_evals.py A.json B.json --label-a 关闭 --label-b 开启 --json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# 分组展示，便于快速定位「检测 / 溯源 / 诚实性 / 反制 / 闸门 / 工程面」
GROUPS: List[tuple[str, List[str]]] = [
    ("检测", ["tpr", "tpr_strict", "fpr", "hard_negative_fpr", "hard_negative_far",
              "precision", "recall", "f1", "accuracy"]),
    ("检测·分类", ["normal.tpr", "normal.specificity", "normal.benign_rate", "normal.fpr",
                    "conventional.tpr", "conventional.tpr_strict",
                    "stealthy.tpr", "stealthy.tpr_strict",
                    "ai_attack.tpr", "ai_attack.tpr_strict"]),
    ("误报面", ["normal.unjustified_attack_rate", "normal.volume_only_rate",
                 "normal.forbidden_action_rate", "normal.irreversible_action_rate",
                 "unjustified_attack_rate", "volume_only_rate"]),
    ("机制审计", ["discriminator_rate", "unjustified_attack_rate", "volume_only_rate",
                  "address_nature_used_rate", "exempt_excuse_rate",
                  "contract_word_rate", "hedge_only_rate", "contradictory_rate",
                  "unclear_rate", "tp_hedged_rate"]),
    ("AI 黑盒", ["ai.injection_resistance", "ai.injection_flag_rate", "ai.complied_rate",
                  "ai_attack.injection_resistance", "ai_attack.injection_flag_rate"]),
    ("动作", ["action_rate", "correct_action_rate", "forbidden_action_rate",
               "irreversible_action_rate", "gate_rejected_rate"]),
    ("溯源", ["attr_host", "attr_peer", "attr_carrier", "attr_shape", "attr_ttp",
              "attr_pqc", "attr_cover", "attr_decoy"]),
    ("诚实性", ["decrypt_hallucination", "uncertainty_marked",
                 "fabrication_rate", "unsupported_number_rate"]),
    ("代价", ["latency_s_mean", "latency_s_p50", "latency_s_p95",
               "cpu_s_mean", "rss_mb_mean", "rss_mb_max", "vram_mb_mean",
               "tokens_per_case", "tokens_total"]),
    ("反制与隔离", ["contain_correct", "block_c2_correct", "block_outbound",
                    "block_host_ip", "block_fabricated", "forensics",
                    "evidence_first", "confirm_gate", "wrong_target", "overreaction"]),
    ("闸门与工具", ["gate_rejected_rate", "gate_corrected_rate", "tool_call_rate"]),
    ("工程面", ["schema_valid", "rejected_actions", "review_rate", "grounded_rate",
                "variant_agreement", "latency_p50", "latency_p95"]),
]

# 这些指标「越大越好」，用于标注方向
HIGHER_BETTER = {
    "tpr", "tpr_strict", "precision", "recall", "f1", "accuracy",
    "specificity", "benign_rate", "discriminator_rate", "contract_word_rate",
    "injection_resistance", "injection_flag_rate", "address_nature_used_rate",
    "attr_host", "attr_peer", "attr_carrier", "attr_shape", "attr_ttp",
    "attr_pqc", "attr_cover", "attr_decoy", "uncertainty_marked",
    "contain_correct", "block_c2_correct", "block_outbound",
    "forensics", "evidence_first", "confirm_gate",
    "schema_valid", "grounded_rate", "tool_call_rate",
}

# 指标名后缀 → 方向（越**小**越好），优先于 HIGHER_BETTER
LOWER_BETTER_SUFFIX = ("_rate", "_fpr", "_far", "_mean", "_max", "_p50", "_p95")
LOWER_BETTER_EXCEPT = {
    "discriminator_rate", "contract_word_rate", "injection_resistance",
    "injection_flag_rate", "address_nature_used_rate", "benign_rate",
    "specificity", "tpr", "tpr_strict", "precision", "recall", "f1", "accuracy",
    "action_rate", "correct_action_rate", "grounded_rate", "review_rate",
    "variant_agreement",
}


def _flatten(s: Dict[str, Any]) -> Dict[str, Any]:
    """把嵌套 summary 压平，让攻防评测（overall/by_class/ai_blackbox）也能通用对比。"""
    if "overall" not in s:
        return s
    flat: Dict[str, Any] = {}
    for k, v in (s.get("overall") or {}).items():
        if isinstance(v, dict):
            for stat in ("mean", "max", "p50", "p95"):
                if stat in v:
                    flat[f"{k}_{stat}"] = v[stat]
        elif isinstance(v, (int, float)):
            flat[k] = v
    for klass, b in (s.get("by_class") or {}).items():
        if not isinstance(b, dict) or not b.get("n"):
            continue
        for kk, vv in b.items():
            if isinstance(vv, (int, float)):
                flat[f"{klass}.{kk}"] = vv
    for k, v in (s.get("ai_blackbox") or {}).items():
        if isinstance(v, (int, float)):
            flat[f"ai.{k}"] = v
    # 兼容隐蔽信道评测的命名
    if "latency_s_p50" in flat:
        flat.setdefault("latency_p50", flat["latency_s_p50"])
        flat.setdefault("latency_p95", flat["latency_s_p95"])
    return flat


def load(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return _flatten(data.get("summary", data))


def _direction(metric: str, delta: float) -> str:
    base = metric.split(".")[-1]
    if abs(delta) < 1e-9:
        return "不变"
    if base in HIGHER_BETTER:
        return "改善" if delta > 0 else "变差"
    if base in LOWER_BETTER_EXCEPT:
        return "改善" if delta > 0 else "变差"
    if base.endswith(LOWER_BETTER_SUFFIX) or "rate" in base:
        return "改善" if delta < 0 else "变差"
    return "—"


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="对比两份评测报告")
    ap.add_argument("a", help="基线报告 JSON")
    ap.add_argument("b", help="对照报告 JSON")
    ap.add_argument("--label-a", default="基线")
    ap.add_argument("--label-b", default="对照")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    a = load(Path(args.a))
    b = load(Path(args.b))
    rows: List[Dict[str, Any]] = []
    for group, keys in GROUPS:
        for k in keys:
            if k not in a or k not in b:
                continue
            va, vb = a[k], b[k]
            if not isinstance(va, (int, float)) or not isinstance(vb, (int, float)):
                continue
            rows.append({"group": group, "metric": k, "a": va, "b": vb,
                         "delta": round(vb - va, 4)})

    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 0

    print(f"{'组':<10}{'指标':<26}{args.label_a:>12}{args.label_b:>12}{'变化':>12}  评价")
    print("-" * 92)
    last = None
    for r in rows:
        if r["group"] != last:
            last = r["group"]
        d = r["delta"]
        verdict = _direction(r["metric"], d)
        print(f"{r['group']:<10}{r['metric']:<26}{r['a']:>12.4f}{r['b']:>12.4f}"
              f"{d:>+12.4f}  {verdict}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
