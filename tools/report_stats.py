#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""汇总报告里的分布型事实（供 md 文档引用），并暴露量具异常。

用法:
    python tools/report_stats.py logs/attack_matrix_eval.json
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("report", nargs="?", default="logs/attack_matrix_eval.json")
    args = ap.parse_args()
    data = json.loads(Path(args.report).read_text(encoding="utf-8"))
    rows = data["records"]
    s = data["summary"]

    print("== 会话级事实 ==")
    for k in ("review_rate", "grounded_rate", "contradictory_rate", "irreversible_action_rate"):
        print(f"  overall.{k} = {s['overall'].get(k)}")
    for k in ("normal", "conventional", "stealthy", "ai_attack"):
        b = s["by_class"][k]
        print(f"  {k:<13} unclear={b.get('unclear_rate')} 矛盾={b.get('contradictory_rate')} "
              f"ttp_hit={b.get('ttp_hit_rate')} 审查={b.get('review_rate')}")

    print("\n== 动作 ==")
    acts = Counter(a for r in rows for a in r["actions"])
    print("  实际执行:", dict(acts.most_common()))
    rej = Counter(x for r in rows for x in r["rejected"])
    print(f"  闸门拒绝合计 {sum(rej.values())} 次:", dict(rej.most_common(8)))
    print(f"  有动作的用例 {sum(1 for r in rows if r['action_rate'])}/{len(rows)}")
    print(f"  被禁动作用例 {[r['case_id'] for r in rows if r['forbidden_action']]}")

    print("\n== 工具调用痕迹（回答文本内）==")
    toolish = [r["case_id"] for r in rows if "```tool" in r["answer"] or "工具:" in r["answer"]]
    print(f"  含工具块的回答 {len(toolish)}/{len(rows)} {toolish[:6]}")

    print("\n== 资源采样合理性检查 ==")
    for f in ("rss_mb", "vram_mb", "cpu_s"):
        vals = [float(r[f]) for r in rows]
        nz = [v for v in vals if v != 0]
        print(f"  {f:<8} n={len(vals)} 非零={len(nz)} min={min(vals)} "
              f"median={statistics.median(vals)} max={max(vals)}")
        print(f"           前 5 大: {sorted(vals, reverse=True)[:5]}")
    print(f"  首案 rss={rows[0]['rss_mb']} 末案 rss={rows[-1]['rss_mb']}")

    print("\n== 分类家族明细 ==")
    for fam, v in sorted(s["by_family"].items(), key=lambda kv: (kv[1]["klass"], kv[0])):
        print(f"  {v['klass']:<13} {fam:<26} n={v['n']} 判攻击={v['attack_rate']:.2f} "
              f"动作={v['action_rate']:.2f} 动作对={v['correct_action_rate']:.2f} 被禁={v['forbidden']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
