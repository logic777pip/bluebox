#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""攻防矩阵评测结果诊断：按类别/家族拆解 verdict 分布，定位 unclear 堆积原因。

用法:
    python tools/analyze_attack_eval.py logs/attack_matrix_eval.json
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


def _load(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _rows(report: dict) -> list[dict]:
    for key in ("rows", "cases", "records", "details"):
        val = report.get(key)
        if isinstance(val, list):
            return val
    return []


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("report", nargs="?", default="logs/attack_matrix_eval.json")
    ap.add_argument("--show-unclear", type=int, default=6, help="每类打印若干 unclear 样本摘要")
    args = ap.parse_args()

    path = Path(args.report)
    report = _load(path)
    rows = _rows(report)
    print(f"== 报告 {path} ==")
    print(f"顶层键: {sorted(report.keys())}")
    print(f"用例数: {len(rows)}\n")
    if not rows:
        return 0

    sample = rows[0]
    print("字段:", sorted(sample.keys()), "\n")

    by_class = defaultdict(list)
    for r in rows:
        by_class[r.get("klass") or r.get("class") or "?"].append(r)

    for klass, items in sorted(by_class.items()):
        verdicts = Counter(str(r.get("verdict")) for r in items)
        print(f"---- {klass} (n={len(items)}) verdict={dict(verdicts)}")

        by_fam = defaultdict(list)
        for r in items:
            by_fam[r.get("family", "?")].append(r)
        for fam, fitems in sorted(by_fam.items()):
            vc = Counter(str(x.get("verdict")) for x in fitems)
            atk = sum(1 for x in fitems if x.get("is_attack"))
            acts = Counter()
            for x in fitems:
                for a in (x.get("actions") or []):
                    acts[a] += 1
            print(f"    {fam:26s} n={len(fitems):2d} attack={atk:2d} verdict={dict(vc)}")
            if acts:
                print(f"      actions: {dict(acts)}")
        print()

    # unclear 样本摘要：看模型到底说了什么
    print(f"== unclear 样本抽样（每类最多 {args.show_unclear} 条）==")
    shown = defaultdict(int)
    for r in rows:
        if str(r.get("verdict")) != "unclear":
            continue
        klass = r.get("klass") or "?"
        if shown[klass] >= args.show_unclear:
            continue
        shown[klass] += 1
        ans = (r.get("answer") or "").replace("\n", " ")
        print(f"[{klass}/{r.get('family')}] {r.get('case_id')}")
        print(f"   evidence={r.get('verdict_evidence')}")
        print(f"   answer[:260]={ans[:260]}")
    print()

    # 误报明细（normal 被判 attack）
    print("== 误报明细（is_attack=False 但 verdict=attack）==")
    for r in rows:
        if not r.get("is_attack") and str(r.get("verdict")) == "attack":
            print(f"  {r.get('case_id')} [{r.get('family')}] hard_neg={r.get('hard_negative')} "
                  f"acts={(r.get('actions') or [])[:4]}")
            print(f"    evidence={r.get('verdict_evidence')}")
    print()

    # 漏报明细（attack 但未被识别）
    print("== 漏报明细（is_attack=True 但 verdict!=attack）==")
    for r in rows:
        if r.get("is_attack") and str(r.get("verdict")) != "attack":
            print(f"  {r.get('case_id')} [{r.get('klass')}/{r.get('family')}] "
                  f"verdict={r.get('verdict')} acts={(r.get('actions') or [])[:4]}")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
