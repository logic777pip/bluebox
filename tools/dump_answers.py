#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""按 case_id 打印原始答案（repr 形式），用于确认换行/空白是否异常。

用法:
    python tools/dump_answers.py logs/attack_matrix_eval.json --limit 3
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("report", nargs="?", default="logs/attack_matrix_eval.json")
    ap.add_argument("--limit", type=int, default=3)
    ap.add_argument("--class", dest="klass", default=None)
    args = ap.parse_args()

    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    rows = report.get("records") or []
    rows = [r for r in rows if r.get("answer")]

    # 统计换行导致的“词内断行”现象
    broken = 0
    total_nl = 0
    for r in rows:
        ans = r["answer"]
        total_nl += ans.count("\n")
        if re.search(r"[\u4e00-\u9fff]\n[\u4e00-\u9fff]", ans):
            broken += 1
    print(f"含中文词内断行的用例: {broken}/{len(rows)}  平均换行数 {total_nl / max(1, len(rows)):.1f}\n")

    shown = 0
    for r in rows:
        if args.klass and r.get("klass") != args.klass:
            continue
        if shown >= args.limit:
            break
        shown += 1
        print(f"===== {r['case_id']} [{r.get('klass')}/{r.get('family')}] verdict={r.get('verdict')}")
        print(repr(r["answer"][:700]))
        print()

    # 结论行词汇普查：模型用什么词表达判定
    vocab = {}
    for r in rows:
        for m in re.finditer(r"判定为[^\n，。；]{0,12}", r["answer"]):
            vocab[m.group(0)] = vocab.get(m.group(0), 0) + 1
    print("== 「判定为…」短语频次 TOP 30 ==")
    for k, v in sorted(vocab.items(), key=lambda kv: -kv[1])[:30]:
        print(f"  {v:3d}  {k}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
