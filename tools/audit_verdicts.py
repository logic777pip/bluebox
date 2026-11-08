#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""人工复核：打印误报/漏报用例的**结论段原文**，逐条确认判定器没冤枉也没放过。

用法:
    python tools/audit_verdicts.py logs/attack_matrix_eval.json --kind fp
    python tools/audit_verdicts.py logs/attack_matrix_eval.json --kind fn
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def conclusion(answer: str) -> str:
    for m in ("【研判结论】", "【结论】"):
        i = answer.find(m)
        if i >= 0:
            tail = answer[i + len(m):]
            j = tail.find("\n\n")
            return tail[:j if j > 0 else 400]
    return answer[:400]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("report", nargs="?", default="logs/attack_matrix_eval.json")
    ap.add_argument("--kind", choices=("fp", "fn", "all"), default="all")
    args = ap.parse_args()

    rows = json.loads(Path(args.report).read_text(encoding="utf-8")).get("records", [])
    fp = [r for r in rows if not r["is_attack"] and r["attack"]]
    fn = [r for r in rows if r["is_attack"] and not r["attack"]]

    if args.kind in ("fp", "all"):
        print(f"===== 误报 FP {len(fp)} 条（非攻击 → 被判攻击）=====")
        for r in fp:
            print(f"\n--- {r['case_id']} [{r['klass']}/{r['family']}] "
                  f"hard_neg={r['hard_negative']} actions={r['actions']}")
            print("  结论:", conclusion(r["answer"]).replace("\n", " / ")[:300])

    if args.kind in ("fn", "all"):
        print(f"\n===== 漏报 FN {len(fn)} 条（攻击 → 未判为攻击）=====")
        for r in fn:
            print(f"\n--- {r['case_id']} [{r['klass']}/{r['family']}] "
                  f"verdict={r['verdict']} actions={r['actions']}")
            print("  结论:", conclusion(r["answer"]).replace("\n", " / ")[:300])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
