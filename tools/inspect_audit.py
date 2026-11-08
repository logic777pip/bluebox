#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/inspect_audit.py — 直读 agent 审计日志，统计动作参数分布。

用途：**旁路校验**评测指标。评分代码出过一次归因合并 bug（指标恒为 0 却看着像
「模型不会」），所以关键结论要能从原始日志独立复核一遍，而不是只信汇总表。

用法::

    python tools/inspect_audit.py --tail 200
    python tools/inspect_audit.py --tail 200 --action block_ip --show-args
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

AUDIT = PROJECT_ROOT / "logs" / "agent_audit.jsonl"


def _name(a: Dict[str, Any]) -> str:
    return str(a.get("action") or a.get("name") or "?")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="审计日志动作参数统计")
    ap.add_argument("--path", default=str(AUDIT))
    ap.add_argument("--tail", type=int, default=200)
    ap.add_argument("--action", default=None, help="只看某个动作的参数取值")
    ap.add_argument("--show-args", action="store_true")
    args = ap.parse_args(argv)

    p = Path(args.path)
    if not p.exists():
        print(f"找不到审计日志 {p}")
        return 1
    lines = [l for l in p.read_text(encoding="utf-8").splitlines() if l.strip()][-args.tail:]
    rows: List[Dict[str, Any]] = []
    for l in lines:
        try:
            rows.append(json.loads(l))
        except json.JSONDecodeError:
            continue

    names: collections.Counter = collections.Counter()
    argvals: Dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for r in rows:
        for a in (r.get("actions") or []):
            n = _name(a)
            names[n] += 1
            for k, v in (a.get("args") or {}).items():
                argvals[f"{n}.{k}"][str(v)] += 1

    print(f"读取 {len(rows)} 条审计记录（尾部 {args.tail} 行）")
    print("\n动作频次:")
    for n, c in names.most_common():
        print(f"  {n:<20} {c}")

    print("\n参数取值 Top:")
    keys = [k for k in argvals if not args.action or k.startswith(args.action + ".")]
    for k in sorted(keys):
        top = argvals[k].most_common(4)
        shown = ", ".join(f"{v}(x{c})" for v, c in top)
        print(f"  {k:<28} {shown}")

    rejected = sum(len(r.get("rejected_actions") or []) for r in rows)
    print(f"\n被 schema 拒绝的动作数: {rejected}")
    why = collections.Counter()
    for r in rows:
        for s in (r.get("rejected_actions") or []):
            why[str(s)[:70]] += 1
    for s, c in why.most_common(6):
        print(f"  x{c}  {s}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
