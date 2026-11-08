#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/read_log.py — 读取 PowerShell 重定向产生的 UTF-16 日志并做过滤。

存在的理由：`python -c "多行脚本"` 在 PowerShell 里会把终端卡在续行提示，
`| Select-Object` 又会把退出码变成管道的（假 exit 1）。所以统一改为
「脚本自己写/读 UTF-8 文件」，这个工具就是读那一侧。

用法:
    python tools/read_log.py logs/agent_local_test.log --tail 40
    python tools/read_log.py logs/train_v2.log --grep "step |eval_loss|Trainable"
    python tools/read_log.py logs/refat_smoke.log --grep "refat|robustness|alpha"
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def read_text(path: Path) -> str:
    """自动识别 UTF-16 / UTF-8 / UTF-8-BOM。"""
    raw = path.read_bytes()
    for enc in ("utf-16", "utf-8-sig", "utf-8", "gbk"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, UnicodeError):
            continue
    return raw.decode("utf-8", errors="replace")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="读取（可能是 UTF-16 的）日志")
    ap.add_argument("path")
    ap.add_argument("--tail", type=int, default=0, help="只显示最后 N 行")
    ap.add_argument("--head", type=int, default=0, help="只显示前 N 行")
    ap.add_argument("--grep", default=None, help="正则过滤（不区分大小写）")
    args = ap.parse_args(argv)

    path = Path(args.path)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    if not path.exists():
        print(f"[error] 文件不存在: {path}", file=sys.stderr)
        return 2

    text = read_text(path)
    # 去掉 PowerShell 错误记录的装饰行，保留有效内容
    lines = [ln.rstrip() for ln in text.splitlines()]
    lines = [ln for ln in lines if not ln.strip().startswith(("所在位置", "+ ", "    +"))]

    if args.grep:
        rx = re.compile(args.grep, re.I)
        lines = [ln for ln in lines if rx.search(ln)]
    if args.head:
        lines = lines[: args.head]
    if args.tail:
        lines = lines[-args.tail:]

    print(f"[{path.relative_to(PROJECT_ROOT) if path.is_relative_to(PROJECT_ROOT) else path}]"
          f" {len(lines)} 行")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
