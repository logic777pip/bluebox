#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""training/inspect_dataset_schema.py — 探查上游数据集真实字段结构。

用途：当 data_prep.py 出现 skip_schema / skip_duplicate 异常偏高，
      或某个源加载失败时，用本脚本打印前 N 行的列名与样例值，
      以便在 normalize_row() 里补对应的映射。

用法:
    python training/inspect_dataset_schema.py --sources cybersec100k,blackbox_cot
    python training/inspect_dataset_schema.py --sources all --rows 2
    python training/inspect_dataset_schema.py --hf id:stindardlogic/cybersecurity-sft-100k

所有输出均经 security.sanitize 脱敏（R1）。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security.sanitize import get_logger, mask_text  # noqa: E402

LOG = get_logger("inspect_schema")

os.environ.setdefault("HF_ENDPOINT", "https://hf-mirror.com")
os.environ.setdefault("HF_HUB_DOWNLOAD_TIMEOUT", "30")

# 与 data_prep.py 保持一致（此处独立定义，避免 import 时的副作用）
SOURCES: Dict[str, str] = {
    "fenrir": "AlicanKiraz0/Cybersecurity-Dataset-Fenrir-v2.1",
    "cybersec100k": "stindardlogic/cybersecurity-sft-100k",
    "kimicot": "echel0nn1881/kimi-cyber-reasoning",
    "cti": "reloading0101/threat-intelligence-dataset",
    "blackbox_cot": "blackboxanalytics/BlackBox-CyberSec-CoT-v1",
    "incident_response": "AYI-NEDJIMI/incident-response-en",
    "phishing_soc": "Ellbendls/phishing-email-soc-agent",
    "attackqa": "gagan3012/AttackQA",
}

MAX_CELL = 160          # 单个字段值最多打印多少字符
MAX_LIST = 3            # 列表最多展示几项


def _shrink(value: Any) -> Any:
    """把字段值压成可打印的小对象，避免刷屏。"""
    if isinstance(value, str):
        s = mask_text(value).replace("\n", "\\n")
        return s if len(s) <= MAX_CELL else s[:MAX_CELL] + f"...(+{len(s) - MAX_CELL})"
    if isinstance(value, list):
        head = [_shrink(v) for v in value[:MAX_LIST]]
        return head + ([f"...(+{len(value) - MAX_LIST})"] if len(value) > MAX_LIST else [])
    if isinstance(value, dict):
        return {k: _shrink(v) for k, v in list(value.items())[:8]}
    return value


def describe(hf_id: str, rows: int, split: Optional[str]) -> None:
    from datasets import load_dataset

    print(f"\n===== {hf_id} =====")
    ds = None
    errors: List[str] = []
    for kwargs in (
        {"split": split or "train", "streaming": True},
        {"split": "train", "streaming": False},
        {"streaming": True},
    ):
        try:
            ds = load_dataset(hf_id, **kwargs)
            print(f"[ok] load_dataset kwargs={kwargs}")
            break
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{kwargs} -> {type(exc).__name__}: {mask_text(str(exc))[:200]}")
    if ds is None:
        print("[FAIL] 所有加载方式都失败：")
        for e in errors:
            print("   -", e)
        return

    # DatasetDict 情况：列出可用 split
    if hasattr(ds, "keys") and not hasattr(ds, "features"):
        print("[info] 返回 DatasetDict，可用 split:", list(ds.keys()))
        ds = ds[list(ds.keys())[0]]

    if getattr(ds, "features", None) is not None:
        print("[info] features:", list(ds.features.keys()))

    print(f"[info] 采样 {rows} 行：")
    iterator = iter(ds)
    for i in range(rows):
        try:
            row = next(iterator)
        except StopIteration:
            break
        except Exception as exc:  # noqa: BLE001
            print(f"  [row {i}] 迭代异常: {type(exc).__name__}: {mask_text(str(exc))[:200]}")
            break
        print(f"  --- row {i} columns={list(row.keys())}")
        print("     ", json.dumps(_shrink(row), ensure_ascii=False)[:2000])


def dedup_check(name: str, limit: int, stream: bool = True) -> None:
    """复用 data_prep 的真实归一化/脱敏逻辑，统计重复率并打印重复样例。

    用于排查 data_prep 报告中 skip_duplicate 异常偏高（疑似归一化把所有行剪成同一条
    或镜像站流式迭代循环）。stream=False 时走整份下载，用于对比确认。
    """
    sys.path.insert(0, str(PROJECT_ROOT / "training"))
    import data_prep as dp  # noqa: PLC0415

    print(f"  [mode] stream={stream}")
    seen: Dict[str, int] = {}
    dupes = 0
    total = 0
    schema_skipped = 0
    for _src, row in dp.iter_hf(name, limit, stream=stream):
        msgs = dp.normalize_row(row)
        if not msgs:
            schema_skipped += 1
            if schema_skipped == 1:
                print("  [skip_schema] 首行字段:", list(row.keys()))
                print("  [skip_schema] 样例:",
                      json.dumps(_shrink(row), ensure_ascii=False)[:600])
            continue
        msgs = dp.ensure_system(dp.scrub_messages(msgs, mask_ip=True))
        key = "\x1f".join(m["content"] for m in msgs)
        total += 1
        if key in seen:
            dupes += 1
            if dupes <= 2:
                preview = mask_text(key)[:150].replace("\n", " ")
                print(f"  [dupe] 与第 {seen[key]} 行相同：{preview}")
        else:
            seen[key] = total
    print(f"  => total={total} unique={len(seen)} dupes={dupes} skip_schema={schema_skipped}")


def list_files(hf_id: str, limit: int = 40) -> None:
    """列出 HF 仓库内的文件，用于定位 DataFilesNotFoundError（缺 parquet/csv/jsonl）。"""
    from huggingface_hub import HfApi

    try:
        files = HfApi().list_repo_files(hf_id)
    except Exception as exc:  # noqa: BLE001
        print(f"  [FAIL] list_repo_files: {type(exc).__name__}: {mask_text(str(exc))[:300]}")
        return
    print(f"  repo 内文件数: {len(files)}")
    for f in files[:limit]:
        print("   -", f)
    if len(files) > limit:
        print(f"   ...(+{len(files) - limit})")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="探查上游数据集字段结构")
    ap.add_argument("--sources", default="all",
                    help="all | 逗号分隔（%s）" % ",".join(SOURCES))
    ap.add_argument("--hf", default=None, help="直接指定 HF 数据集 id（忽略 --sources）")
    ap.add_argument("--rows", type=int, default=2)
    ap.add_argument("--split", default=None, help="指定 split，默认先试 train")
    ap.add_argument("--dedup-check", action="store_true",
                   help="复用 data_prep 的归一化逻辑统计重复率（排查 skip_duplicate 异常）")
    ap.add_argument("--no-stream", action="store_true", help="dedup-check 时改走整份下载")
    ap.add_argument("--list-files", action="store_true", help="列出 repo 文件清单（排查 DataFilesNotFoundError）")
    args = ap.parse_args(argv)

    if args.hf:
        targets = {"custom": args.hf}
    elif args.sources == "all":
        targets = SOURCES
    else:
        names = [s.strip() for s in args.sources.split(",") if s.strip()]
        unknown = [n for n in names if n not in SOURCES]
        if unknown:
            ap.error(f"未知源: {unknown}；可选 {list(SOURCES)}")
        targets = {n: SOURCES[n] for n in names}

    for name, hf_id in targets.items():
        print(f"\n########## {name} ##########")
        try:
            if args.list_files:
                list_files(hf_id)
            elif args.dedup_check:
                dedup_check(name, args.rows if args.rows > 2 else 200, stream=not args.no_stream)
            else:
                describe(hf_id, args.rows, args.split)
        except Exception as exc:  # noqa: BLE001
            print(f"[FAIL] {name}: {type(exc).__name__}: {mask_text(str(exc))[:300]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
