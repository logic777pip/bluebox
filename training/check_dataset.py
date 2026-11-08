#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""training/check_dataset.py — 数据集质量门禁（训练前必跑）。

检查项:
  1. 每行是合法 JSON，且含非空 messages 列表
  2. role 只能是 system / user / assistant，且以 assistant 结尾
  3. 消息长度在阈值内（过短样本对 3B 模型无信息量）
  4. 所有 ```action / 裸 JSON 动作块必须通过 security.action_schema 校验（R3）
  5. 文本中不得出现疑似真实凭据（用 sanitize 的规则做反向探测）

用法:
    python training/check_dataset.py --files data/sft_dataset.jsonl data/eval_dataset.jsonl
退出码: 0 通过 / 1 存在问题
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security.action_schema import SchemaError, validate_action  # noqa: E402
from security.sanitize import mask_text  # noqa: E402

VALID_ROLES = {"system", "user", "assistant"}
ACTION_BLOCK_RE = re.compile(r"\{[^{}]*\"action\"\s*:[^{}]*\}", re.S)
# 与 security/sanitize.py 保持一致的严格 IPv4（八位组 ≤255）；
# 不能用宽松的 \d{1,3} 版本，否则会把 123.456.789.012 这类假 IP/占位符误报。
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOC_IP_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.", "127.0.0.1")


def check_messages(msgs: Any, idx: int) -> List[str]:
    errs: List[str] = []
    if not isinstance(msgs, list) or not msgs:
        return [f"第 {idx} 行: messages 缺失或为空"]
    roles = []
    for m in msgs:
        if not isinstance(m, dict) or "role" not in m or "content" not in m:
            errs.append(f"第 {idx} 行: 消息结构非法 {mask_text(str(m))[:60]}")
            continue
        if m["role"] not in VALID_ROLES:
            errs.append(f"第 {idx} 行: 非法 role={m['role']}")
        if not isinstance(m["content"], str) or not m["content"].strip():
            errs.append(f"第 {idx} 行: content 为空（role={m['role']}）")
        roles.append(m["role"])
    if roles and roles[-1] != "assistant":
        errs.append(f"第 {idx} 行: 最后一条不是 assistant（{roles[-1]}），train_on_responses_only 会丢样本")
    return errs


def check_actions(msgs: List[Dict[str, str]], idx: int) -> Tuple[List[str], int, int, int]:
    """检查 assistant 输出中的**动作 JSON**。

    关键：不能把「以 { 开头的行」都当成动作 —— 真实安全数据里满是代码/JSON 片段，
    那会产生大量误报。判定条件：该行能 json.loads 成功，**且含 action/name 键**，
    才视为动作并送 schema 校验。

    返回 (错误, 动作总数, 通过数, 被忽略的 JSON 片段数)。
    """
    errs: List[str] = []
    total = passed = ignored = 0
    for m in msgs:
        if m.get("role") != "assistant":
            continue
        for line in m.get("content", "").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                ignored += 1          # 代码片段/非 JSON，不算动作
                continue
            if not isinstance(obj, dict) or not ("action" in obj or "name" in obj):
                ignored += 1          # 只是 JSON 示例（如日志样例），不算动作
                continue
            total += 1
            try:
                validate_action(obj)          # R3：默认拒绝
                passed += 1
            except SchemaError as exc:
                errs.append(f"第 {idx} 行: 动作未通过 schema -> {exc}")
            except Exception as exc:  # noqa: BLE001
                errs.append(f"第 {idx} 行: 动作解析异常 -> {exc}")
    return errs, total, passed, ignored


def check_credentials(msgs: List[Dict[str, str]], idx: int) -> List[str]:
    """反向探测：若脱敏后内容发生变化，说明原文含疑似真实凭据。"""
    errs: List[str] = []
    for m in msgs:
        content = m.get("content", "")
        masked = mask_text(content)
        # 训练数据应使用 RFC5737 文档网段或占位符，不得出现真实内网/公网 IP
        bare = [ip for ip in _IPV4_RE.findall(content) if not ip.startswith(DOC_IP_PREFIXES)]
        if bare:
            errs.append(f"第 {idx} 行: 含非文档网段 IP {bare[:3]}（请用 RFC5737 或占位符）")
        if masked != content and "password" in content.lower():
            errs.append(f"第 {idx} 行: 疑似明文口令（应改为占位符 <PASSWORD>）")
    return errs


def check_file(path: Path, min_chars: int) -> Tuple[List[str], Counter]:
    errs: List[str] = []
    stats: Counter = Counter()
    with path.open("r", encoding="utf-8") as fh:
        for idx, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            stats["rows"] += 1
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                errs.append(f"第 {idx} 行: JSON 解析失败 -> {exc}")
                continue
            msgs = row.get("messages")
            e = check_messages(msgs, idx)
            errs.extend(e)
            if e:
                continue

            code_chars = sum(len(m["content"]) for m in msgs)
            stats["chars"] += code_chars
            stats["turns"] += len(msgs)
            if code_chars < min_chars:
                errs.append(f"第 {idx} 行: 样本过短（{code_chars} < {min_chars} 字符）")

            stats["samples"] += 1
            e2, total, passed, ignored = check_actions(msgs, idx)
            errs.extend(e2)
            stats["actions_total"] += total
            stats["actions_passed"] += passed
            stats["json_snippets_ignored"] += ignored
            errs.extend(check_credentials(msgs, idx))
    return errs, stats


def purge_file(path: Path, min_chars: int, assume_yes: bool) -> int:
    """--fix：剔除未通过检查的样本并重写文件（R5 不可逆写入 → 两阶段确认）。

    返回删除的行数。仅当出现真正的硬错误（结构/角色/动作 schema/凭据）时才删样本；
    过短样本也会一并剔除（对 3B 模型无信息量）。
    """
    keep: List[Dict[str, Any]] = []
    dropped: Counter = Counter()
    total = 0
    with path.open("r", encoding="utf-8") as fh:
        for idx, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                dropped["json"] += 1
                continue
            msgs = row.get("messages")
            if check_messages(msgs, idx):
                dropped["structure"] += 1
                continue
            if sum(len(m["content"]) for m in msgs) < min_chars:
                dropped["too_short"] += 1
                continue
            errs, total_a, passed_a, _ignored = check_actions(msgs, idx)
            if errs or (total_a and passed_a != total_a):
                dropped["bad_action"] += 1
                continue
            if check_credentials(msgs, idx):
                dropped["credentials"] += 1
                continue
            keep.append(row)

    n_drop = total - len(keep)
    if n_drop == 0:
        print(f"  [fix] {path.name}: 无需修改")
        return 0

    print(f"  [fix] {path.name}: 将删除 {n_drop}/{total} 条 —— {dict(dropped)}")
    if not assume_yes:
        a1 = input("阶段一确认：输入 yes 执行剔除 > ").strip().lower()
        if a1 != "yes":
            print("  已中止，未修改文件。")
            return 0
        a2 = input("阶段二确认：再次输入 yes > ").strip().lower()
        if a2 != "yes":
            print("  已中止，未修改文件。")
            return 0

    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as fh:
        for row in keep:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    tmp.replace(path)
    print(f"  [fix] 已重写 {path.name}: {len(keep)} 条保留，{n_drop} 条剔除")
    return n_drop


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="SFT/评测数据集质量门禁")
    ap.add_argument("--files", nargs="+",
                    default=["data/sft_dataset.jsonl", "data/eval_dataset.jsonl"])
    ap.add_argument("--min-chars", type=int, default=80)
    ap.add_argument("--fix", action="store_true",
                    help="剔除未通过检查的样本并重写文件（需两阶段确认）")
    ap.add_argument("--yes", action="store_true", help="跳过交互确认（CI）")
    args = ap.parse_args(argv)

    all_errs: List[str] = []
    grand: Counter = Counter()
    fixed_total = 0
    for rel in args.files:
        path = Path(rel)
        if not path.is_absolute():
            path = PROJECT_ROOT / path
        if not path.exists():
            all_errs.append(f"文件不存在: {path}")
            continue

        if args.fix:
            # 先修再查：修后的结果才是可入训状态
            fixed_total += purge_file(path, args.min_chars, args.yes)

        errs, stats = check_file(path, args.min_chars)
        grand.update(stats)
        status = "OK" if not errs else f"{len(errs)} 个问题"
        print(f"[{status}] {path.relative_to(PROJECT_ROOT)}  "
              f"samples={stats['samples']} turns={stats['turns']} "
              f"动作={stats['actions_passed']}/{stats['actions_total']} 通过, "
              f"忽略的 JSON 片段={stats['json_snippets_ignored']}")
        all_errs.extend(errs)

    if all_errs:
        print("\n发现以下问题（前 30 条）:")
        for e in all_errs[:30]:
            print(f"  - {e}")
        print(f"\n合计 {len(all_errs)} 个问题")
        return 1

    avg_turns = grand["turns"] / max(1, grand["samples"])
    prefix = f"已剔除 {fixed_total} 条；" if args.fix else ""
    print(f"\n{prefix}全部通过: {grand['samples']} 条样本，平均 {avg_turns:.2f} 轮/条，"
          f"动作 schema 校验 {grand['actions_passed']}/{grand['actions_total']} 通过，"
          f"忽略的 JSON 片段 {grand['json_snippets_ignored']} 处。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
