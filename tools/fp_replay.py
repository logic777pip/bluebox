#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/fp_replay.py — 用**真实误报数据**回放验证降误报改动是否生效。

为什么要单独做回放
------------------

改完「降误报」的代码后，最危险的结论方式是「看起来应该好了」。
本工具把两类可复算的证据跑出来：

**A. 模型回答回放**（对应 `security/confidence.py` 的多维置信度）
   取 `logs/net_sensor_events.jsonl` 里**已经真实发生过**的告警与模型回答，
   用新的置信度门槛重算路由：
   * 旧行为：判定 attack 就弹通知
   * 新行为：只有高置信且过硬门槛才弹，其余降为「需复核」
   输出「原本会打扰用户多少条、现在剩多少条」。

**B. 规则回放**（对应两处规则修正）
   用**实测到的原始形状**构造连接，跑新版 `analyse()`，验证：
   * `msedge.exe → DNS:53` 的 UDP 大量端点不再算「连接爆发」
   * `BackgroundDownload.exe`（签名有效、Temp 目录）降级到阈值以下
   * 真正的恶意形状（无签名 + Temp + 高危端口）仍然高分

用法::

    python tools/fp_replay.py
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security.confidence import BenignProfile, assess  # noqa: E402
from security.reasoning_audit import audit as reasoning_audit  # noqa: E402
from tools.net_sensor import (Baseline, Conn, analyse,  # noqa: E402
                              suspect_proc_finding)
from tools.proc_watch import signature_status  # noqa: E402

EVENTS = PROJECT_ROOT / "logs" / "net_sensor_events.jsonl"


def part_a(rows: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    """按新置信度门槛重算「原本会弹通知」的条目。"""
    print("=" * 72)
    print("A. 模型回答回放：多维置信度门槛会拦下多少条打扰")
    print("=" * 72)
    stat = Counter()
    details: List[str] = []
    for r in rows:
        t = r.get("triage") or {}
        if t.get("verdict") != "attack":
            continue
        stat["old_notify"] += 1
        answer = t.get("answer") or ""
        ra = reasoning_audit(answer, benign_verdict=False)
        conf = assess(
            rule_score=int(r.get("score") or 0),
            verdict="attack",
            attack_strict=bool(t.get("attack_strict")),
            hedged=bool(t.get("hedged")),
            grounded_ok=bool(t.get("grounded_ok", True)),
            discriminator=ra.discriminator,
            contradictory=False,
            baseline_hit=("benign_baseline" in (r.get("rules") or [])))
        stat["new_" + conf.route] += 1
        if conf.route != "auto_attack":
            stat["suppressed"] += 1
        details.append(
            f"  {r['ts'][5:16]} score={r['score']:<3} {r['proc'] or '?':<22} "
            f"规则={','.join(r['rules']):<26} 置信度={conf.score:<6} 路由={conf.route}"
            f"{'  ← 不再打扰' if conf.route != 'auto_attack' else ''}")
    for d in details:
        print(d)
    print(f"\n  旧口径会弹通知：{stat['old_notify']} 条")
    print(f"  新口径：告警 {stat.get('new_auto_attack', 0)} / "
          f"需复核 {stat.get('new_review', 0)} / 静默 {stat.get('new_auto_benign', 0)}"
          f" → **拦下 {stat['suppressed']} 条打扰**")
    return stat


def part_b(profile: Optional[BenignProfile]) -> None:
    """按实测形状回放规则。"""
    print()
    print("=" * 72)
    print("B. 规则回放：用实测到的原始形状跑新版规则")
    print("=" * 72)
    now = 1_700_000_000.0

    # B1: 浏览器 UDP DNS 突发（实测 2026-10-03 10:11 msedge.exe → 120.196.165.24:53）
    dns = [Conn("UDP", "192.168.1.31", 50000 + i, "120.196.165.24", 53, "", 6612,
                "msedge.exe", r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")
           for i in range(30)]
    fs = analyse(dns, Baseline(), now, profile=profile)
    hit = [f for f in fs if {"conn_burst", "port_fanout"} & set(f.rules)]
    print(f"  [B1] msedge.exe → DNS:53 共 30 个 UDP 端点")
    print(f"       旧规则：conn_burst ≥20 → 40 分并送模型判为 attack")
    print(f"       新规则：命中 {'、'.join(sorted({r for f in hit for r in f.rules})) or '无'}"
          f"，最高分 {max((f.score for f in fs), default=0)} → "
          f"{'不再上报（修复已生效）' if not hit else '仍会上报（修复未生效）'}")

    # B2: VS 安装器自解压（实测 2026-10-03 01:59 BackgroundDownload.exe）
    real = (r"C:\Users\user\AppData\Local\Temp\1bb1odbl.gkv\resources\app\ServiceHub"
            r"\Services\Microsoft.VisualStudio.Setup.Service\BackgroundDownload.exe")

    class _Ev:
        pid, name, path = 13148, "BackgroundDownload.exe", real

    f_nosig = suspect_proc_finding(_Ev())
    f_sig = suspect_proc_finding(_Ev(), sig_fn=signature_status)
    sig = signature_status(real)
    print(f"  [B2] {real.split(chr(92))[-1]} @ %TEMP%\\<随机>\\")
    print(f"       签名查询：{sig[0]} / {sig[1].split(',')[0] or '未知'}")
    print(f"       旧规则：仅看「位于 Temp」→ {f_nosig.score} 分 → 被送模型判 attack")
    print(f"       新规则：签名有效降级 → {f_sig.score} 分 → "
          f"{'低于阈值不再上报（修复已生效）' if f_sig.score < 30 else '仍会上报（修复未生效）'}")

    # B3: 真恶意形状必须仍然报（防「为了降误报把灵敏度也降没了」）
    class _Ev2:
        pid, name, path = 999, "svchost.exe", r"C:\Users\Public\Temp\svchost.exe"

    f3 = suspect_proc_finding(_Ev2(), sig_fn=signature_status)
    print(f"  [B3] 无签名 svchost.exe @ C:\\Users\\Public\\Temp\\（真恶意形状）")
    print(f"       新规则：{f3.score} 分 → "
          f"{'仍然上报（灵敏度保住了）' if f3.score >= 30 else '被误放过（灵敏度丢了）'}")

    mal = [Conn("TCP", "192.168.1.31", 50100, "203.0.113.9", 4444, "ESTABLISHED", 999,
                "svchost.exe", r"C:\Users\Public\Temp\svchost.exe")
           for _ in range(25)]
    fm = analyse(mal, Baseline(), now, profile=profile)
    print(f"  [B4] 同进程 25 条 TCP 连接 → 高危端口（真恶意形状）")
    print(f"       新规则：最高分 {max((f.score for f in fm), default=0)} "
          f"规则 {sorted({r for f in fm for r in f.rules})} → "
          f"{'仍然上报（灵敏度保住了）' if max((f.score for f in fm), default=0) >= 30 else '被误放过（灵敏度丢了）'}")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="误报改动回放验证")
    ap.add_argument("--events", default=str(EVENTS))
    ap.add_argument("--no-baseline", action="store_true")
    args = ap.parse_args(argv)

    p = Path(args.events)
    rows = []
    if p.exists():
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    print(f"事件流水：{p}（{len(rows)} 条）\n")
    profile = None if args.no_baseline else BenignProfile()
    if profile is not None:
        print(f"良性基线：{profile.summary()}\n")

    part_a(rows)
    part_b(profile)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
