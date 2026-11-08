#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/detection_report.py — 把传感器事件流水汇总成**按天的检测报告**。

为什么需要
----------

`logs/net_sensor_events.jsonl` 是逐条追加的事件流水，长时间运行后很难直接看；
心跳在 `logs/net_sensor.log` 里，两者需要交叉才能回答「昨天到底发生了什么」。
本工具把两者合成一份 Markdown 日报，并单独把**已送模型研判**的条目列全
（那才是真正需要人看的「检测报告」）。

用法::

    python tools/detection_report.py                       # 今天
    python tools/detection_report.py --date 2026-10-02     # 指定某天
    python tools/detection_report.py --all                 # 全部
    python tools/detection_report.py --date 2026-10-03 --out reports/d3.md
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EVENTS = PROJECT_ROOT / "logs" / "net_sensor_events.jsonl"
DEFAULT_LOG = PROJECT_ROOT / "logs" / "net_sensor.log"

TAIL_RE = re.compile(r"心跳：已轮询 (\d+) 次 / 看过 (\d+) 条连接 / 发现 (\d+) 条 / "
                     r"上报 (\d+) 条 / 因冷却跳过 (\d+) / 待办队列 (\d+)（已补 (\d+)，"
                     r"队列满丢弃 (\d+)）/ 进程事件 (\d+)（其中非常规目录 (\d+)）/ "
                     r"事件源 (\S+?)（RSS (\d+) MB）/ 快采样 (\S+?) / 子进程调用 (\d+) 次")


def load_events(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def heartbeats(path: Path) -> List[Dict[str, Any]]:
    """取最后一次心跳（代表当前累计运行状态）。"""
    if not path.exists():
        return []
    out: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = TAIL_RE.search(line)
        if not m:
            continue
        g = m.groups()
        out.append({"ts": line[:19], "polls": int(g[0]), "conns": int(g[1]),
                    "findings": int(g[2]), "reported": int(g[3]),
                    "cooldown": int(g[4]), "queue": int(g[5]), "deferred_done": int(g[6]),
                    "dropped_low": int(g[7]), "proc_events": int(g[8]),
                    "suspect_proc": int(g[9]), "source": g[10], "source_rss": int(g[11]),
                    "burst": g[12], "spawns": int(g[13])})
    return out


def triaged(rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [r for r in rows
            if (r.get("triage") or {}).get("verdict") not in (None, "skipped")]


def build(events: Sequence[Dict[str, Any]], hbs: Sequence[Dict[str, Any]],
          label: str) -> str:
    tri = triaged(events)
    verdicts = Counter((r.get("triage") or {}).get("verdict") for r in events
                       if r.get("triage"))
    rules = Counter(rule for r in events for rule in r.get("rules", []))
    lines = [
        f"# 本机流量检测报告 — {label}", "",
        f"- 事件条数：**{len(events)}**（其中送模型研判 **{len(tri)}**）",
        f"- 判定分布：`{dict(verdicts)}`",
        f"- 规则命中：`{dict(rules)}`",
        f"- 已弹通知：**{sum(1 for r in events if r.get('notified'))}** 条",
    ]
    if hbs:
        h = hbs[-1]
        lines += ["", "## 累计运行状态（最后一次心跳）", "",
                  f"- 轮询 **{h['polls']}** 次 / 观察连接 **{h['conns']}** 条",
                  f"- 发现 {h['findings']} 条：上报 {h['reported']}、因冷却跳过 {h['cooldown']}",
                  f"- 优先级队列：待办 {h['queue']}、已补 {h['deferred_done']}、满队丢弃 {h['dropped_low']}",
                  f"- 进程创建事件 {h['proc_events']} 个（非常规目录 **{h['suspect_proc']}** 个）",
                  f"- 事件源 {h['source']}（自身 RSS {h['source_rss']} MB）/ 快采样 {h['burst']}",
                  f"- 子进程调用 {h['spawns']} 次（仅模型启停，应为个位数）"]

    lines += ["", "## 需要人看的条目（已送模型研判）", ""]
    if not tri:
        lines.append("_本期无（说明没有达到阈值的可疑事件）_")
    else:
        lines += ["| 时间 | 分值 | 进程 | 目标 | 规则 | 判定 | 通知 |",
                  "|---|---|---|---|---|---|---|"]
        for r in tri:
            t = r.get("triage") or {}
            lines.append(f"| {r['ts'][5:]} | {r['score']} | `{r['proc'] or '?'}` | "
                         f"`{r['remote']}` | {', '.join(r['rules'])} | "
                         f"**{t.get('verdict')}** | {'✓' if r.get('notified') else '—'} |")
        lines += ["", "<details><summary>逐条研判详情（建议动作与理由）</summary>", ""]
        for r in tri:
            t = r.get("triage") or {}
            lines += [f"### {r['ts']} — {r['proc'] or '?'} → {r['remote']}",
                      "",
                      f"- 分值 **{r['score']}**；规则 `{', '.join(r['rules'])}`"
                      f"{'（排队后补研判）' if t.get('deferred') else ''}",
                      f"- 判定：**{t.get('verdict')}**；耗时 {t.get('latency_s')}s；"
                      f"需复核 {t.get('needs_review')}；接地通过 {t.get('grounded_ok')}",
                      f"- 建议动作（**未执行，本系统只读**）：`{t.get('actions')}`",
                      f"- 规则说明：{r.get('detail', '')[:200]}", ""]
            if t.get("answer"):
                lines += ["```", str(t["answer"])[:1200], "```", ""]
        lines += ["</details>", ""]

    lines += ["## 事件驱动命中（进程创建）", ""]
    sp = [r for r in events if "proc_from_suspect_dir" in r.get("rules", [])]
    if not sp:
        lines.append("_本期无非常规目录启动的新进程_")
    else:
        for r in sp:
            t = r.get("triage") or {}
            lines.append(f"- {r['ts']} 分值 {r['score']} `{r['proc']}` — {r.get('detail', '')}"
                         f" → 判定 {t.get('verdict')}")

    lines += ["", "## 环境说明（避免误读本报告）", "",
              "- 采集是**连接级**（五元组 + 所属进程），**不含报文载荷**；",
              "- 判定由本地 3B 模型给出，实测误报率约 15%、存在「幻觉注入」，"
              "**必须以“需复核”为准做人工判断**；",
              "- 本系统**只读**：报告里的建议动作从未被执行。"]

    lines += ["", "## 全部事件明细", "",
              "| 时间 | 分值 | 进程 | 目标 | 规则 | 研判 | 冷却/去向 |",
              "|---|---|---|---|---|---|---|"]
    for r in events:
        t = r.get("triage") or {}
        lines.append(f"| {r['ts'][5:]} | {r['score']} | `{r['proc'] or '?'}` | "
                     f"`{r['remote']}` | {', '.join(r['rules'])} | "
                     f"{t.get('verdict', '（未研判）')} | "
                     f"{'通知' if r.get('notified') else '记录'} |")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="本机流量检测日报")
    ap.add_argument("--events", default=str(DEFAULT_EVENTS))
    ap.add_argument("--log", default=str(DEFAULT_LOG))
    ap.add_argument("--date", default=None, help="YYYY-MM-DD，默认今天")
    ap.add_argument("--all", action="store_true", help="不按日期过滤")
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    rows = load_events(Path(args.events))
    hbs = heartbeats(Path(args.log))

    import datetime as _dt
    label = args.date or _dt.date.today().isoformat()
    if not args.all:
        rows = [r for r in rows if r.get("ts", "").startswith(label)]
    else:
        days = sorted({r.get("ts", "")[:10] for r in rows})
        label = f"{days[0]} ~ {days[-1]}" if days else "无数据"

    text = build(rows, hbs, label)
    out = Path(args.out) if args.out else (PROJECT_ROOT / "reports" / f"detection_{label.replace(' ~ ', '_')}.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")

    tri = triaged(rows)
    print(f"日期 {label}：事件 {len(rows)} 条，其中送模型研判 {len(tri)} 条")
    for r in tri:
        t = r.get("triage") or {}
        print(f"  {r['ts'][5:16]}  score={r['score']:<3} {r['proc'] or '?':<20} -> "
              f"{r['remote']:<30} {','.join(r['rules']):<28} => {t.get('verdict')}")
    print(f"报告已写入 {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
