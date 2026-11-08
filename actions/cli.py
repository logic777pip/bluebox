#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""actions/cli.py — PDCERF 动作层命令行（`python -m actions.cli ...`）。

子命令：
    phases     打印 PDCERF 阶段机与各阶段可用动作
    list       列出工具（可按阶段/是否已训练过滤）
    schema     输出工具 JSON Schema（OpenAI tools 数组或文本目录）
    run        执行一个动作（默认 dry-run；`--execute` 才产生副作用）
    loop       跑一次工具调用闭环（需模型后端）
    doctor     打印执行器策略与适配器健康状态
    selftest   运行安全语义自检（R3 / 前置 / 保护对象 / R5 / 沙箱 / 闭环）

示例：
    python -m actions.cli phases
    python -m actions.cli list --phase C
    python -m actions.cli run --action query_logs --args "{\\"host_id\\":\\"fin-ws-07\\",\\"query\\":\\"rundll32\\"}" --json
    python -m actions.cli run --action isolate_host --args-file a.json --execute
    python -m actions.cli loop --alert-file cases/alert.txt --backend stub
    python -m actions.cli selftest --json --out logs/pdcerf_selftest.json

⚠ PowerShell 下中文输出易乱码：加 `--out <文件>` 写 UTF-8 文件，再用编辑器查看。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from .executor import ActionExecutor  # noqa: E402
from .pdcerf import PHASE_META, PHASE_ORDER, CaseState, Phase, phase_table  # noqa: E402
from .registry import build_tool_specs, openai_tools, text_catalog  # noqa: E402
from .selftest import run_selftest  # noqa: E402


def _emit(text: str, out: Optional[str]) -> None:
    if out:
        p = Path(out)
        if not p.is_absolute():
            p = PROJECT_ROOT / p
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        print(f"已写入 {p}")
    else:
        print(text)


# --------------------------------------------------------------------------- #
#  子命令
# --------------------------------------------------------------------------- #

def cmd_phases(args: argparse.Namespace) -> int:
    rows = phase_table()
    if args.json:
        return _emit(json.dumps(rows, ensure_ascii=False, indent=2), args.out) or 0
    lines = ["PDCERF 应急响应阶段机", "=" * 60]
    for r in rows:
        lines.append(f"\n[{r['phase']}] {r['zh']} / {r['en']}"
                     f"{'  ← 需要先完成 ' + ','.join(r['requires']) if r['requires'] else ''}")
        lines.append(f"  目标：{r['goal']}")
        lines.append(f"  完成判据：{r['exit']}")
        lines.append(f"  主阶段动作（{len(r['actions'])}）：{', '.join(r['actions'])}")
    _emit("\n".join(lines), args.out)
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    wanted = [Phase(args.phase)] if args.phase else None
    specs = build_tool_specs()
    items: List[Dict[str, Any]] = []
    for name, s in specs.items():
        if wanted and not (set(wanted) & set(s.phases)):
            continue
        if args.trained_only and not s.trained:
            continue
        if args.irreversible_only and not s.irreversible:
            continue
        items.append(s.to_dict())
    items.sort(key=lambda d: (d["phase"], d["name"]))

    if args.json:
        return _emit(json.dumps(items, ensure_ascii=False, indent=2), args.out) or 0

    lines = [f"工具清单（{len(items)} 个）", "=" * 60]
    current = None
    for d in items:
        if d["phase"] != current:
            current = d["phase"]
            lines.append(f"\n## {current} {PHASE_META[Phase(current)]['zh']}")
        flag = []
        if d["irreversible"]:
            flag.append("不可逆")
        if d["risk"] in ("high", "critical"):
            flag.append(d["risk"])
        if not d["trained"]:
            flag.append("未训练")
        tail = f"  [{'/'.join(flag)}]" if flag else ""
        lines.append(f"- {d['name']}: {d['description']}{tail}")
        lines.append(f"    必填={d['required']}"
                     + (f" 可选={d['optional']}" if d["optional"] else "")
                     + (f" 目标={d['targets']}" if d["targets"] else ""))
    _emit("\n".join(lines), args.out)
    return 0


def cmd_schema(args: argparse.Namespace) -> int:
    if args.format == "openai":
        payload = openai_tools(only_trained=args.trained_only)
        text = json.dumps(payload, ensure_ascii=False, indent=2)
    else:
        text = text_catalog(only_trained=args.trained_only)
    _emit(text, args.out)
    return 0


def _parse_args(raw_text: str) -> Dict[str, Any]:
    """解析 --args 的 JSON，失败时给出可操作提示而不是 traceback。"""
    try:
        payload = json.loads(raw_text or "{}")
    except json.JSONDecodeError as exc:
        print(
            "--args 不是合法 JSON：" + str(exc) + "\n"
            "提示：PowerShell 会把双引号剥掉（{\"host_id\":\"x\"} 变成 {host_id:x}），\n"
            "      请改用 --args-file <文件.json>（推荐），或单引号包裹整个 JSON。\n"
            "      也可用：python -m actions.cli run --action <名> --args-file actions/examples/args_query_logs.json",
            file=sys.stderr,
        )
        raise SystemExit(64) from exc
    if not isinstance(payload, dict):
        print("--args 必须是 JSON 对象（如 {\"host_id\": \"fin-ws-07\"}）", file=sys.stderr)
        raise SystemExit(64)
    return payload


def cmd_run(args: argparse.Namespace) -> int:
    if args.args_file:
        path = Path(args.args_file)
        if not path.is_absolute():
            path = PROJECT_ROOT / path
        try:
            raw_args = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            print(f"参数文件不存在：{path}", file=sys.stderr)
            return 64
        except json.JSONDecodeError as exc:
            print(f"参数文件不是合法 JSON（{path}）：{exc}", file=sys.stderr)
            return 64
    else:
        raw_args = _parse_args(args.args)
    raw = {"action": args.action, "args": raw_args}
    if args.rationale:
        raw["rationale"] = args.rationale

    ex = ActionExecutor.from_config(
        config_path=Path(args.config) if args.config else None,
        dry_run=(None if args.execute is None else (not args.execute)),
    )
    if args.sim_fallback:
        ex.policy.allow_sim_fallback = True
    if args.auto_confirm:
        ex.policy.allow_auto_confirm = True

    case_path = Path(args.case_file) if args.case_file else None
    if case_path and not case_path.is_absolute():
        case_path = PROJECT_ROOT / case_path
    if case_path and case_path.exists():
        case = CaseState.load(case_path)
    else:
        case = CaseState(case_id=args.case_id or "cli-case", severity=args.severity)
        if args.phase:
            case.phase = Phase(args.phase)
            if case.phase.value not in case.phases_visited:
                case.phases_visited.append(case.phase.value)

    confirmation = None
    if args.confirm_proposal:
        confirmation = (args.confirm_proposal, args.confirm_signature or "")

    result = ex.execute(raw, case, confirmation=confirmation)
    if case_path:
        case.save(case_path)

    if args.json:
        payload = {
            "result": result.to_dict(),
            "case": case.to_dict(),
            "policy": ex.policy.to_dict(),
            "stats": ex.stats(),
        }
        _emit(json.dumps(payload, ensure_ascii=False, indent=2), args.out)
    else:
        lines = [
            f"动作 : {result.action}",
            f"状态 : {result.status}  (adapter={result.adapter}, dry_run={result.dry_run}, "
            f"simulated={result.simulated})",
            f"案例 : {case.describe()}",
        ]
        if result.error:
            lines.append(f"错误 : {result.error}")
        if result.observations:
            lines += ["", "观测：", result.observations]
        if result.status == "pending_confirmation":
            pid = result.output.get("proposal_id")
            lines += ["", f"→ 需人工确认：python -m actions.cli run --action {result.action} "
                          f"--args-file <同参数> --execute --confirm-proposal {pid} --confirm-signature <HMAC>"]
        _emit("\n".join(lines), args.out)

    if result.status in ("denied", "pending_confirmation"):
        return 2
    return 0 if result.ok else 1


def cmd_loop(args: argparse.Namespace) -> int:
    import yaml  # noqa: PLC0415

    alert = args.alert
    if args.alert_file:
        raw = Path(args.alert_file).read_text(encoding="utf-8")
        try:
            obj = json.loads(raw)
            alert = obj.get("alert") or obj.get("observation") or raw
        except json.JSONDecodeError:
            alert = raw
    if not alert:
        print("必须提供 --alert 或 --alert-file", file=sys.stderr)
        return 1

    from agent.agent import build_backend  # noqa: PLC0415  （重依赖，按需导入）
    from .loop import ToolLoop, summarize  # noqa: PLC0415

    agent_cfg_path = PROJECT_ROOT / "agent" / "config.yaml"
    cfg = yaml.safe_load(agent_cfg_path.read_text(encoding="utf-8")) or {}
    if args.backend:
        cfg["backend"] = args.backend
    backend = build_backend(cfg)

    retriever = None
    if not args.no_rag:
        try:
            from rag.retrieve import Retriever  # noqa: PLC0415
            rag_cfg = cfg.get("rag", {}) or {}
            retriever = Retriever(config_path=PROJECT_ROOT / rag_cfg.get("config", "rag/config.yaml"))
        except Exception as exc:  # noqa: BLE001
            print(f"[warn] RAG 不可用，降级为无知识库：{exc}", file=sys.stderr)

    ex = ActionExecutor.from_config(
        config_path=Path(args.config) if args.config else None,
        dry_run=(None if args.execute is None else (not args.execute)),
    )
    if args.auto_confirm:
        ex.policy.allow_auto_confirm = True

    case = CaseState(case_id=args.case_id or f"cli-loop-{abs(hash(alert)) % 100000:05d}")
    loop = ToolLoop(backend, ex, retriever=retriever,
                    intel_enabled=not args.no_intel,
                    max_steps=args.max_steps, max_calls_per_step=args.max_calls,
                    only_trained_tools=not args.all_tools,
                    grounding=not args.no_grounding)
    result = loop.run(alert, case)

    if args.json:
        _emit(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), args.out)
    else:
        lines = [summarize(result), "", "=" * 60, "最终研判：", result.final_answer or "（无）"]
        for s in result.steps:
            lines += ["", f"--- 第 {s['index']} 步（{s['phase_before']} → {s['phase_after']}）---"]
            lines.append(f"调用：{[c['action'] for c in s['calls']]}")
            for r in s["results"]:
                lines.append(f"  {r['action']}: {r['status']} ({r['adapter']})")
            if s["rejected"]:
                lines.append(f"  被拒：{s['rejected']}")
        _emit("\n".join(lines), args.out)
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    ex = ActionExecutor.from_config(config_path=Path(args.config) if args.config else None)
    info = ex.describe()
    info["case_table"] = phase_table()
    if args.json:
        _emit(json.dumps(info, ensure_ascii=False, indent=2), args.out)
        return 0
    lines = ["PDCERF 动作层健康检查", "=" * 60,
             f"审计路径 : {info['audit_path']}",
             f"待确认目录 : {info['pending_dir']}",
             f"工具总数 : {info['tools']}",
             "",
             "策略："]
    for k, v in info["policy"].items():
        lines.append(f"  {k} = {v}")
    lines += ["", "适配器："]
    for a in info["adapters"]:
        lines.append(f"  {a['name']:<12} healthy={a['healthy']} real_effects={a['real_effects']} "
                     f"caps={len(a['capabilities'])}  {a['health_detail']}")
        if a["healthy"] and not a["real_effects"]:
            lines.append("      ⚠ 仅仿真：真实执行模式下不会产生真实处置效果")
    _emit("\n".join(lines), args.out)
    return 0


def cmd_selftest(args: argparse.Namespace) -> int:
    result = run_selftest()
    if args.json:
        _emit(json.dumps(result, ensure_ascii=False, indent=2), args.out)
    else:
        lines = []
        for c in result["checks"]:
            lines.append(f"[{'PASS' if c['ok'] else 'FAIL'}] {c['name']}")
            if c["detail"]:
                lines.append(f"        {c['detail']}")
        lines.append(f"\n通过 {result['passed']} / 失败 {result['failed']} / 共 {result['total']}")
        _emit("\n".join(lines), args.out)
    return 0 if result["failed"] == 0 else 1


# --------------------------------------------------------------------------- #
#  参数解析
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="python -m actions.cli",
                                 description="PDCERF 动作与工具层命令行")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def _common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--config", default=None, help="执行器配置（默认 actions/config.yaml）")
        p.add_argument("--json", action="store_true", help="输出 JSON")
        p.add_argument("--out", default=None, help="把输出写入 UTF-8 文件（PowerShell 中文防乱码）")

    p = sub.add_parser("phases", help="打印 PDCERF 阶段机")
    _common(p)
    p.set_defaults(func=cmd_phases)

    p = sub.add_parser("list", help="列出工具")
    _common(p)
    p.add_argument("--phase", default=None, choices=[x.value for x in PHASE_ORDER])
    p.add_argument("--trained-only", action="store_true", help="只列出微调模型学过的动作")
    p.add_argument("--irreversible-only", action="store_true")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("schema", help="输出工具 JSON Schema / 文本目录")
    _common(p)
    p.add_argument("--format", default="openai", choices=["openai", "text"])
    p.add_argument("--trained-only", action="store_true")
    p.set_defaults(func=cmd_schema)

    p = sub.add_parser("run", help="执行一个动作")
    _common(p)
    p.add_argument("--action", required=True)
    p.add_argument("--args", default="{}", help='JSON 字符串，如 {"host_id":"fin-ws-07"}')
    p.add_argument("--args-file", default=None, help="从文件读取 args JSON（推荐，避免引号地狱）")
    p.add_argument("--rationale", default=None)
    p.add_argument("--case-id", default=None)
    p.add_argument("--case-file", default=None,
                   help="案例状态文件（存在则续跑，结束则回写）——多步 PDCERF 流程必用")
    p.add_argument("--phase", default=None, choices=[x.value for x in PHASE_ORDER],
                   help="仅新建案例时生效：指定初始阶段")
    p.add_argument("--severity", default="MEDIUM",
                   choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    p.add_argument("--execute", dest="execute", action="store_true", default=None,
                   help="真实执行（默认 dry-run）")
    p.add_argument("--dry-run", dest="execute", action="store_false",
                   help="强制 dry-run（默认）")
    p.add_argument("--auto-confirm", action="store_true",
                   help="自动完成两阶段确认（仅靶场/自测）")
    p.add_argument("--sim-fallback", action="store_true", help="允许回落到仿真靶场")
    p.add_argument("--confirm-proposal", default=None, help="两阶段确认：proposal_id")
    p.add_argument("--confirm-signature", default=None, help="两阶段确认：HMAC 签名")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("loop", help="运行工具调用闭环")
    _common(p)
    p.add_argument("--alert", default=None)
    p.add_argument("--alert-file", default=None)
    p.add_argument("--backend", default=None, help="stub/llamacpp/ollama/local")
    p.add_argument("--case-id", default=None)
    p.add_argument("--max-steps", type=int, default=6)
    p.add_argument("--max-calls", type=int, default=3)
    p.add_argument("--execute", dest="execute", action="store_true", default=None)
    p.add_argument("--auto-confirm", action="store_true")
    p.add_argument("--all-tools", action="store_true", help="下发全部工具（默认只下发已训练动作）")
    p.add_argument("--no-rag", action="store_true")
    p.add_argument("--no-intel", action="store_true")
    p.add_argument("--no-grounding", action="store_true")
    p.set_defaults(func=cmd_loop)

    p = sub.add_parser("doctor", help="健康检查：策略 + 适配器")
    _common(p)
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("selftest", help="运行安全语义自检")
    _common(p)
    p.set_defaults(func=cmd_selftest)

    return ap


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
