#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""actions/toolkit.py — 面向 AI 系统的工具接口（tool-calling surface）。

一个 AI 系统要「具备动作能力」，需要三样东西同时到位：
  1. **目录**：模型能看到的可用工具清单（`tool_catalog_text` / `openai_tools`）
  2. **协议**：模型怎么表达"我要调用这个工具"（`parse_tool_calls`）
  3. **回执**：工具执行结果怎么回灌给模型（`format_observation`）

本项目有两条协议并存，因为部署形态不同：
  * 文本协议（默认）：微调过的 Qwen2.5-3B 学的是
        ```action
        {"action": "query_logs", "args": {"host_id": "...", "query": "..."}}
        ```
    适配 llama-server / Ollama 的纯文本对话。
  * 原生 function-calling：llama-server 支持 OpenAI `tools`（`--jinja` + Qwen 模板），
    返回 `tool_calls[].function.{name,arguments}`。本模块把两种都归一成 (name, args)。

⚠ 本模块**不执行**任何动作：解析结果必须交给 `ActionExecutor`（R3 白名单 + 策略 + R5 确认）。
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security.action_schema import SchemaError, parse_actions, validate_action  # noqa: E402
from security.sanitize import mask_text  # noqa: E402

from .executor import ActionExecutor  # noqa: E402
from .pdcerf import PHASE_META, PHASE_ORDER, CaseState, Phase  # noqa: E402
from .registry import openai_tools, text_catalog  # noqa: E402

__all__ = [
    "tool_definitions",
    "tool_catalog_text",
    "phase_instruction",
    "parse_tool_calls",
    "format_observation",
    "dispatch",
]

_TOOL_CALL_BLOCK_RE = re.compile(r"<tool_call>\s*(.+?)\s*</tool_call>", re.S | re.I)


def tool_definitions(
    phases: Optional[Sequence["Phase | str"]] = None,
    only_trained: bool = False,
    include_irreversible: bool = True,
) -> List[Dict[str, Any]]:
    """OpenAI 兼容的工具定义数组（可直接用于 `tools=` 参数）。"""
    return openai_tools(phases, only_trained, include_irreversible)


def tool_catalog_text(
    phases: Optional[Sequence["Phase | str"]] = None,
    only_trained: bool = False,
    show_args: bool = True,
) -> str:
    """按 PDCERF 阶段分组的文本工具目录（注入 system prompt）。"""
    return text_catalog(phases, only_trained, include_irreversible=True, show_args=show_args)


def phase_instruction(phase: "Phase | str") -> str:
    """当前阶段的行动指引（含"该做什么 / 不该做什么"）。"""
    p = Phase(phase)
    meta = PHASE_META[p]
    hints: Dict[Phase, str] = {
        Phase.PREPARATION: "先确认资产归属与回滚点：没有快照/备份时，任何不可逆动作都不可接受。",
        Phase.DETECTION: "只做只读动作。把告警收敛成事实（资产、时间线、证据），不要急着处置。",
        Phase.CONTAINMENT: "先取证后隔离。封禁要分清方向：C2 对端出向封禁，别把受害主机自己的 IP 封了。",
        Phase.ERADICATION: "杀进程不等于根除：必须继续清除持久化项；清除后要重新枚举确认。",
        Phase.RECOVERY: "恢复后必须校验完整性并保留观察期；回滚不会自动移除持久化。",
        Phase.FOLLOWUP: "归档证据 → 登记 IOC → 更新检测规则 → 关闭工单；复盘要写清检测盲区。",
    }
    return (
        f"【当前 PDCERF 阶段】{p.value} {meta['zh']}（{meta['en']}）\n"
        f"阶段目标：{meta['goal']}\n"
        f"阶段完成判据：{meta['exit']}\n"
        f"行动要求：{hints[p]}\n"
        f"阶段顺序：{' → '.join(q.value for q in PHASE_ORDER)}（可回退补充检测，但处置动作必须先满足前置）"
    )


def parse_tool_calls(text: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """从模型输出中解析工具调用。

    支持三种写法（可混排）：
      1. ```action / ```json 代码块里的 {"action":..., "args":{...}}
      2. `<tool_call>{...}</tool_call>`
      3. OpenAI 风格 {"tool_calls":[{"function":{"name":...,"arguments":"{...}"}}]}

    Returns:
        (合法调用列表, 被拒绝的原因列表)
    """
    calls: List[Dict[str, Any]] = []
    rejected: List[str] = []

    # ① 分支：security.parse_actions 已覆盖代码块与裸 JSON 行
    for act in parse_actions(text):
        calls.append({"action": act.name, "args": act.args, "rationale": act.rationale})

    # ② <tool_call> 块
    for block in _TOOL_CALL_BLOCK_RE.findall(text):
        try:
            payload = json.loads(block)
        except json.JSONDecodeError as exc:
            rejected.append(f"<tool_call> 不是合法 JSON: {mask_text(str(exc))}")
            continue
        for item in _normalize_openai_payload(payload):
            try:
                act = validate_action(item)
                calls.append({"action": act.name, "args": act.args, "rationale": act.rationale})
            except SchemaError as exc:
                rejected.append(f"{item.get('action') or item.get('name')}: {exc}")

    # ③ OpenAI tool_calls（模型把整个响应体写进了文本）
    if '"tool_calls"' in text:
        for m in re.finditer(r"\{[^{}]*\"tool_calls\"\s*:\s*\[.*?\]\s*\}", text, flags=re.S):
            try:
                payload = json.loads(m.group(0))
            except json.JSONDecodeError:
                continue
            for item in _normalize_openai_payload(payload):
                try:
                    act = validate_action(item)
                    calls.append({"action": act.name, "args": act.args, "rationale": act.rationale})
                except SchemaError as exc:
                    rejected.append(f"{item.get('action') or item.get('name')}: {exc}")

    # 去重（保序）
    seen = set()
    uniq: List[Dict[str, Any]] = []
    for c in calls:
        key = json.dumps(c, sort_keys=True, ensure_ascii=False)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(c)
    return uniq, rejected


def _normalize_openai_payload(payload: Any) -> List[Dict[str, Any]]:
    """把各种 OpenAI/裸 JSON 形态归一成 [{"action":..., "args":{...}}]。"""
    out: List[Dict[str, Any]] = []
    if isinstance(payload, dict):
        if "tool_calls" in payload:
            for tc in payload.get("tool_calls") or []:
                fn = (tc or {}).get("function") or {}
                args = fn.get("arguments")
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        args = {}
                out.append({"action": fn.get("name"), "args": args or {}})
        elif "action" in payload or "name" in payload:
            out.append(payload)
    elif isinstance(payload, list):
        for item in payload:
            out.extend(_normalize_openai_payload(item))
    return out


def format_observation(index: int, result: Dict[str, Any]) -> str:
    """把执行结果格式化成回灌给模型的观测文本。"""
    status = result.get("status", "?")
    action = result.get("action", "?")
    adapter = result.get("adapter", "?")
    obs = str(result.get("observations", "")).strip()
    lines = [f"【工具执行结果 {index}】action={action} status={status} adapter={adapter}"]
    if result.get("error"):
        lines.append(f"错误：{result['error']}")
    if obs:
        lines.append(obs)
    if status == "pending_confirmation":
        pid = (result.get("output") or {}).get("proposal_id", "")
        lines.append(f"该动作不可逆，已登记待确认（proposal_id={pid}）；在确认前不要重复提出同一动作。")
    return "\n".join(lines)


def dispatch(
    text_or_calls: Any,
    executor: ActionExecutor,
    case: CaseState,
    *,
    dry_run: Optional[bool] = None,
    auto_confirm: Optional[bool] = None,
    max_calls: int = 5,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """解析并执行模型输出中的工具调用。

    Returns:
        (结果列表, 解析拒绝原因列表)
    """
    if isinstance(text_or_calls, str):
        calls, rejected = parse_tool_calls(text_or_calls)
    else:
        calls, rejected = list(text_or_calls), []
    results: List[Dict[str, Any]] = []
    for call in calls[:max_calls]:
        res = executor.execute(call, case, dry_run=dry_run, auto_confirm=auto_confirm)
        results.append(res.to_dict())
    return results, rejected
