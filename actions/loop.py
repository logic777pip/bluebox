#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""actions/loop.py — PDCERF 驱动的工具调用闭环（ReAct 式）。

与 `agent/agent.py` 的**单次 ask()** 的区别：
    ask()      ：一次推理 → 产出建议动作（不执行）
    ToolLoop   ：推理 → 执行动作 → 把**真实观测**回灌 → 再推理 …… 直到不能继续
                 即"具备动作能力"，而不是"会写动作 JSON"。

循环骨架：

    ┌─ 注入当前 PDCERF 阶段指引 + 工具目录（可只下发已训练工具）
    │  模型输出
    │    ├─ 含工具调用 → ActionExecutor 放行检查 → 执行 → 观测回灌 ──┐
    │    └─ 无工具调用 → 收敛为最终答复 ────────────────────────────┘
    └─ 终止条件：无调用 / 达到 max_steps / 出现待确认不可逆动作 / 模型显式声明完成

安全约束：
  * 本模块**不做**任何放宽：所有动作都过 `ActionExecutor`（R3 + 前置 + 保护对象 + R5）。
  * 出现待确认的不可逆动作时立即停轮 —— 否则模型会反复提同一动作刷屏，污染时间线。
  * 每步观测写入案例时间线，审计落 `logs/action_audit.jsonl`（R1 脱敏）。
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security.sanitize import get_logger, mask_text  # noqa: E402

from .executor import ActionExecutor  # noqa: E402
from .pdcerf import PHASE_META, CaseState, Phase, primary_phase  # noqa: E402
from .toolkit import format_observation, parse_tool_calls, phase_instruction, tool_catalog_text  # noqa: E402

LOG = get_logger("actions.loop")

__all__ = ["LoopStep", "LoopResult", "ToolLoop", "build_output_protocol"]

_PROTOCOL = """
【输出协议（必须遵守）】
* 需要观测时，输出一个或多个动作 JSON，每行一个，放在 ```action 代码块内：
  ```action
  {"action": "query_logs", "args": {"host_id": "fin-ws-07", "query": "rundll32"}}
  ```
* 一次最多提 {max_calls} 个动作；只允许使用上面目录里的动作名与参数。
* 不需要再观测时，直接输出最终研判（不要输出动作 JSON），结构：
    一、研判结论  二、证据与推理（标注出处）  三、已执行动作与结果  四、残余风险与建议
* 不要臆造观测结果：工具没返回的事实，写「未获取到该项信息」。
* 不可逆动作在得到确认前不会被执行；不要连续重复提交同一个不可逆动作。
""".strip()


def build_output_protocol(max_calls: int = 3) -> str:
    return _PROTOCOL.replace("{max_calls}", str(max_calls))


@dataclass
class LoopStep:
    index: int
    phase_before: str
    phase_after: str
    model_output: str
    calls: List[Dict[str, Any]] = field(default_factory=list)
    results: List[Dict[str, Any]] = field(default_factory=list)
    rejected: List[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LoopResult:
    alert: str
    backend: str
    case: Dict[str, Any] = field(default_factory=dict)
    steps: List[Dict[str, Any]] = field(default_factory=list)
    final_answer: str = ""
    stopped_reason: str = ""
    grounding: Dict[str, Any] = field(default_factory=dict)
    elapsed_seconds: float = 0.0
    stats: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ToolLoop:
    """PDCERF 工具调用闭环。"""

    def __init__(
        self,
        backend: Any,
        executor: ActionExecutor,
        *,
        retriever: Any = None,
        rag_top_k: int = 5,
        intel_enabled: bool = True,
        intel_providers: Sequence[str] = ("mock",),
        max_steps: int = 6,
        max_calls_per_step: int = 3,
        only_trained_tools: bool = True,
        grounding: bool = True,
        max_new_tokens: int = 512,
        observation_budget_chars: int = 6000,
    ) -> None:
        self.backend = backend
        self.executor = executor
        self.retriever = retriever
        self.rag_top_k = int(rag_top_k)
        self.intel_enabled = bool(intel_enabled)
        self.intel_providers = list(intel_providers)
        self.max_steps = int(max_steps)
        self.max_calls_per_step = int(max_calls_per_step)
        self.only_trained_tools = bool(only_trained_tools)
        self.grounding = bool(grounding)
        self.max_new_tokens = int(max_new_tokens)
        self.observation_budget_chars = int(observation_budget_chars)

    # ------------------------------------------------------------------ #
    def _system_prompt(self) -> str:
        try:
            from agent.agent import build_system_prompt  # noqa: PLC0415
            base = build_system_prompt()
        except Exception:  # noqa: BLE001 — 允许脱离 agent 目录独立运行
            base = ("你是蓝队应急响应分析助手。职责：告警研判、日志与流量分析、"
                    "MITRE ATT&CK 映射、时间线还原、遏制与恢复。")
        return "\n\n".join([
            base,
            "【可用工具（按 PDCERF 阶段分组）】",
            tool_catalog_text(only_trained=self.only_trained_tools),
            build_output_protocol(self.max_calls_per_step),
        ])

    def _initial_context(self, alert: str) -> Tuple[str, str, List[Any]]:
        """返回 (kb_context, intel_text, hits)。"""
        kb_context, intel_text, hits = "", "", []
        if self.retriever is not None:
            try:
                ctx = self.retriever.build_context(alert, self.rag_top_k)
                kb_context, hits = ctx.text, list(ctx.hits)
            except Exception as exc:  # noqa: BLE001
                LOG.warning("RAG 检索失败，降级为无知识库：%s", mask_text(str(exc)))
        if self.intel_enabled:
            try:
                from intel.enrich import enrich  # noqa: PLC0415
                from rag.retrieve import extract_indicators  # noqa: PLC0415
                iocs = [v for kind, v in extract_indicators(alert)
                        if kind in ("ipv4", "sha256", "md5", "domain")]
                intel_text = enrich(iocs, self.intel_providers, max_iocs=4).text
            except Exception as exc:  # noqa: BLE001
                LOG.warning("情报富化失败，跳过：%s", mask_text(str(exc)))
        return kb_context, intel_text, hits

    # ------------------------------------------------------------------ #
    def run(self, alert: str, case: Optional[CaseState] = None) -> LoopResult:
        t0 = time.time()
        case = case or CaseState(case_id=f"loop-{int(t0)}")
        kb_context, intel_text, hits = self._initial_context(alert)
        system = self._system_prompt()

        header: List[str] = [
            "【本案观测】", alert.strip(), "",
            "【知识库检索结果】", kb_context.strip() or "（未检索到相关内容）", "",
            intel_text.strip() or "（未执行情报检索）", "",
        ]
        transcript: List[str] = []
        steps: List[LoopStep] = []
        final_answer = ""
        stopped = "max_steps"

        for step_idx in range(self.max_steps):
            phase_before = case.phase.value
            user = "\n".join(header + transcript + [
                "", phase_instruction(case.phase),
                "", f"（第 {step_idx + 1}/{self.max_steps} 步）请给出下一步："
                    f"若需要观测工具就输出动作 JSON，否则输出最终研判。",
            ])
            s_t0 = time.time()
            try:
                output = self.backend.generate(system, user, self.max_new_tokens)
            except Exception as exc:  # noqa: BLE001 — 后端故障要如实终止，不能假装完成
                stopped = f"backend_error: {type(exc).__name__}: {exc}"
                LOG.error("模型后端调用失败：%s", mask_text(str(exc)))
                break

            calls, rejected = parse_tool_calls(output)
            step = LoopStep(index=step_idx + 1, phase_before=phase_before,
                            phase_after=case.phase.value, model_output=output,
                            calls=calls, rejected=rejected)

            if not calls:
                final_answer = output
                stopped = "final_answer"
                step.elapsed_seconds = round(time.time() - s_t0, 2)
                steps.append(step)
                break

            results: List[Dict[str, Any]] = []
            obs_blocks: List[str] = []
            pending = False
            for i, call in enumerate(calls[: self.max_calls_per_step], start=1):
                res = self.executor.execute(
                    call, case,
                    dry_run=self.executor.policy.dry_run,
                    auto_confirm=self.executor.policy.allow_auto_confirm,
                )
                d = res.to_dict()
                results.append(d)
                obs_blocks.append(format_observation(i, d))
                if res.status == "pending_confirmation":
                    pending = True

            step.results = results
            step.phase_after = case.phase.value
            step.elapsed_seconds = round(time.time() - s_t0, 2)
            steps.append(step)

            transcript.append("【你上一步的输出】")
            transcript.append(output.strip()[:2000])
            transcript.append("")
            transcript.extend(obs_blocks)
            transcript.append("")

            # 观测预算：避免上下文无限增长（本项目实测 top_k 过大反而变差，同源问题）
            while sum(len(x) for x in transcript) > self.observation_budget_chars and len(transcript) > 6:
                del transcript[:2]

            if pending:
                stopped = "awaiting_confirmation"
                LOG.warning("出现待确认的不可逆动作，暂停工具循环（避免重复提交）")
                break

            # 无进展即停：本步所有结果都没有带来新信息（重复/拒绝/不可用），
            # 继续循环只会白烧步数并污染审计。把原因显式暴露，而不是静默耗尽 max_steps。
            progress = {r.get("status") for r in results} & {"ok", "dry_run", "pending_confirmation"}
            if not progress:
                stopped = "no_progress"
                LOG.warning("本步无任何新进展（状态=%s），提前终止工具循环",
                            sorted({r.get("status") for r in results}))
                break

        # 收敛：如果循环因「步数耗尽」或「无进展」而终止，补一次"收尾"生成
        if stopped in ("max_steps", "no_progress") and not final_answer:
            why = ("已达到工具调用步数上限" if stopped == "max_steps"
                   else "后续工具调用没有带来新信息（重复/被拒/不可用）")
            user = "\n".join(header + transcript + [
                "", phase_instruction(case.phase),
                "", f"{why}。请基于已有观测输出最终研判，不要再输出动作 JSON；"
                    f"若仍缺信息，请明确指出缺什么、以及无法获取的原因。",
            ])
            try:
                final_answer = self.backend.generate(system, user, self.max_new_tokens)
                stopped = f"{stopped}_wrapped"
            except Exception as exc:  # noqa: BLE001
                final_answer = ""
                stopped = f"backend_error: {type(exc).__name__}: {exc}"

        grounding: Dict[str, Any] = {}
        if self.grounding and final_answer:
            try:
                from rag.retrieve import grounding_check  # noqa: PLC0415
                contexts = [h.text for h in hits]
                report = grounding_check(final_answer, contexts, observation=alert, max_unsupported=0)
                grounding = report.to_dict()
            except Exception as exc:  # noqa: BLE001
                LOG.warning("接地校验不可用：%s", mask_text(str(exc)))

        return LoopResult(
            alert=alert,
            backend=getattr(self.backend, "name", "unknown"),
            case=case.to_dict(),
            steps=[s.to_dict() for s in steps],
            final_answer=final_answer,
            stopped_reason=stopped,
            grounding=grounding,
            elapsed_seconds=round(time.time() - t0, 2),
            stats=self.executor.stats(),
        )


def summarize(result: LoopResult) -> str:
    """一行摘要（CLI 用）。"""
    executed = [r for s in result.steps for r in s["results"]]
    ok = [r["action"] for r in executed if r.get("status") in ("ok", "dry_run")]
    lines = [
        f"案例={result.case.get('case_id')} 阶段={result.case.get('phase')} "
        f"步数={len(result.steps)} 停止原因={result.stopped_reason} 耗时={result.elapsed_seconds}s",
        f"工具调用={len(executed)} 次，成功/已演练={len(ok)}：{ok}",
        f"执行器统计={result.stats}",
    ]
    if result.grounding:
        lines.append(f"接地校验={'通过' if result.grounding.get('ok') else '未通过'}"
                     f"{' 编造指标=' + str(result.grounding.get('unsupported')) if not result.grounding.get('ok') else ''}")
    return "\n".join(lines)
