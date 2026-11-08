#!/usr/bin/env python3
"""actions/adapters/containment_placeholder.py —— 遏制动作的**占位适配器**。

用户明确要求：**遏制阶段仅使用占位**。

这个适配器存在的意义不是"实现遏制"，而是：
  1. 让 PDCERF 流程在"遏制(C)"阶段有明确的、不会越界的落点；
  2. 把"建议怎么遏制 + 代价是什么"完整回灌给模型与分析师
     （见 forensics/containment.py 的 prereqs/pitfalls）；
  3. **用代码保证**它永远不会改变系统状态 —— 不 import subprocess、
     不调用任何系统变更 API，返回值 `executed` 恒为 False。

为什么这样比"让它去调 sim 仿真适配器"更好：
    sim 适配器会返回"执行成功"，模型于是认为遏制**已经完成**，
    可能据此推进到根除/恢复阶段 —— 那是**假装处置**，比不处置更危险。
    占位适配器返回的是"计划已登记、未执行"，模型只能继续等人确认。

替换成真实实现时的正确做法（不要直接改本文件的行为）：
    写一个新适配器（如 containment_firewall.py / containment_edr.py），
    在 actions/config.yaml 的 adapters.order 里**排在它前面**，
    并把 placeholder_only 关掉。这样"占位"与"真执行"是两个可审计的文件，
    不会出现"哪天有人顺手把占位改成真执行、没人发现"的情况。
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, Set, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from actions.adapters.base import (Adapter, STATUS_DRY_RUN, ToolContext,  # noqa: E402
                                  ToolResult)
from forensics import containment as cont                                 # noqa: E402
from security.action_schema import Action                                 # noqa: E402

#: 会被本适配器接管的遏制(C)阶段动作
CONTAINMENT_ACTIONS: Tuple[str, ...] = (
    "isolate_host", "block_ip", "block_domain", "disable_account",
    "revoke_session", "restrict_account", "kill_process", "quarantine_file",
)


class ContainmentPlaceholderAdapter(Adapter):
    name = "containment_placeholder"
    #: 永远没有真实副作用
    real_effects = False

    def __init__(self, cfg: Dict[str, Any] | None = None) -> None:
        cfg = cfg or {}
        self.enabled: bool = bool(cfg.get("enabled", True))
        self.placeholder_only: bool = bool(cfg.get("placeholder_only", True))
        extra = cfg.get("placeholder_actions") or []
        self.actions: Tuple[str, ...] = tuple(extra) if extra else CONTAINMENT_ACTIONS

    def capabilities(self) -> Set[str]:
        # placeholder_only=false 时不接管任何动作（放开给其它适配器），
        # 这样"关掉占位"是一个显式行为，不会悄悄变成真执行。
        return set(self.actions) if (self.enabled and self.placeholder_only) else set()

    def health(self) -> Tuple[bool, str]:
        if not self.enabled:
            return False, "占位适配器已禁用"
        if not self.placeholder_only:
            return False, "placeholder_only=false：遏制动作不再由占位接管"
        ok = cont.assert_never_executes()
        return (ok, "占位模式：仅登记计划，不执行任何变更" if ok
                else "**内部检查失败**：占位模块疑似含有执行能力，已拒绝接管")

    def execute(self, action: Action, ctx: ToolContext) -> ToolResult:
        args = dict(action.args or {})
        if ctx.case_id and "case_id" not in args:
            args["case_id"] = ctx.case_id
        plan = cont.plan(action.name, args, action.rationale or "由 Agent 提案",
                         ctx.case_id)
        # 即使调用方把 dry_run 置为 false，这里也不执行 —— 占位是无条件的
        obs = (f"{cont.PLACEHOLDER_BANNER}（遏制仅登记计划）。\n"
               f"计划命令（**未执行**）：{plan.get('planned_command', '—')}\n"
               f"可逆性：{'可逆' if plan.get('reversible') else '不可逆'}\n"
               f"前置条件：" + "；".join(plan.get("prereqs") or ["—"]) + "\n"
               f"已知代价/坑：" + "；".join(plan.get("pitfalls") or ["—"]) + "\n"
               f"→ 需要人工确认后再执行；本系统不做处置。")
        return ToolResult(ok=True, action=action.name, adapter=self.name,
                          status=STATUS_DRY_RUN,
                          output={"placeholder": True, "executed": False,
                                  "plan": plan,
                                  "note": "遏制为占位实现：未执行任何变更"},
                          observations=obs)


def build(cfg: Dict[str, Any] | None = None) -> ContainmentPlaceholderAdapter:
    return ContainmentPlaceholderAdapter(cfg)
