#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""actions — PDCERF 动作与工具层（让 AI 系统真正"能做事"，而不只是"会写 JSON"）。

分层：

    security/action_schema.py   R3 白名单 + R5 两阶段确认（安全闸门，唯一真相）
    actions/pdcerf.py           PDCERF 阶段机 + 案例状态（什么时候该做什么）
    actions/registry.py         动作 → 工具描述 / JSON Schema（对外的接口定义）
    actions/adapters/           工具适配器：soar(真实) / filesystem(沙箱) / sim(仿真)
    actions/executor.py         策略执行器：放行检查 → 路由 → 审计（唯一放行点）
    actions/toolkit.py          面向模型的工具接口（目录 / 协议解析 / 观测回执）
    actions/loop.py             PDCERF 驱动的工具调用闭环

典型用法：

    from actions import ActionExecutor, CaseState, ToolLoop

    executor = ActionExecutor.from_config()            # 默认 dry-run + 仿真靶场
    case = CaseState(case_id="INC-2026-101")
    result = executor.execute(
        {"action": "query_logs", "args": {"host_id": "fin-ws-07", "query": "rundll32"}},
        case,
    )
    print(result.observations)
"""

from __future__ import annotations

from .adapters import (  # noqa: F401
    Adapter,
    FilesystemAdapter,
    HttpSoarAdapter,
    SimulatedRangeAdapter,
    ToolContext,
    ToolResult,
    build_adapters,
)
from .executor import ActionExecutor, ExecutorPolicy  # noqa: F401
from .loop import LoopResult, ToolLoop, summarize  # noqa: F401
from .pdcerf import (  # noqa: F401
    ACTION_PHASES,
    ACTION_RISK,
    PHASE_META,
    PHASE_ORDER,
    PHASE_PREREQUISITES,
    TRAINED_ACTIONS,
    CaseState,
    Phase,
    PhaseError,
    check_registry_coverage,
    phase_table,
    primary_phase,
    risk_of,
    targets_of,
)
from .registry import (  # noqa: F401
    ALL_TOOL_NAMES,
    ToolSpec,
    build_tool_specs,
    openai_tools,
    text_catalog,
    tool_schema,
    validate_registry,
)
from .toolkit import (  # noqa: F401
    dispatch,
    format_observation,
    parse_tool_calls,
    phase_instruction,
    tool_catalog_text,
    tool_definitions,
)

__version__ = "1.0.0"

__all__ = [
    "__version__",
    # 阶段机
    "Phase", "PhaseError", "PHASE_META", "PHASE_ORDER", "PHASE_PREREQUISITES",
    "ACTION_PHASES", "ACTION_RISK", "TRAINED_ACTIONS",
    "CaseState", "phase_table", "primary_phase", "risk_of", "targets_of",
    "check_registry_coverage",
    # 工具定义
    "ToolSpec", "build_tool_specs", "tool_schema", "openai_tools", "text_catalog",
    "validate_registry", "ALL_TOOL_NAMES",
    # 适配器与执行器
    "Adapter", "ToolContext", "ToolResult", "build_adapters",
    "SimulatedRangeAdapter", "FilesystemAdapter", "HttpSoarAdapter",
    "ActionExecutor", "ExecutorPolicy",
    # 工具接口与闭环
    "tool_definitions", "tool_catalog_text", "phase_instruction",
    "parse_tool_calls", "format_observation", "dispatch",
    "ToolLoop", "LoopResult", "summarize",
]
