#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""actions/registry.py — 动作 → 工具（Tool Spec / JSON Schema）注册表。

把 `security.action_schema.ACTION_SPECS`（安全闸门）与 `actions.pdcerf`（阶段/风险元数据）
合并成**对外工具接口**：

  * `ToolSpec`          —— 一个动作的完整描述（给策略层、审计、文档用）
  * `tool_schema()`     —— OpenAI / Function-Calling 兼容的 `parameters` JSON Schema
  * `openai_tools()`    —— 可直接喂给 llama-server / Ollama `/v1/chat/completions` 的 tools 数组
  * `text_catalog()`    —— 给**没有原生 function-calling** 的小模型用的文本版工具目录
                          （本项目微调模型学的是 ```action {"action":...,"args":{...}}``` 文本协议）

一致性保证：`ARG_SCHEMA` 必须覆盖白名单里出现的每一个参数名，`validate_registry()` 会自检。
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security.action_schema import ACTION_SPECS  # noqa: E402

from .pdcerf import (  # noqa: E402
    PHASE_META,
    PHASE_ORDER,
    Phase,
    is_trained,
    phases_of,
    primary_phase,
    risk_of,
    targets_of,
)

__all__ = [
    "ToolSpec",
    "ARG_SCHEMA",
    "build_tool_specs",
    "tool_spec",
    "tool_schema",
    "openai_tools",
    "text_catalog",
    "validate_registry",
    "ALL_TOOL_NAMES",
]

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,127}$"

# 参数名 → JSON Schema 片段（与 security/action_schema.py::_check_type 保持同源语义）
ARG_SCHEMA: Dict[str, Dict[str, Any]] = {
    # 通用标识
    "host_id": {"type": "string", "pattern": _ID_PATTERN, "description": "主机资产标识"},
    "account": {"type": "string", "pattern": _ID_PATTERN, "description": "账号名"},
    "domain": {"type": "string", "pattern": _ID_PATTERN, "description": "域/域名"},
    "case_id": {"type": "string", "pattern": _ID_PATTERN, "description": "事件工单号"},
    "snapshot_id": {"type": "string", "pattern": _ID_PATTERN, "description": "快照/备份点标识"},
    "asset": {"type": "string", "minLength": 1, "maxLength": 256, "description": "资产名/IP/URI"},
    "src_ip": {"type": "string", "description": "IP 或网段"},
    "indicator": {"type": "string", "minLength": 2, "maxLength": 512,
                  "description": "IOC：IP / 域名 / 文件哈希 / URL"},
    # 数值
    "pid": {"type": "integer", "minimum": 1, "description": "进程号"},
    "ttl_seconds": {"type": "integer", "minimum": 1, "maximum": 86400,
                    "description": "封禁/登记有效期（秒）"},
    "window_minutes": {"type": "integer", "minimum": 1, "maximum": 10080,
                       "description": "检索时间窗（分钟）"},
    "duration_seconds": {"type": "integer", "minimum": 1, "maximum": 3600,
                         "description": "抓包时长（秒）"},
    # 结构化
    "artifacts": {"type": "array", "minItems": 1, "items": {"type": "string"},
                  "description": "取证/校验产物列表"},
    "path": {"type": "string", "description": "文件路径（禁止目录穿越）"},
    "sha256": {"type": "string", "pattern": r"^[0-9a-fA-F]{64}$", "description": "SHA-256"},
    "cve": {"type": "string", "pattern": r"^CVE-\d{4}-\d{4,7}$", "description": "CVE 编号"},
    "rule_id": {"type": "string", "pattern": _ID_PATTERN, "description": "检测规则标识"},
    "rule": {"type": "string", "minLength": 1, "maxLength": 4000,
             "description": "检测规则内容（Sigma/YARA/KQL 等）"},
    "image": {"type": "string", "pattern": _ID_PATTERN, "description": "黄金镜像标识"},
    "service": {"type": "string", "pattern": _ID_PATTERN, "description": "服务名"},
    "label": {"type": "string", "minLength": 1, "maxLength": 256, "description": "备注标签"},
    # 枚举
    "mode": {"type": "string", "enum": ["soft", "hard"], "description": "隔离强度"},
    "direction": {"type": "string", "enum": ["inbound", "outbound", "both"],
                  "description": "封禁方向"},
    "severity": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
    "verdict": {"type": "string", "enum": ["true_positive", "false_positive", "benign"]},
    "scope": {"type": "string", "enum": ["process", "network", "auth", "all"],
              "description": "采集粒度范围"},
    "mechanism": {
        "type": "string",
        "enum": ["scheduled_task", "service", "registry_run", "cron", "startup",
                 "ssh_authorized_key", "wmi_subscription", "all"],
        "description": "要清除的持久化机制（仅清除，不涉及创建）",
    },
    # 自由文本
    "summary": {"type": "string", "minLength": 1, "maxLength": 2000},
    "reason": {"type": "string", "minLength": 1, "maxLength": 2000},
    "query": {"type": "string", "minLength": 1, "maxLength": 2000,
              "description": "日志检索条件"},
}


@dataclass(frozen=True)
class ToolSpec:
    """一个动作的对外描述（安全闸门 + PDCERF 元数据的合并视图）。"""

    name: str
    description: str
    required: Tuple[str, ...]
    optional: Tuple[str, ...]
    irreversible: bool
    phases: Tuple[Phase, ...]
    risk: str
    targets: Tuple[str, ...]
    trained: bool
    parameters: Dict[str, Any] = field(default_factory=dict)

    @property
    def phase(self) -> Phase:
        return self.phases[0]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "phase": self.phase.value,
            "phase_zh": PHASE_META[self.phase]["zh"],
            "phases": [p.value for p in self.phases],
            "risk": self.risk,
            "irreversible": self.irreversible,
            "requires_confirmation": self.irreversible,
            "trained": self.trained,
            "targets": list(self.targets),
            "required": list(self.required),
            "optional": list(self.optional),
            "parameters": self.parameters,
        }


def tool_schema(name: str) -> Dict[str, Any]:
    """生成某个动作的 JSON Schema（parameters 部分）。"""
    spec = ACTION_SPECS[name]
    props: Dict[str, Any] = {}
    for arg in spec.required + spec.optional:
        props[arg] = ARG_SCHEMA.get(arg, {"type": "string", "description": arg})
    return {
        "type": "object",
        "properties": props,
        "required": list(spec.required),
        "additionalProperties": False,
    }


def _build_one(name: str) -> ToolSpec:
    spec = ACTION_SPECS[name]
    ps = phases_of(name)
    assert ps, f"{name} 缺少 PDCERF 阶段归属"
    return ToolSpec(
        name=name,
        description=spec.description or name,
        required=tuple(spec.required),
        optional=tuple(spec.optional),
        irreversible=bool(spec.irreversible),
        phases=ps,
        risk=risk_of(name),
        targets=targets_of(name),
        trained=is_trained(name),
        parameters=tool_schema(name),
    )


_ALL: Optional[Dict[str, ToolSpec]] = None


def build_tool_specs(refresh: bool = False) -> Dict[str, ToolSpec]:
    """构建（并缓存）全部工具描述。"""
    global _ALL
    if _ALL is None or refresh:
        _ALL = {name: _build_one(name) for name in ACTION_SPECS}
    return _ALL


ALL_TOOL_NAMES: Tuple[str, ...] = tuple(ACTION_SPECS.keys())


def tool_spec(name: str) -> ToolSpec:
    return build_tool_specs()[name]


def _select(
    phases: Optional[Sequence["Phase | str"]] = None,
    only_trained: bool = False,
    include_irreversible: bool = True,
) -> List[ToolSpec]:
    wanted = {Phase(p) for p in phases} if phases else None
    out: List[ToolSpec] = []
    for name in ACTION_SPECS:
        spec = tool_spec(name)
        if wanted is not None and not (wanted & set(spec.phases)):
            continue
        if only_trained and not spec.trained:
            continue
        if not include_irreversible and spec.irreversible:
            continue
        out.append(spec)
    return sorted(out, key=lambda s: (s.phase.order, s.name))


def openai_tools(
    phases: Optional[Sequence["Phase | str"]] = None,
    only_trained: bool = False,
    include_irreversible: bool = True,
) -> List[Dict[str, Any]]:
    """OpenAI 兼容的 tools 数组（可直接放进 /v1/chat/completions 的 "tools"）。"""
    return [
        {
            "type": "function",
            "function": {
                "name": s.name,
                "description": (
                    f"[{s.phase.value}/{PHASE_META[s.phase]['zh']}] {s.description}"
                    + (f"（风险 {s.risk}，不可逆，需人工确认）" if s.irreversible else "")
                ),
                "parameters": s.parameters,
            },
        }
        for s in _select(phases, only_trained, include_irreversible)
    ]


def text_catalog(
    phases: Optional[Sequence["Phase | str"]] = None,
    only_trained: bool = False,
    include_irreversible: bool = True,
    show_args: bool = True,
) -> str:
    """文本版工具目录（按 PDCERF 阶段分组），用于无原生 tool-calling 的模型提示词。"""
    specs = _select(phases, only_trained, include_irreversible)
    by_phase: Dict[Phase, List[ToolSpec]] = {p: [] for p in PHASE_ORDER}
    for s in specs:
        by_phase[s.phase].append(s)

    lines: List[str] = []
    for p in PHASE_ORDER:
        items = by_phase.get(p) or []
        if not items:
            continue
        lines.append(f"## {p.value} {PHASE_META[p]['zh']}（{PHASE_META[p]['en']}）")
        lines.append(f"（{PHASE_META[p]['goal']}）")
        for s in items:
            flags = []
            if s.irreversible:
                flags.append("不可逆/需确认")
            if s.risk in ("high", "critical"):
                flags.append(f"高风险 {s.risk}")
            if not s.trained:
                flags.append("未训练")
            tail = f"  [{'; '.join(flags)}]" if flags else ""
            lines.append(f"- {s.name}: {s.description}{tail}")
            if show_args:
                req = ", ".join(s.required)
                opt = ", ".join(s.optional)
                lines.append(f"    必填({req})" + (f" 可选({opt})" if opt else ""))
        lines.append("")
    return "\n".join(lines).rstrip()


def validate_registry() -> List[str]:
    """自检：Schema 与白名单/元数据的一致性。返回问题列表（空 = 通过）。"""
    problems: List[str] = []
    for name in ACTION_SPECS:
        spec = ACTION_SPECS[name]
        for arg in spec.required + spec.optional:
            if arg not in ARG_SCHEMA:
                problems.append(f"{name}.{arg} 缺少 ARG_SCHEMA 定义（工具 schema 会退化为裸 string）")
        for arg in spec.required:
            if arg not in tool_schema(name)["required"]:
                problems.append(f"{name}.{arg} 是必填但没有出现在 JSON Schema required 里")
    for arg in ARG_SCHEMA:
        used = any(arg in (ACTION_SPECS[n].required + ACTION_SPECS[n].optional) for n in ACTION_SPECS)
        if not used:
            problems.append(f"ARG_SCHEMA 中的 {arg} 未被任何动作使用（冗余定义）")
    return problems
