#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""actions/adapters — 工具适配器包。

适配器按 `adapters.order` 顺序匹配：第一个「声明支持该动作 + 健康」的适配器被执行。
建议顺序：真实系统优先（soar）→ 本地沙箱（filesystem）→ 仿真靶场（sim）。

⚠ 模拟兜底是有前提的：真实执行模式下，`sim` 只有在
`policy.allow_sim_fallback: true`（靶场/自测场景）时才会被使用，
并且结果会带 `simulated: true` —— 不允许把仿真结果当成真实处置上报。
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from .base import (  # noqa: F401
    Adapter,
    AdapterError,
    AdapterUnavailable,
    ExecutionFailed,
    STATUS_DENIED,
    STATUS_DRY_RUN,
    STATUS_DUPLICATE,
    STATUS_FAILED,
    STATUS_OK,
    STATUS_PENDING,
    STATUS_UNAVAILABLE,
    ToolContext,
    ToolResult,
    find_adapter,
)
from .filesystem import FilesystemAdapter  # noqa: F401
from .http_soar import HttpSoarAdapter  # noqa: F401
from .simulated import RANGE_HOSTS, SimulatedRangeAdapter  # noqa: F401

__all__ = [
    "Adapter", "ToolContext", "ToolResult", "find_adapter",
    "SimulatedRangeAdapter", "FilesystemAdapter", "HttpSoarAdapter",
    "SandboxAdapter",
    "build_adapters", "default_adapters",
]


def _kape(cfg: Dict[str, Any]) -> Adapter:
    # 延迟 import：避免包初始化顺序与 forensics 子包互相牵扯。
    from .kape import KapeAdapter
    return KapeAdapter(cfg)


def _containment_placeholder(cfg: Dict[str, Any]) -> Adapter:
    from .containment_placeholder import ContainmentPlaceholderAdapter
    return ContainmentPlaceholderAdapter(cfg)


def _sandbox(cfg: Dict[str, Any]) -> Adapter:
    from .sandboxie import SandboxAdapter
    return SandboxAdapter(cfg)


_FACTORY = {
    "sim": lambda cfg, root: SimulatedRangeAdapter(seed=int(cfg.get("seed", 3407))),
    "soar": lambda cfg, root: HttpSoarAdapter(cfg),
    "filesystem": lambda cfg, root: FilesystemAdapter(
        root=root / str(cfg.get("root", "logs/toolbox")),
        enabled=bool(cfg.get("enabled", True)),
    ),
    # 取证（KAPE）—— `collect_forensics` 动作的落地点
    "kape": lambda cfg, root: _kape(cfg),
    # 沙箱联动：载荷只读固化 / 静态分析 / 人工交接包 / 最小影响封锁。
    # ⚠ 不含动态分析（`detonate_payload` 在动作表里就不存在）。
    "sandbox": lambda cfg, root: _sandbox(cfg),
    # 遏制（**仅占位**）—— 必须排在 sim 之前，否则 sim 会假装"遏制已成功"
    "containment_placeholder": lambda cfg, root: _containment_placeholder(cfg),
}


def build_adapters(cfg: Dict[str, Any], project_root: Optional[Path] = None) -> List[Adapter]:
    """按配置构建适配器列表。

    Args:
        cfg: `actions/config.yaml` 的完整配置（读 `adapters` 段）
        project_root: 项目根（filesystem 沙箱根相对此解析）
    """
    root = Path(project_root) if project_root else PROJECT_ROOT
    ad_cfg = (cfg or {}).get("adapters", {}) or {}
    order: Sequence[str] = ad_cfg.get("order") or ["soar", "filesystem", "sim"]

    adapters: List[Adapter] = []
    for key in order:
        key = str(key)
        factory = _FACTORY.get(key)
        if factory is None:
            continue
        sub = dict(ad_cfg.get(key, {}) or {})
        # sim 没有 enabled 字段时默认启用；其它适配器默认禁用，必须显式开启
        if key != "sim" and "enabled" not in sub:
            sub["enabled"] = False
        adapters.append(factory(sub, root))

    if not any(isinstance(a, SimulatedRangeAdapter) for a in adapters):
        adapters.append(SimulatedRangeAdapter())
    return adapters


def default_adapters() -> List[Adapter]:
    """无配置时的兜底：只用仿真靶场（绝不误连真实系统）。"""
    return [SimulatedRangeAdapter()]
