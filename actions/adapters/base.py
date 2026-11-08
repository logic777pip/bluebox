#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""actions/adapters/base.py — 工具适配器抽象层。

适配器 = 「PDCERF 动作」到「某个真实系统」的映射。每个适配器只声明**它能做哪些动作**
（`capabilities()`），执行器按配置顺序挑第一个可用且支持的适配器。

约定：
  * 适配器**不负责**安全校验（schema / 两阶段确认 / 保护资产）——那是 `ActionExecutor` 的职责，
    适配器只做「执行 + 如实汇报」，避免同一套策略在多个适配器里各写一遍然后漂移。
  * 执行结果用 `ToolResult` 表达，必须带 `observations`（给模型看的自然语言观测），
    因为「工具返回什么」决定了模型下一步怎么走。
  * 不可用（缺配置/缺密钥/连不上）必须**显式**返回 `unavailable`，不允许静默降级成模拟结果。
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from security.action_schema import Action  # noqa: E402

__all__ = ["ToolResult", "ToolContext", "Adapter", "AdapterError", "AdapterUnavailable", "ExecutionFailed"]


# 状态取值（executor 与评测脚本共用，不要随意扩充语义）
STATUS_OK = "ok"                            # 真实执行成功
STATUS_DRY_RUN = "dry_run"                  # 只演练，无副作用
STATUS_PENDING = "pending_confirmation"      # 不可逆动作已登记，等确认
STATUS_DENIED = "denied"                    # 策略/校验拒绝
STATUS_UNAVAILABLE = "unavailable"          # 无可用适配器
STATUS_DUPLICATE = "duplicate"              # 同一案例内重复动作，已去重
STATUS_FAILED = "failed"                    # 适配器执行失败


class AdapterError(RuntimeError):
    """适配器异常基类。"""


class AdapterUnavailable(AdapterError):
    """适配器不可用（未配置 / 缺凭据 / 不健康）。"""


class ExecutionFailed(AdapterError):
    """适配器执行失败（目标不存在、后端 5xx 等）。"""


@dataclass
class ToolContext:
    """执行上下文（避免适配器反向依赖 executor）。"""

    case_id: str = ""
    phase: str = "D"
    dry_run: bool = True
    case: Any = None            # CaseState，弱类型以避免循环依赖
    requested_by: str = "agent"
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolResult:
    ok: bool
    action: str
    adapter: str = "none"
    status: str = STATUS_OK
    output: Dict[str, Any] = field(default_factory=dict)
    observations: str = ""
    error: str = ""
    latency_ms: int = 0
    dry_run: bool = False
    simulated: bool = False
    rollback: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    # -- 便捷构造 -- #
    @classmethod
    def planned(cls, action: str, adapter: str, would_do: str, **output: Any) -> "ToolResult":
        return cls(
            ok=True, action=action, adapter=adapter, status=STATUS_DRY_RUN,
            output=output, observations=f"[dry-run] 未产生副作用。计划执行：{would_do}",
            dry_run=True,
        )

    @classmethod
    def denied(cls, action: str, reason: str) -> "ToolResult":
        return cls(ok=False, action=action, adapter="policy", status=STATUS_DENIED,
                   error=reason, observations=f"动作被策略拒绝：{reason}")

    @classmethod
    def failed(cls, action: str, adapter: str, reason: str) -> "ToolResult":
        return cls(ok=False, action=action, adapter=adapter, status=STATUS_FAILED,
                   error=reason, observations=f"{adapter} 执行失败：{reason}")


class Adapter(ABC):
    """工具适配器基类。"""

    name: str = "adapter"
    #: 该适配器是否会产生真实副作用（模拟/沙箱适配器为 False）
    real_effects: bool = True

    @abstractmethod
    def capabilities(self) -> Set[str]:
        """本适配器支持的动作名集合。"""

    def health(self) -> Tuple[bool, str]:
        """返回 (是否可用, 说明)。缺配置/缺密钥必须返回 False（fail-closed）。"""
        return True, ""

    @abstractmethod
    def execute(self, action: Action, ctx: ToolContext) -> ToolResult:
        """执行动作。实现里不得吞掉异常——失败要返回 STATUS_FAILED 或抛 ExecutionFailed。"""

    # -- 辅助 -- #
    def supports(self, action_name: str) -> bool:
        return action_name in self.capabilities()

    def describe(self) -> Dict[str, Any]:
        ok, why = self.health()
        return {
            "name": self.name,
            "healthy": ok,
            "health_detail": why,
            "real_effects": self.real_effects,
            "capabilities": sorted(self.capabilities()),
        }


def find_adapter(
    adapters: Sequence[Adapter],
    action_name: str,
    *,
    require_real: bool = False,
) -> Tuple[Optional[Adapter], List[str]]:
    """按顺序找第一个支持该动作且健康的适配器。

    Args:
        require_real: True 时跳过 `real_effects=False` 的适配器（真实执行模式用）。

    Returns:
        (适配器或 None, 跳过原因列表)
    """
    skipped: List[str] = []
    for ad in adapters:
        if not ad.supports(action_name):
            continue
        if require_real and not ad.real_effects:
            skipped.append(f"{ad.name}: 仅模拟，跳过（真实执行模式）")
            continue
        ok, why = ad.health()
        if not ok:
            skipped.append(f"{ad.name}: 不可用（{why}）")
            continue
        return ad, skipped
    if not skipped:
        skipped.append(f"没有适配器声明支持动作 {action_name}")
    return None, skipped
