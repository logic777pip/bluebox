#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""actions/pdcerf.py — PDCERF 应急响应模型的阶段机与案例状态。

PDCERF 六阶段（本文件是**唯一**的阶段元数据来源）：

    P 准备 Preparation   资产可见性、回滚点、备份可用性 —— 决定「一旦出事能不能救回来」
    D 检测 Detection     告警研判、情报富化、流量与时间线
    C 遏制 Containment   隔离 / 封禁 / 吊销 / 降权 —— 先止血，再谈根除
    E 根除 Eradication   清持久化、删恶意文件、轮换凭据、打补丁、重建
    R 恢复 Recovery      备份恢复、服务重启、解除隔离、完整性校验
    F 复盘 Follow-up     证据归档、复盘报告、检测规则、IOC 登记

设计要点：
  * 阶段归属放在本文件（而不是 security/action_schema.py）——schema 只管「能不能执行」，
    本文件管「什么时候该执行、需要哪些前置动作」。
  * 阶段推进是**单调前进**的；回退到已访问过的阶段仅用于「补充检测」这类合法回归，
    且会在时间线上留下 `regressed` 标记。
  * 前置约束是硬约束（可被配置关闭，但关闭即等于放弃 PDCERF 的因果顺序）：
      C 需要先有 D 的成功动作；E 需要先有 C；R 需要先有 C；F 需要先有 D。
    这样可以拦住「没看一眼就隔离」「没隔离就直接重建」这两类最常见的错误处置。

仅依赖标准库 + security.action_schema。
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security.action_schema import ACTION_SPECS  # noqa: E402

__all__ = [
    "Phase",
    "PhaseError",
    "PHASE_META",
    "PHASE_ORDER",
    "PHASE_PREREQUISITES",
    "ACTION_PHASES",
    "ACTION_RISK",
    "ACTION_TARGETS",
    "TRAINED_ACTIONS",
    "primary_phase",
    "phases_of",
    "risk_of",
    "targets_of",
    "is_trained",
    "check_registry_coverage",
    "CaseState",
]


# --------------------------------------------------------------------------- #
#  阶段定义
# --------------------------------------------------------------------------- #

class Phase(str, Enum):
    PREPARATION = "P"
    DETECTION = "D"
    CONTAINMENT = "C"
    ERADICATION = "E"
    RECOVERY = "R"
    FOLLOWUP = "F"

    @property
    def order(self) -> int:
        return PHASE_ORDER.index(self)


PHASE_ORDER: Tuple[Phase, ...] = (
    Phase.PREPARATION,
    Phase.DETECTION,
    Phase.CONTAINMENT,
    Phase.ERADICATION,
    Phase.RECOVERY,
    Phase.FOLLOWUP,
)

PHASE_META: Dict[Phase, Dict[str, str]] = {
    Phase.PREPARATION: {
        "zh": "准备", "en": "Preparation",
        "goal": "确认资产归属、可用回滚点与备份可用性，保证后续处置可逆",
        "exit": "已掌握受影响资产的责任人/角色，且存在可用快照或备份",
    },
    Phase.DETECTION: {
        "zh": "检测", "en": "Detection",
        "goal": "把告警收敛为可复现的事实：谁、在哪、做了什么、证据在哪",
        "exit": "有明确的受影响资产、时间线与可追溯证据（不能只凭告警文本）",
    },
    Phase.CONTAINMENT: {
        "zh": "遏制", "en": "Containment",
        "goal": "限制影响面：隔离受影响主机、切断 C2 对端、吊销被滥用凭据",
        "exit": "攻击者失去对受影响资产的通路，且业务影响已知",
    },
    Phase.ERADICATION: {
        "zh": "根除", "en": "Eradication",
        "goal": "移除持久化与恶意产物，修补被利用的入口",
        "exit": "持久化/恶意文件/被滥用凭据已清除，入口已修补或有明确缓解",
    },
    Phase.RECOVERY: {
        "zh": "恢复", "en": "Recovery",
        "goal": "受控地恢复业务，并验证恢复后没有残留活动",
        "exit": "业务恢复、隔离解除、完整性校验通过并有监控观察期",
    },
    Phase.FOLLOWUP: {
        "zh": "复盘", "en": "Follow-up",
        "goal": "归档证据、沉淀检测规则与 IOC、产出复盘结论",
        "exit": "证据链归档、检测规则更新、IOC 登记、工单关闭",
    },
}

# 阶段 → 必须先「成功执行过动作」的前置阶段
PHASE_PREREQUISITES: Dict[Phase, Tuple[Phase, ...]] = {
    Phase.PREPARATION: (),
    Phase.DETECTION: (),
    Phase.CONTAINMENT: (Phase.DETECTION,),
    Phase.ERADICATION: (Phase.CONTAINMENT,),
    Phase.RECOVERY: (Phase.CONTAINMENT,),
    Phase.FOLLOWUP: (Phase.DETECTION,),
}


# --------------------------------------------------------------------------- #
#  动作 → 阶段 / 风险 / 目标参数
# --------------------------------------------------------------------------- #

# 一个动作可以服务多个阶段，**首项为主阶段**（用于前置判定与阶段推进）。
ACTION_PHASES: Dict[str, Tuple[Phase, ...]] = {
    # 原有 10 个（微调模型已训练）
    "query_logs": (Phase.DETECTION, Phase.PREPARATION, Phase.FOLLOWUP),
    "collect_forensics": (Phase.DETECTION, Phase.CONTAINMENT),
    "notify_analyst": (Phase.DETECTION, Phase.FOLLOWUP),
    "close_case": (Phase.FOLLOWUP,),
    "block_ip": (Phase.CONTAINMENT,),
    "isolate_host": (Phase.CONTAINMENT,),
    "kill_process": (Phase.ERADICATION,),
    "quarantine_file": (Phase.ERADICATION,),
    "disable_account": (Phase.CONTAINMENT, Phase.ERADICATION),
    "restore_host": (Phase.RECOVERY,),
    # P
    "asset_lookup": (Phase.PREPARATION, Phase.DETECTION),
    "snapshot_host": (Phase.PREPARATION, Phase.ERADICATION),
    "verify_backup": (Phase.PREPARATION, Phase.RECOVERY),
    "raise_log_level": (Phase.PREPARATION, Phase.DETECTION),
    # D
    "enrich_ioc": (Phase.DETECTION,),
    "query_flow": (Phase.DETECTION,),
    "collect_timeline": (Phase.DETECTION, Phase.FOLLOWUP),
    "capture_pcap": (Phase.DETECTION,),
    # C
    "block_domain": (Phase.CONTAINMENT,),
    "revoke_session": (Phase.CONTAINMENT,),
    "restrict_account": (Phase.CONTAINMENT,),
    # E
    "remove_persistence": (Phase.ERADICATION,),
    "delete_file": (Phase.ERADICATION,),
    "reset_credential": (Phase.ERADICATION,),
    "patch_vulnerability": (Phase.ERADICATION,),
    "rebuild_host": (Phase.ERADICATION, Phase.RECOVERY),
    # R
    "restore_from_backup": (Phase.RECOVERY,),
    "restart_service": (Phase.RECOVERY,),
    "lift_isolation": (Phase.RECOVERY,),
    "verify_integrity": (Phase.RECOVERY, Phase.FOLLOWUP),
    # F
    "archive_evidence": (Phase.FOLLOWUP, Phase.DETECTION),
    "write_postmortem": (Phase.FOLLOWUP,),
    "update_detection_rule": (Phase.FOLLOWUP,),
    "publish_ioc": (Phase.FOLLOWUP,),
    # 沙箱与载荷。
    # extract/analyze/prepare 都在检测阶段 —— 它们只读现场 + 固化证据，不改系统状态。
    # contain_threat 落在遏制阶段（前置是检测，符合 PHASE_PREREQUISITES）。
    "extract_payload": (Phase.DETECTION, Phase.CONTAINMENT),
    "analyze_payload": (Phase.DETECTION, Phase.FOLLOWUP),
    "prepare_dynamic_analysis": (Phase.DETECTION, Phase.FOLLOWUP),
    "contain_threat": (Phase.CONTAINMENT,),
}

# 风险等级：决定是否需要人工确认以外的额外约束（见 executor 的策略层）
ACTION_RISK: Dict[str, str] = {
    "query_logs": "low", "collect_forensics": "medium", "notify_analyst": "low",
    "close_case": "medium", "block_ip": "high", "isolate_host": "high",
    "kill_process": "high", "quarantine_file": "high", "disable_account": "high",
    "restore_host": "high",
    "asset_lookup": "low", "snapshot_host": "medium", "verify_backup": "low",
    "raise_log_level": "medium",
    "enrich_ioc": "low", "query_flow": "low", "collect_timeline": "low",
    "capture_pcap": "medium",
    "block_domain": "high", "revoke_session": "medium", "restrict_account": "medium",
    "remove_persistence": "high", "delete_file": "high", "reset_credential": "high",
    "patch_vulnerability": "high", "rebuild_host": "critical",
    "restore_from_backup": "high", "restart_service": "medium", "lift_isolation": "high",
    "verify_integrity": "low",
    "archive_evidence": "low", "write_postmortem": "low",
    "update_detection_rule": "high", "publish_ioc": "medium",
    # 沙箱与载荷：提取/分析/交接都是只读或纯写文件，风险低；
    # contain_threat 会改防火墙，风险等级不能因为"范围小"而降低 ——
    # 风险等级驱动的是"要不要更严的约束"，而它确实是系统状态变更。
    "extract_payload": "medium", "analyze_payload": "low",
    "prepare_dynamic_analysis": "low", "contain_threat": "high",
}

# 动作的目标参数：用于对接受保护资产清单做匹配（破坏性动作打到保护对象 = 直接拒绝）
ACTION_TARGETS: Dict[str, Tuple[str, ...]] = {
    "block_ip": ("src_ip",),
    "isolate_host": ("host_id",),
    "kill_process": ("host_id",),
    "quarantine_file": ("host_id",),
    "delete_file": ("host_id",),
    "disable_account": ("account",),
    "revoke_session": ("account",),
    "restrict_account": ("account",),
    "reset_credential": ("account",),
    "restore_host": ("host_id",),
    "rebuild_host": ("host_id",),
    "restore_from_backup": ("host_id",),
    "restart_service": ("host_id",),
    "lift_isolation": ("host_id",),
    "remove_persistence": ("host_id",),
    "patch_vulnerability": ("host_id",),
    "snapshot_host": ("host_id",),
    "block_domain": ("domain",),
    # 沙箱：提取要落到具体主机上，所以声明 host_id（与 kill_process 等一致）。
    # contain_threat 的目标参数**刻意不是 indicator** —— indicator 是攻击者地址，
    # 不是我们要保护的资产标识；把它当资产匹配会出现「攻击者 IP 恰好与某资产名相同」
    # 这类假拒绝。这里声明 host_id，表示"在哪个主机上动防火墙"。
    "extract_payload": ("host_id",),
    "contain_threat": ("host_id",),
}

# 微调模型（Qwen2.5-3B QLoRA）实际见过的动作。给本地小模型下发工具目录时默认只用这些，
# 否则会出现「写得出动作名、但从未学过该格式」的假能力。
TRAINED_ACTIONS: frozenset = frozenset({
    "query_logs", "collect_forensics", "notify_analyst", "close_case", "block_ip",
    "isolate_host", "kill_process", "quarantine_file", "disable_account", "restore_host",
})


class PhaseError(RuntimeError):
    """阶段推进/前置条件不满足。"""


# --------------------------------------------------------------------------- #
#  查询辅助
# --------------------------------------------------------------------------- #

def phases_of(name: str) -> Tuple[Phase, ...]:
    return ACTION_PHASES.get(name, ())


def primary_phase(name: str) -> Optional[Phase]:
    ps = phases_of(name)
    return ps[0] if ps else None


def risk_of(name: str) -> str:
    return ACTION_RISK.get(name, "high")  # 未标注 → 按高风险处理（fail-closed）


def targets_of(name: str) -> Tuple[str, ...]:
    return ACTION_TARGETS.get(name, ())


def is_trained(name: str) -> bool:
    return name in TRAINED_ACTIONS


def check_registry_coverage() -> List[str]:
    """自检：白名单里的每个动作都必须有阶段/风险标注，且不得有孤儿标注。"""
    problems: List[str] = []
    for name in ACTION_SPECS:
        if name not in ACTION_PHASES:
            problems.append(f"动作 {name} 缺少 PDCERF 阶段归属")
        if name not in ACTION_RISK:
            problems.append(f"动作 {name} 缺少风险等级")
    for name in ACTION_PHASES:
        if name not in ACTION_SPECS:
            problems.append(f"阶段表里的 {name} 不在 ACTION_SPECS 白名单内")
    for name in ACTION_RISK:
        if name not in ACTION_SPECS:
            problems.append(f"风险表里的 {name} 不在 ACTION_SPECS 白名单内")
    return problems


# --------------------------------------------------------------------------- #
#  案例状态
# --------------------------------------------------------------------------- #

@dataclass
class CaseState:
    """一次事件处置的状态载体（阶段、事实、证据、时间线）。"""

    case_id: str
    phase: Phase = Phase.DETECTION
    severity: str = "MEDIUM"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    facts: Dict[str, Any] = field(default_factory=dict)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    phases_visited: List[str] = field(default_factory=lambda: [Phase.DETECTION.value])
    actions_ok: List[str] = field(default_factory=list)

    # -- 查询 -- #
    def has_visited(self, phase: "Phase | str") -> bool:
        return Phase(phase).value in self.phases_visited

    def actions_in(self, phase: "Phase | str") -> List[str]:
        """成功执行过、且主阶段等于 phase 的动作名（去重）。"""
        p = Phase(phase)
        return sorted({n for n in self.actions_ok if primary_phase(n) == p})

    # -- 前置判定 -- #
    def can_enter(self, phase: "Phase | str") -> Tuple[bool, str]:
        p = Phase(phase)
        if p == self.phase:
            return True, ""
        missing = [q for q in PHASE_PREREQUISITES.get(p, ()) if not self.actions_in(q)]
        if missing:
            names = "、".join(f"{q.value}({PHASE_META[q]['zh']})" for q in missing)
            return False, (
                f"进入 {p.value}({PHASE_META[p]['zh']}) 前必须先有 {names} 阶段的成功动作；"
                f"当前案例 {self.case_id} 只记录到 {self.actions_ok or ['（无）']}"
            )
        return True, ""

    # -- 推进 -- #
    def advance(self, phase: "Phase | str", reason: str = "") -> None:
        """推进（或合法回退）到目标阶段。前置不满足时抛 PhaseError。"""
        p = Phase(phase)
        ok, why = self.can_enter(p)
        if not ok:
            raise PhaseError(why)

        regressed = p.order < self.phase.order
        if regressed and not self.has_visited(p):
            raise PhaseError(
                f"不允许回退到从未访问过的 {p.value}({PHASE_META[p]['zh']})；"
                f"要求补充检测请使用已访问过的阶段"
            )
        prev = self.phase
        self.phase = p
        if p.value not in self.phases_visited:
            self.phases_visited.append(p.value)
        self.updated_at = time.time()
        self.timeline.append({
            "ts": self.updated_at, "kind": "phase_change",
            "from": prev.value, "to": p.value,
            "regressed": regressed, "reason": reason,
        })

    # -- 记录 -- #
    def record(self, action_name: str, result: Dict[str, Any]) -> None:
        """记录一次工具调用结果；只有成功（或 dry_run 计划）才计入 actions_ok。"""
        status = str(result.get("status", ""))
        self.timeline.append({
            "ts": time.time(), "kind": "action", "case_id": self.case_id,
            "action": action_name, "status": status,
            "adapter": result.get("adapter", ""),
            "ok": bool(result.get("ok")),
            "detail": result.get("error", "") or result.get("observations", "")[:200],
        })
        if bool(result.get("ok")) and status in ("ok", "dry_run"):
            if action_name not in self.actions_ok:
                self.actions_ok.append(action_name)
            # 动作落在更靠后的阶段 → 自动推进（前置检查在 advance 内）
            p = primary_phase(action_name)
            if p is not None and p.order > self.phase.order:
                try:
                    self.advance(p, reason=f"由动作 {action_name} 触发自动推进")
                except PhaseError:
                    pass  # 前置不满足时保持原阶段（不动结果，由策略层决定是否拦截）
        self.updated_at = time.time()

    def add_evidence(self, item: Dict[str, Any]) -> None:
        self.evidence.append({"ts": time.time(), **item})
        self.updated_at = time.time()

    # -- 序列化 -- #
    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["phase"] = self.phase.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CaseState":
        payload = dict(data)
        payload["phase"] = Phase(payload.get("phase", "D"))
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in payload.items() if k in known})

    def save(self, path: Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: Path) -> "CaseState":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    # -- 展示 -- #
    def describe(self) -> str:
        meta = PHASE_META[self.phase]
        covered = {p.value: len(self.actions_in(p)) for p in PHASE_ORDER}
        return (
            f"案例 {self.case_id} | 阶段={self.phase.value}({meta['zh']}) "
            f"| 严重度={self.severity} | 已访问阶段={''.join(self.phases_visited)} "
            f"| 各阶段成功动作数={covered} | 证据={len(self.evidence)} 条"
        )


def phase_table() -> List[Dict[str, Any]]:
    """阶段总览（供 CLI/文档渲染）。"""
    rows: List[Dict[str, Any]] = []
    for p in PHASE_ORDER:
        req = PHASE_PREREQUISITES.get(p, ())
        rows.append({
            "phase": p.value,
            "zh": PHASE_META[p]["zh"],
            "en": PHASE_META[p]["en"],
            "goal": PHASE_META[p]["goal"],
            "exit": PHASE_META[p]["exit"],
            "requires": [q.value for q in req],
            "actions": [n for n, ps in ACTION_PHASES.items() if ps and ps[0] == p],
        })
    return rows
