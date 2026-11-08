#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""actions/executor.py — PDCERF 动作执行器（策略层 / 唯一放行点）。

任何动作要真正落地，必须依次通过这 7 道检查（全部 fail-closed）：

  ① R3 schema 白名单校验      —— `security.action_schema.validate_action()`，未知动作/未知字段一律拒绝
  ② 案例预算                  —— 单案例动作总数上限（防失控循环）
  ③ 保护对象                  —— 不可逆动作打到受保护资产（域控/备份/跳板机/管理员账号）直接拒绝
  ④ PDCERF 前置               —— 处置类动作（不可逆或高风险）必须先满足阶段前置：
                                 C←D、E←C、R←C、F←D；只读动作不受限（补充检测永远允许）
  ⑤ R5 两阶段确认             —— 不可逆动作需 HMAC 签名确认；未确认只产出待办提案，不执行
                                 （**先于去重**：确认令牌重放属安全事件，不能被 duplicate 掩盖）
  ⑥ 幂等去重                  —— 同一案例内相同动作+参数只执行一次，重复调用返回首次结果
  ⑦ 适配器路由                —— 真实执行模式下不允许静默降级到仿真靶场

之后才写审计（R1 脱敏）并回填 `CaseState`（时间线 + 阶段推进）。
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

from security.action_schema import (  # noqa: E402
    Action,
    ConfirmationError,
    SchemaError,
    TwoPhaseGuard,
    is_irreversible,
    validate_action,
)
from security.sanitize import get_logger, mask_obj, mask_text  # noqa: E402

from .adapters import (  # noqa: E402
    Adapter,
    AdapterUnavailable,
    SimulatedRangeAdapter,
    ToolContext,
    ToolResult,
    build_adapters,
    default_adapters,
    find_adapter,
)
from .pdcerf import (  # noqa: E402
    PHASE_META,
    CaseState,
    Phase,
    PhaseError,
    primary_phase,
    risk_of,
    targets_of,
)
from .registry import build_tool_specs  # noqa: E402

LOG = get_logger("actions.executor")

__all__ = ["ExecutorPolicy", "ActionExecutor", "ExecutionRecord"]

CONFIG_PATH = PROJECT_ROOT / "actions" / "config.yaml"


# --------------------------------------------------------------------------- #
#  策略
# --------------------------------------------------------------------------- #

@dataclass
class ExecutorPolicy:
    dry_run: bool = True
    allow_auto_confirm: bool = False
    enforce_prerequisites: bool = True
    strict_phase: bool = False
    max_actions_per_case: int = 200
    allow_sim_fallback: bool = True
    protected_hosts: List[str] = field(default_factory=list)
    protected_accounts: List[str] = field(default_factory=list)
    protected_domains: List[str] = field(default_factory=list)
    protected_ips: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, cfg: Dict[str, Any]) -> "ExecutorPolicy":
        ex = (cfg or {}).get("executor", {}) or {}
        pol = (cfg or {}).get("policy", {}) or {}
        return cls(
            dry_run=bool(ex.get("dry_run", True)),
            allow_auto_confirm=bool(ex.get("allow_auto_confirm", False)),
            enforce_prerequisites=bool(ex.get("enforce_prerequisites", True)),
            strict_phase=bool(ex.get("strict_phase", False)),
            max_actions_per_case=int(ex.get("max_actions_per_case", 200)),
            allow_sim_fallback=bool(pol.get("allow_sim_fallback", True)),
            protected_hosts=[str(x) for x in pol.get("protected_hosts", []) or []],
            protected_accounts=[str(x) for x in pol.get("protected_accounts", []) or []],
            protected_domains=[str(x) for x in pol.get("protected_domains", []) or []],
            protected_ips=[str(x) for x in pol.get("protected_ips", []) or []],
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExecutionRecord:
    """一次动作的完整审计记录（脱敏后落盘）。"""

    ts: float
    case_id: str
    phase: str
    action: str
    args: Dict[str, Any]
    status: str
    adapter: str
    ok: bool
    irreversible: bool
    risk: str
    dry_run: bool
    simulated: bool
    error: str = ""
    observations: str = ""
    proposal_id: str = ""
    policy_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- #
#  执行器
# --------------------------------------------------------------------------- #

class ActionExecutor:
    """动作执行器。构造一次可服务多个案例。"""

    def __init__(
        self,
        adapters: Optional[Sequence[Adapter]] = None,
        policy: Optional[ExecutorPolicy] = None,
        *,
        pending_dir: Optional[Path] = None,
        audit_path: Optional[Path] = None,
        confirm_ttl_seconds: int = 300,
        project_root: Optional[Path] = None,
    ) -> None:
        self.root = Path(project_root) if project_root else PROJECT_ROOT
        self.policy = policy or ExecutorPolicy()
        self.adapters: List[Adapter] = list(adapters) if adapters is not None else default_adapters()
        self.pending_dir = Path(pending_dir) if pending_dir else self.root / "logs" / "pending_actions"
        self.audit_path = Path(audit_path) if audit_path else self.root / "logs" / "action_audit.jsonl"
        self.guard = TwoPhaseGuard(self.pending_dir, ttl_seconds=confirm_ttl_seconds)
        self.records: List[ExecutionRecord] = []
        self._applied: Dict[str, ToolResult] = {}   # (case_id|fingerprint) → 首次结果（幂等去重）
        self._pending: Dict[str, ToolResult] = {}   # 已登记的待确认提案（防止重复刷提案）

    # ------------------------------------------------------------------ #
    @classmethod
    def from_config(
        cls,
        config_path: Optional[Path] = None,
        *,
        project_root: Optional[Path] = None,
        adapters: Optional[Sequence[Adapter]] = None,
        dry_run: Optional[bool] = None,
    ) -> "ActionExecutor":
        """从 `actions/config.yaml` 构建（缺配置时退化为「仅仿真 + dry-run」）。"""
        root = Path(project_root) if project_root else PROJECT_ROOT
        path = Path(config_path) if config_path else (root / "actions" / "config.yaml")
        cfg: Dict[str, Any] = {}
        if path.exists():
            import yaml  # noqa: PLC0415
            cfg = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        else:
            LOG.warning("未找到执行器配置 %s，使用安全默认值（仅仿真 + dry-run）", path)

        policy = ExecutorPolicy.from_dict(cfg)
        if dry_run is not None:
            policy.dry_run = bool(dry_run)

        adapter_list = list(adapters) if adapters is not None else build_adapters(cfg, root)
        audit_cfg = cfg.get("executor", {}) or {}
        return cls(
            adapters=adapter_list,
            policy=policy,
            pending_dir=root / str(audit_cfg.get("pending_dir", "logs/pending_actions")),
            audit_path=root / str(audit_cfg.get("audit_path", "logs/action_audit.jsonl")),
            confirm_ttl_seconds=int(audit_cfg.get("confirm_ttl_seconds", 300)),
            project_root=root,
        )

    # ------------------------------------------------------------------ #
    #  策略检查（可单独调用，用于预演/审计）
    # ------------------------------------------------------------------ #
    def _protected_hit(self, action: Action) -> Tuple[bool, str]:
        pol = self.policy
        for arg in targets_of(action.name):
            val = str(action.args.get(arg, ""))
            if not val:
                continue
            if arg == "host_id" and val in pol.protected_hosts:
                return True, f"{val} 在保护主机清单内（域控/备份/跳板机等）"
            if arg == "account" and val in pol.protected_accounts:
                return True, f"{val} 是保护账号（服务账号/应急账号）"
            if arg == "domain" and val in pol.protected_domains:
                return True, f"{val} 是保护域（业务依赖域名）"
            if arg == "src_ip" and val in pol.protected_ips:
                return True, f"{val} 在保护网段/地址清单内"
        return False, ""

    def check_policy(self, action: Action, case: CaseState) -> Tuple[bool, str]:
        """不执行，只回答「这个动作在当前案例下会不会被放行」。"""
        if self.policy.max_actions_per_case > 0:
            executed = sum(1 for e in case.timeline if e.get("kind") == "action")
            if executed >= self.policy.max_actions_per_case:
                return False, f"案例已达动作上限 {self.policy.max_actions_per_case}（防失控循环）"

        if action.irreversible:
            hit, why = self._protected_hit(action)
            if hit:
                return False, f"保护对象拦截：{why}；不可逆动作不得作用于保护对象"

        # 只读动作不受阶段前置约束（补充检测、复盘回看永远允许）
        if action.irreversible or risk_of(action.name) in ("high", "critical"):
            p = primary_phase(action.name)
            if p is None:
                return False, f"动作 {action.name} 缺少 PDCERF 阶段归属"
            if self.policy.strict_phase and case.phase != p:
                return False, (f"strict_phase=true：{action.name} 属 {p.value}"
                               f"({PHASE_META[p]['zh']})，但案例当前处于 {case.phase.value}")
            if self.policy.enforce_prerequisites:
                ok, why = case.can_enter(p)
                if not ok:
                    return False, why
        return True, ""

    # ------------------------------------------------------------------ #
    #  执行
    # ------------------------------------------------------------------ #
    def execute(
        self,
        raw: Any,
        case: CaseState,
        *,
        confirmation: Optional[Tuple[str, str]] = None,
        dry_run: Optional[bool] = None,
        auto_confirm: Optional[bool] = None,
    ) -> ToolResult:
        """执行一个动作。

        Args:
            raw: 模型原始输出（dict 或 JSON 字符串）
            case: 案例状态（会被就地更新：时间线 + 阶段推进）
            confirmation: (proposal_id, signature)，两阶段确认的第二次调用
            dry_run: 覆盖策略中的 dry_run
            auto_confirm: 覆盖策略中的 allow_auto_confirm（仅靶场/自测使用）
        """
        dry = self.policy.dry_run if dry_run is None else bool(dry_run)
        auto = self.policy.allow_auto_confirm if auto_confirm is None else bool(auto_confirm)

        # ① R3 schema
        try:
            action = validate_action(raw)
        except SchemaError as exc:
            return self._finalize(
                ToolResult.denied(str((raw or {}).get("action", "?") if isinstance(raw, dict) else "?"),
                                  f"schema 校验失败：{exc}"),
                case, args=raw if isinstance(raw, dict) else {}, proposal_id="",
                policy_reason="R3 默认拒绝",
            )

        args = dict(action.args)

        # ②③④ 策略
        ok, why = self.check_policy(action, case)
        if not ok:
            return self._finalize(
                ToolResult.denied(action.name, why), case, args=args, policy_reason=why,
            )

        # ⑤ R5 两阶段确认（**必须先于去重**：确认令牌重放属安全事件，
        #    不能被「重复动作」的 duplicate 掩盖掉）
        dedup_key = f"{case.case_id}|{action.fingerprint()}"
        proposal_id = ""
        if action.irreversible and not dry:
            if confirmation is not None:
                proposal_id, signature = confirmation
                try:
                    self.guard.confirm(proposal_id, signature, action)
                except ConfirmationError as exc:
                    return self._finalize(
                        ToolResult.denied(action.name, f"两阶段确认失败：{exc}"),
                        case, args=args, proposal_id=proposal_id, policy_reason="R5 确认未通过",
                    )
            elif auto:
                proposal_id, _rec = self.guard.propose(action, case_id=case.case_id)
                self.guard.confirm(proposal_id, self.guard.expected_signature(proposal_id, action), action)
                LOG.warning("自动确认已启用（靶场模式）：%s %s", action.name,
                            mask_text(json.dumps(args, ensure_ascii=False)))
            else:
                # 同一案例内重复提交同一不可逆动作 → 复用已登记的提案，不重复刷提案
                if dedup_key in self._pending:
                    prev = self._pending[dedup_key]
                    return ToolResult(
                        ok=False, action=action.name, adapter="guard",
                        status="pending_confirmation",
                        output=dict(prev.output),
                        observations=(
                            f"同一案例内已存在该动作的待确认提案"
                            f"（proposal_id={prev.output.get('proposal_id')}），本次不再重复登记。"
                            f"在确认前不要反复提交；若目标已变更，请改用不同参数。"
                        ),
                        error="需要两阶段确认（R5）",
                    )
                pid, _rec = self.guard.propose(action, case_id=case.case_id)
                pending = ToolResult(
                    ok=False, action=action.name, adapter="guard", status="pending_confirmation",
                    output={"proposal_id": pid, "action": action.name, "args": args,
                            "irreversible": True, "risk": risk_of(action.name),
                            "expires_in_seconds": self.guard.ttl},
                    observations=(
                        f"不可逆动作 [{action.name}] 已登记为待确认提案（proposal_id={pid}）。"
                        f"需人工/策略引擎用 HMAC 签名确认后才执行，TTL={self.guard.ttl}s。"
                        f"在此之前不会产生任何副作用。"
                    ),
                    error="需要两阶段确认（R5）",
                )
                self._pending[dedup_key] = pending
                return self._finalize(pending, case, args=args, proposal_id=pid,
                                      policy_reason="R5 待人工确认", record_action=False)

        # ⑥ 幂等去重（副作用层）
        if dedup_key in self._applied:
            first = self._applied[dedup_key]
            dup = ToolResult(
                ok=first.ok, action=action.name, adapter=first.adapter, status="duplicate",
                output={**first.output, "duplicate_of_status": first.status},
                observations=f"同一案例内该动作（含参数）已执行过，本次不再重复执行。"
                             f"首次结果状态={first.status}。"
                             + (f" 首次观测：{first.observations}" if first.observations else ""),
                dry_run=first.dry_run, simulated=first.simulated,
            )
            return self._finalize(dup, case, args=args, policy_reason="幂等去重（未重复产生副作用）")

        # ⑦ 干跑
        if dry:
            plan = self._plan_text(action)
            target_ad = self._pick_adapter(action.name, require_real=False)[0]
            res = ToolResult.planned(
                action.name, target_ad.name if target_ad else "none",
                plan + ("（注意：该动作不可逆，真实执行时需要两阶段确认）" if action.irreversible else ""),
                target_present=target_ad is not None,
                would_require_confirmation=action.irreversible,
                risk=risk_of(action.name),
                phase=(primary_phase(action.name).value if primary_phase(action.name) else ""),
            )
            self._applied[dedup_key] = res
            return self._finalize(res, case, args=args, policy_reason="dry-run")

        # 适配器路由
        adapter, skipped = self._pick_adapter(action.name, require_real=not self.policy.allow_sim_fallback)
        if adapter is None:
            res = ToolResult(
                ok=False, action=action.name, adapter="none", status="unavailable",
                error="无可用适配器：" + "；".join(skipped),
                observations=(
                    "没有可用适配器执行该动作。"
                    + ("（当前为真实执行模式，仿真靶场被跳过；"
                       "请配置 adapters.soar，或改用 dry-run 演练）"
                       if not self.policy.allow_sim_fallback else "")
                ),
            )
            return self._finalize(res, case, args=args, policy_reason="适配器不可用")

        ctx = ToolContext(case_id=case.case_id, phase=case.phase.value, dry_run=False, case=case)
        try:
            res = adapter.execute(action, ctx)
        except AdapterUnavailable as exc:
            res = ToolResult(ok=False, action=action.name, adapter=adapter.name,
                             status="unavailable", error=str(exc))
        except Exception as exc:  # noqa: BLE001 — 适配器异常必须变成可审计结果，不能冒泡打断处置
            LOG.error("适配器 %s 执行 %s 抛出异常：%s", adapter.name, action.name, mask_text(str(exc)))
            res = ToolResult.failed(action.name, adapter.name, f"{type(exc).__name__}: {exc}")

        if res.ok and isinstance(adapter, SimulatedRangeAdapter) and not self.policy.allow_sim_fallback:
            res.ok = False
            res.status = "unavailable"

        if skipped:
            res.output.setdefault("adapter_skips", skipped)
        self._applied[dedup_key] = res
        return self._finalize(res, case, args=args)

    def execute_batch(
        self,
        raws: Sequence[Any],
        case: CaseState,
        *,
        dry_run: Optional[bool] = None,
        auto_confirm: Optional[bool] = None,
        max_count: int = 5,
    ) -> List[ToolResult]:
        """依次执行一批动作（默认最多 5 个，防止单步轰炸式处置）。"""
        out: List[ToolResult] = []
        for raw in list(raws)[:max_count]:
            out.append(self.execute(raw, case, dry_run=dry_run, auto_confirm=auto_confirm))
        return out

    # ------------------------------------------------------------------ #
    def _pick_adapter(self, action_name: str, *, require_real: bool) -> Tuple[Optional[Adapter], List[str]]:
        return find_adapter(self.adapters, action_name, require_real=require_real)

    @staticmethod
    def _plan_text(action: Action) -> str:
        return (f"调用 {action.name}"
                f" args={mask_text(json.dumps(action.args, ensure_ascii=False, sort_keys=True))} "
                f"（阶段 {primary_phase(action.name).value if primary_phase(action.name) else '?'}，"
                f"风险 {risk_of(action.name)}）")

    def _finalize(
        self,
        result: ToolResult,
        case: CaseState,
        *,
        args: Dict[str, Any],
        proposal_id: str = "",
        policy_reason: str = "",
        record_action: bool = True,
    ) -> ToolResult:
        """写审计 + 回填案例状态。"""
        if record_action:
            case.record(result.action, result.to_dict())

        rec = ExecutionRecord(
            ts=time.time(), case_id=case.case_id, phase=case.phase.value,
            action=result.action, args=mask_obj(args), status=result.status,
            adapter=result.adapter, ok=result.ok,
            # 审计必须反映「动作本身」的不可逆属性：被拒绝的不可逆动作仍然是不可逆动作，
            # 否则事后复核会低估该次尝试的风险等级。
            irreversible=is_irreversible(result.action) or result.status == "pending_confirmation",
            risk=str(result.output.get("risk", risk_of(result.action))),
            dry_run=result.dry_run, simulated=result.simulated,
            error=mask_text(result.error), observations=mask_text(result.observations)[:2000],
            proposal_id=proposal_id, policy_reason=policy_reason,
        )
        self.records.append(rec)
        self._audit(rec)
        return result

    def _audit(self, rec: ExecutionRecord) -> None:
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_path.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(rec.to_dict(), ensure_ascii=False) + "\n")

    # ------------------------------------------------------------------ #
    def stats(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"total": len(self.records)}
        for r in self.records:
            out[r.status] = out.get(r.status, 0) + 1
        return out

    def describe(self) -> Dict[str, Any]:
        return {
            "policy": self.policy.to_dict(),
            "adapters": [a.describe() for a in self.adapters],
            "audit_path": str(self.audit_path),
            "pending_dir": str(self.pending_dir),
            "tools": len(build_tool_specs()),
        }
