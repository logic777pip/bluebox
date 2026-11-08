#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""actions/selftest.py — 动作层自检（不依赖 pytest，可直接跑）。

覆盖的不是"代码能跑"，而是**安全语义是否真的成立**：

  * 白名单/阶段/风险元数据是否完整（新增动作忘了标注阶段 → 立刻失败）
  * 仿真靶场是否对每个动作都有实现（防止"能力清单虚标"）
  * R3：未知动作、未知字段、非法参数是否被拒
  * PDCERF 前置：E 阶段动作在没有 C 的时候是否被拒
  * 保护对象：不可逆动作打到域控/跳板机/备份机是否被拒
  * R5：不可逆动作是否必须两阶段确认、是否拒绝重放
  * 幂等去重、阶段自动推进、案例状态持久化
  * 工具协议解析（文本 ```action 块 / <tool_call> / OpenAI tool_calls）
  * 沙箱逃逸与哈希不匹配是否被拒

用法：python -m actions.cli selftest
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security.action_schema import ACTION_SPECS, Action, SchemaError, validate_action  # noqa: E402

from .adapters import FilesystemAdapter, SimulatedRangeAdapter, ToolContext  # noqa: E402
from .executor import ActionExecutor, ExecutorPolicy  # noqa: E402
from .pdcerf import CaseState, Phase, check_registry_coverage  # noqa: E402
from .registry import validate_registry  # noqa: E402
from .toolkit import parse_tool_calls  # noqa: E402

__all__ = ["Check", "run_selftest"]


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""
    skipped: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class _Ctx:
    """自检上下文：持有临时沙箱与执行器。"""

    def __init__(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pdcerf-selftest-"))
        self.sandbox = self.tmp / "toolbox"
        self.sandbox.mkdir(parents=True, exist_ok=True)
        self.sim = SimulatedRangeAdapter(seed=1)
        self._n = 0

    def executor(self, **kw: Any) -> ActionExecutor:
        self._n += 1
        pending_dir = self.tmp / f"pending-{self._n}"
        policy = ExecutorPolicy(
            dry_run=kw.pop("dry_run", True),
            allow_auto_confirm=kw.pop("allow_auto_confirm", False),
            enforce_prerequisites=kw.pop("enforce_prerequisites", True),
            strict_phase=kw.pop("strict_phase", False),
            allow_sim_fallback=kw.pop("allow_sim_fallback", True),
            protected_hosts=kw.pop("protected_hosts", ["dc-01", "jump-01", "backup-01"]),
            protected_accounts=kw.pop("protected_accounts", ["svc-backup", "admin-ops"]),
            protected_domains=kw.pop("protected_domains", ["corp.example.com"]),
            protected_ips=kw.pop("protected_ips", ["203.0.113.5"]),
        )
        adapters = kw.pop("adapters", None)
        if adapters is None:
            adapters = [FilesystemAdapter(root=self.sandbox), SimulatedRangeAdapter(seed=1)]
        return ActionExecutor(
            adapters=adapters, policy=policy,
            pending_dir=pending_dir, audit_path=self.tmp / "audit.jsonl",
            project_root=self.tmp,
        )

    def cleanup(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)


def _q(host: str = "fin-ws-07", query: str = "rundll32") -> Dict[str, Any]:
    return {"action": "query_logs", "args": {"host_id": host, "query": query}}


def run_selftest(verbose: bool = False) -> Dict[str, Any]:
    ctx = _Ctx()
    checks: List[Check] = []

    def add(name: str, fn: Callable[[], str]) -> None:
        try:
            detail = fn()
            checks.append(Check(name=name, ok=True, detail=detail or ""))
        except AssertionError as exc:
            checks.append(Check(name=name, ok=False, detail=str(exc)))
        except Exception as exc:  # noqa: BLE001 — 自检里任何异常都算失败
            checks.append(Check(name=name, ok=False, detail=f"{type(exc).__name__}: {exc}"))

    try:
        # ---------------- 元数据一致性 ---------------- #
        def c_coverage() -> str:
            problems = check_registry_coverage()
            assert not problems, "；".join(problems)
            return f"{len(ACTION_SPECS)} 个动作的 PDCERF 元数据齐全"
        add("registry: PDCERF 元数据完整（阶段/风险）", c_coverage)

        def c_schema() -> str:
            problems = validate_registry()
            assert not problems, "；".join(problems)
            return f"{len(ACTION_SPECS)} 个动作的 JSON Schema 参数定义齐全"
        add("registry: 工具 JSON Schema 与白名单一致", c_schema)

        def c_sim_caps() -> str:
            sim = SimulatedRangeAdapter()
            missing = sorted(set(ACTION_SPECS) - sim.capabilities())
            extra = sorted(sim.capabilities() - set(ACTION_SPECS))
            assert not missing, f"仿真靶场未声明支持：{missing}"
            assert not extra, f"仿真靶场声明了白名单外的动作：{extra}"
            return f"仿真靶场覆盖全部 {len(ACTION_SPECS)} 个动作"
        add("sim: 仿真靶场覆盖全部白名单动作", c_sim_caps)

        def c_sim_handlers() -> str:
            sim = SimulatedRangeAdapter()
            bad = [n for n in sim.capabilities() if not hasattr(sim, f"_do_{n}")]
            assert not bad, f"声明支持但未实现 handler：{bad}"
            return "全部动作都有 _do_* 实现（无虚标能力）"
        add("sim: 每个动作都有实际实现（非虚标）", c_sim_handlers)

        def c_phases() -> str:
            from .pdcerf import ACTION_PHASES
            for name, ps in ACTION_PHASES.items():
                assert ps, f"{name} 阶段列表为空"
                for p in ps:
                    assert isinstance(p, Phase), f"{name} 含非 Phase 值"
            return f"{len(ACTION_PHASES)} 个动作的阶段归属合法"
        add("pdcerf: 阶段归属类型合法", c_phases)

        # ---------------- R3 schema ---------------- #
        def c_unknown_action() -> str:
            try:
                validate_action({"action": "rm_rf_slash", "args": {}})
            except SchemaError as exc:
                return f"未知动作被拒：{exc}"
            raise AssertionError("未知动作竟然通过了 schema 校验（默认拒绝失效）")
        add("R3: 未知动作被拒绝（默认拒绝）", c_unknown_action)

        def c_unknown_field() -> str:
            try:
                validate_action({"action": "isolate_host", "args": {"host_id": "fin-ws-07", "sudo": True}})
            except SchemaError as exc:
                return f"未知字段被拒：{exc}"
            raise AssertionError("未知字段竟然通过（参数注入风险）")
        add("R3: 未知字段被拒绝", c_unknown_field)

        def c_bad_args() -> str:
            cases = [
                ({"action": "block_ip", "args": {"src_ip": "203.0.113.9", "direction": "sideways"}}, "direction 枚举"),
                ({"action": "delete_file", "args": {"host_id": "h", "path": "../../etc/shadow"}}, "路径穿越"),
                ({"action": "patch_vulnerability", "args": {"host_id": "h", "cve": "CVE-2026"}}, "CVE 格式"),
                ({"action": "remove_persistence", "args": {"host_id": "h", "mechanism": "sword"}}, "mechanism 枚举"),
                ({"action": "isolate_host", "args": {"host_id": "<HOST_A>"}}, "ID 正则"),
            ]
            rejected = []
            for raw, label in cases:
                try:
                    validate_action(raw)
                except SchemaError:
                    rejected.append(label)
            assert len(rejected) == len(cases), f"这些非法参数未被拒：{set(l for _, l in cases) - set(rejected)}"
            return f"{len(cases)} 类非法参数全部被拒（{', '.join(rejected)}）"
        add("R3: 非法参数（枚举/路径穿越/CVE/ID）被拒", c_bad_args)

        def c_new_actions_valid() -> str:
            samples = [
                {"action": "asset_lookup", "args": {"asset": "fin-ws-07"}},
                {"action": "snapshot_host", "args": {"host_id": "fin-ws-07", "label": "pre-eradication"}},
                {"action": "enrich_ioc", "args": {"indicator": "203.0.113.9"}},
                {"action": "capture_pcap", "args": {"host_id": "web-01", "duration_seconds": 60}},
                {"action": "block_domain", "args": {"domain": "cf-update-svc.example", "ttl_seconds": 3600}},
                {"action": "revoke_session", "args": {"account": "zhang.wei"}},
                {"action": "remove_persistence", "args": {"host_id": "fin-ws-07", "mechanism": "scheduled_task"}},
                {"action": "patch_vulnerability", "args": {"host_id": "web-01", "cve": "cve-2026-12345"}},
                {"action": "verify_integrity", "args": {"host_id": "web-01"}},
                {"action": "update_detection_rule", "args": {"rule_id": "rule-ou-001", "rule": "title: x\nlevel: high"}},
                {"action": "publish_ioc", "args": {"indicator": "cf-update-svc.example"}},
                {"action": "archive_evidence", "args": {"case_id": "INC-1", "artifacts": ["mem.raw"]}},
            ]
            for raw in samples:
                validate_action(raw)
            return f"{len(samples)} 个新增动作的样例参数均通过校验"
        add("新增 PDCERF 动作：样例参数合法", c_new_actions_valid)

        # ---------------- 执行器策略 ---------------- #
        def c_deny_bad_action() -> str:
            ex = ctx.executor()
            res = ex.execute({"action": "exfiltrate", "args": {}}, CaseState(case_id="C-deny"))
            assert res.status == "denied", f"期望 denied，实际 {res.status}"
            return "未知动作在执行器入口被拒（R3 闸门生效）"
        add("executor: 未知动作在入口被拒", c_deny_bad_action)

        def c_dry_run_default() -> str:
            ex = ctx.executor()
            case = CaseState(case_id="C-dry")
            res = ex.execute(_q(), case)
            assert res.status == "dry_run" and res.dry_run, f"期望 dry_run，实际 {res.status}"
            return "默认只演练，不产生副作用"
        add("executor: 默认 dry-run（无副作用）", c_dry_run_default)

        def c_real_ok() -> str:
            ex = ctx.executor(dry_run=False)
            case = CaseState(case_id="C-real")
            res = ex.execute(_q(query="7z.lock7z"), case)
            assert res.status == "ok", f"期望 ok，实际 {res.status} / {res.error}"
            assert "EDR" in res.observations or "FILE" in res.observations, "观测内容异常"
            assert case.actions_ok == ["query_logs"], f"案例未记录成功动作：{case.actions_ok}"
            return "真实（仿真靶场）执行成功，并回填案例状态"
        add("executor: 真实执行 + 观测回执", c_real_ok)

        def c_unknown_host() -> str:
            ex = ctx.executor(dry_run=False)
            case = CaseState(case_id="C-ghost")
            res = ex.execute(_q(host="ghost-host-99"), case)
            assert res.status == "failed", f"未知主机应失败，实际 {res.status}"
            assert "不存在" in res.error, f"错误信息不明确：{res.error}"
            return "未知资产如实失败（不编造观测）"
        add("executor: 未知资产如实失败", c_unknown_host)

        def c_protected_host() -> str:
            ex = ctx.executor(dry_run=False, allow_auto_confirm=True)
            case = CaseState(case_id="C-prot")
            ex.execute(_q(), case)                       # 先满足 D 前置
            res = ex.execute({"action": "isolate_host", "args": {"host_id": "dc-01"}}, case)
            assert res.status == "denied", f"保护对象应被拒，实际 {res.status}"
            assert "保护" in res.error, f"拒绝原因不明确：{res.error}"
            return "不可逆动作打到保护主机（dc-01）被拒"
        add("policy: 保护对象拦截（域控不可隔离）", c_protected_host)

        def c_protected_ip() -> str:
            ex = ctx.executor(dry_run=False, allow_auto_confirm=True)
            case = CaseState(case_id="C-prot-ip")
            res = ex.execute({"action": "block_ip", "args": {"src_ip": "203.0.113.5"}}, case)
            assert res.status == "denied", f"保护 IP 应被拒，实际 {res.status}"
            return "保护网段/地址拦截（不会封掉自己的域控）"
        add("policy: 保护 IP 拦截", c_protected_ip)

        def c_prereq_e_before_c() -> str:
            ex = ctx.executor(dry_run=False, allow_auto_confirm=True)
            case = CaseState(case_id="C-prereq")
            res = ex.execute({"action": "reset_credential", "args": {"account": "zhang.wei"}}, case)
            assert res.status == "denied", f"E 阶段动作在无 C 时应被拒，实际 {res.status}"
            assert "前置" in res.error or "遏制" in res.error, f"拒绝原因应说明前置缺失：{res.error}"
            return "PDCERF 前置生效：未遏制先根除被拒"
        add("pdcerf: E 之前必须先 C", c_prereq_e_before_c)

        def c_prereq_c_after_d() -> str:
            ex = ctx.executor(dry_run=False, allow_auto_confirm=True)
            case = CaseState(case_id="C-order")
            res1 = ex.execute({"action": "isolate_host", "args": {"host_id": "fin-ws-07"}}, case)
            assert res1.status == "denied", f"未检测先隔离应被拒，实际 {res1.status}"
            ex.execute(_q(), case)
            res2 = ex.execute({"action": "isolate_host", "args": {"host_id": "fin-ws-07"}}, case)
            assert res2.status == "ok", f"完成 D 后隔离应放行，实际 {res2.status} / {res2.error}"
            assert case.phase == Phase.CONTAINMENT, f"阶段应自动推进到 C，实际 {case.phase}"
            return "PDCERF 前置 + 阶段自动推进（D → C）正确"
        add("pdcerf: C 之前必须先 D，且阶段自动推进", c_prereq_c_after_d)

        def c_readonly_always_allowed() -> str:
            ex = ctx.executor(dry_run=False, allow_auto_confirm=True)
            case = CaseState(case_id="C-read", phase=Phase.RECOVERY)
            res = ex.execute(_q(), case)
            assert res.status == "ok", f"只读动作在任何阶段都应放行，实际 {res.status}"
            return "只读动作不受阶段前置限制（补充检测永远允许）"
        add("pdcerf: 只读动作不受前置限制", c_readonly_always_allowed)

        # ---------------- R5 两阶段确认 ---------------- #
        def c_two_phase_required() -> str:
            ex = ctx.executor(dry_run=False, allow_auto_confirm=False)
            case = CaseState(case_id="C-2p")
            ex.execute(_q(), case)
            res = ex.execute({"action": "isolate_host", "args": {"host_id": "fin-ws-07"}}, case)
            assert res.status == "pending_confirmation", f"未确认应挂起，实际 {res.status}"
            pid = res.output.get("proposal_id", "")
            assert len(pid) == 16, f"proposal_id 异常：{pid!r}"
            assert not case.actions_ok or "isolate_host" not in case.actions_ok, "未确认的动作不应计入已执行"
            return f"不可逆动作挂起待确认（proposal_id={pid}），未产生副作用"
        add("R5: 不可逆动作必须两阶段确认", c_two_phase_required)

        def c_two_phase_no_duplicate_proposal() -> str:
            ex = ctx.executor(dry_run=False, allow_auto_confirm=False)
            case = CaseState(case_id="C-2p-dup")
            ex.execute(_q(), case)
            raw = {"action": "isolate_host", "args": {"host_id": "fin-ws-07"}}
            r1 = ex.execute(raw, case)
            r2 = ex.execute(raw, case)
            assert r1.status == r2.status == "pending_confirmation", f"{r1.status}/{r2.status}"
            assert r1.output["proposal_id"] == r2.output["proposal_id"], \
                "重复提交竟然产生了新的提案（会刷爆待确认目录）"
            pend = list(ex.pending_dir.glob("*.json"))
            assert len(pend) == 1, f"待确认目录应有 1 个提案，实际 {len(pend)}"
            return f"重复提交复用同一提案（proposal_id={r1.output['proposal_id']}）"
        add("R5: 重复提交不可逆动作不重复登记提案", c_two_phase_no_duplicate_proposal)

        def c_two_phase_confirm() -> str:
            ex = ctx.executor(dry_run=False, allow_auto_confirm=False)
            case = CaseState(case_id="C-2p-ok")
            ex.execute(_q(), case)
            raw = {"action": "isolate_host", "args": {"host_id": "fin-ws-07"}}
            res = ex.execute(raw, case)
            pid = res.output["proposal_id"]
            act = validate_action(raw)
            sig = ex.guard.expected_signature(pid, act)
            res2 = ex.execute(raw, case, confirmation=(pid, sig))
            assert res2.status == "ok", f"确认后应执行成功，实际 {res2.status} / {res2.error}"
            assert "隔离" in res2.observations
            return "携带正确 HMAC 签名后执行成功"
        add("R5: 确认通过后正常执行", c_two_phase_confirm)

        def c_two_phase_replay() -> str:
            ex = ctx.executor(dry_run=False, allow_auto_confirm=False)
            case = CaseState(case_id="C-2p-replay")
            ex.execute(_q(), case)
            raw = {"action": "isolate_host", "args": {"host_id": "fin-ws-08"}}
            res = ex.execute(raw, case)
            pid = res.output["proposal_id"]
            sig = ex.guard.expected_signature(pid, validate_action(raw))
            ex.execute(raw, case, confirmation=(pid, sig))
            res3 = ex.execute(raw, case, confirmation=(pid, sig))
            assert res3.status == "denied", f"重放应被拒，实际 {res3.status}"
            assert "重放" in res3.error or "使用" in res3.error, f"拒绝原因：{res3.error}"
            return "同一确认签名重放被拒"
        add("R5: 确认签名重放被拒", c_two_phase_replay)

        def c_two_phase_tamper() -> str:
            ex = ctx.executor(dry_run=False, allow_auto_confirm=False)
            case = CaseState(case_id="C-2p-tamper")
            ex.execute(_q(), case)
            raw = {"action": "isolate_host", "args": {"host_id": "fin-ws-07"}}
            res = ex.execute(raw, case)
            pid = res.output["proposal_id"]
            sig = ex.guard.expected_signature(pid, validate_action(raw))
            tampered = {"action": "isolate_host", "args": {"host_id": "web-01"}}   # 换了目标
            res2 = ex.execute(tampered, case, confirmation=(pid, sig))
            assert res2.status == "denied", f"篡改动作应被拒，实际 {res2.status}"
            return "确认后被篡改的动作被拒（指纹绑定生效）"
        add("R5: 确认前后的动作篡改被拒", c_two_phase_tamper)

        # ---------------- 幂等与状态 ---------------- #
        def c_dedup() -> str:
            ex = ctx.executor(dry_run=False)
            case = CaseState(case_id="C-dedup")
            r1 = ex.execute(_q(), case)
            r2 = ex.execute(_q(), case)
            assert r1.status == "ok" and r2.status == "duplicate", f"{r1.status} / {r2.status}"
            return "同一案例内重复动作被去重（不重复产生副作用）"
        add("executor: 幂等去重", c_dedup)

        def c_audit_written() -> str:
            ex = ctx.executor(dry_run=False)
            case = CaseState(case_id="C-audit")
            ex.execute(_q(), case)
            assert ex.audit_path.exists(), "审计文件未生成"
            rec = json.loads(ex.audit_path.read_text(encoding="utf-8").strip().splitlines()[-1])
            assert rec["action"] == "query_logs" and "status" in rec
            return f"审计落盘（{ex.audit_path.name}），字段齐全"
        add("审计: 动作落盘", c_audit_written)

        def c_audit_irreversible_flag() -> str:
            """审计保真：被拒绝的不可逆动作，在审计里仍须标记 irreversible=true。"""
            ex = ctx.executor(dry_run=False, allow_auto_confirm=False)
            case = CaseState(case_id="C-audit-irr")
            res = ex.execute({"action": "isolate_host", "args": {"host_id": "fin-ws-07"}}, case)
            assert res.status == "denied", f"未满足前置应被拒，实际 {res.status}"
            assert ex.records, "审计记录未生成"
            assert ex.records[-1].irreversible is True, \
                "被拒绝的不可逆动作在审计里被记成 irreversible=false（会低估事后复核的风险等级）"
            return "审计保真：被拒的不可逆动作仍标记 irreversible=true"
        add("审计: 不可逆属性保真（含被拒动作）", c_audit_irreversible_flag)

        def c_case_roundtrip() -> str:
            case = CaseState(case_id="C-persist")
            case.facts["note"] = "test"
            case.add_evidence({"kind": "log", "ref": "x"})
            path = case.save(ctx.tmp / "case.json")
            back = CaseState.load(path)
            assert back.case_id == case.case_id and back.facts == case.facts
            assert len(back.evidence) == 1
            return "案例状态可持久化/还原"
        add("case: 状态持久化往返", c_case_roundtrip)

        # ---------------- 工具协议 ---------------- #
        def c_parse_text_block() -> str:
            text = '```action\n{"action": "query_logs", "args": {"host_id": "fin-ws-07", "query": "x"}}\n```'
            calls, rejected = parse_tool_calls(text)
            assert len(calls) == 1 and calls[0]["action"] == "query_logs", f"{calls} / {rejected}"
            return "文本 ```action 协议解析正确"
        add("toolkit: 文本协议解析", c_parse_text_block)

        def c_parse_tool_call_block() -> str:
            text = '<tool_call>{"action": "block_ip", "args": {"src_ip": "203.0.113.9"}}</tool_call>'
            calls, _ = parse_tool_calls(text)
            assert len(calls) == 1 and calls[0]["action"] == "block_ip", f"{calls}"
            return "<tool_call> 协议解析正确"
        add("toolkit: <tool_call> 协议解析", c_parse_tool_call_block)

        def c_parse_openai() -> str:
            text = json.dumps({"tool_calls": [
                {"function": {"name": "query_logs",
                              "arguments": json.dumps({"host_id": "web-01", "query": "java"})}}
            ]})
            calls, _ = parse_tool_calls(text)
            assert len(calls) == 1 and calls[0]["args"]["host_id"] == "web-01", f"{calls}"
            return "OpenAI tool_calls 协议解析正确"
        add("toolkit: OpenAI tool_calls 解析", c_parse_openai)

        def c_parse_rejects_bad() -> str:
            text = '```action\n{"action": "rm_rf", "args": {}}\n```'
            calls, _ = parse_tool_calls(text)
            assert calls == [], f"非法动作不应被解析为调用：{calls}"
            return "非法动作不会被解析（不会绕过执行器）"
        add("toolkit: 非法动作不产生调用", c_parse_rejects_bad)

        # ---------------- 沙箱 ---------------- #
        def c_sandbox_escape() -> str:
            fs = FilesystemAdapter(root=ctx.sandbox)
            res = fs.execute(
                Action(name="quarantine_file", args={"host_id": "h", "path": "../outside.txt"}),
                ToolContext(case_id="C-jail"),
            )
            assert not res.ok, "沙箱逃逸竟然成功"
            return f"越界路径被拒：{res.error}"
        add("sandbox: 路径逃逸被拒", c_sandbox_escape)

        def c_sandbox_hash_mismatch() -> str:
            fs = FilesystemAdapter(root=ctx.sandbox)
            (ctx.sandbox / "sample.bin").write_bytes(b"malware-sample")
            res = fs.execute(
                Action(name="quarantine_file",
                       args={"host_id": "h", "path": "sample.bin", "sha256": "0" * 64}),
                ToolContext(case_id="C-hash"),
            )
            assert not res.ok and "哈希不匹配" in res.error, f"哈希不匹配未拦截：{res.to_dict()}"
            return "隔离前哈希校验生效（防止隔离错文件）"
        add("sandbox: 哈希不匹配被拒", c_sandbox_hash_mismatch)

        def c_sandbox_quarantine_ok() -> str:
            import hashlib
            fs = FilesystemAdapter(root=ctx.sandbox)
            data = b"real-sample"
            (ctx.sandbox / "sample2.bin").write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            res = fs.execute(
                Action(name="quarantine_file",
                       args={"host_id": "h", "path": "sample2.bin", "sha256": digest}),
                ToolContext(case_id="C-q"),
            )
            assert res.ok, f"隔离失败：{res.error}"
            assert (ctx.sandbox / "sample2.bin").exists(), "原件应保留（取证需要样本）"
            return "隔离成功且保留原件"
        add("sandbox: 隔离成功（原件保留）", c_sandbox_quarantine_ok)

        # ---------------- 闭环 ---------------- #
        def c_loop_stub() -> str:
            try:
                from agent.agent import StubBackend  # noqa: PLC0415
            except Exception as exc:  # noqa: BLE001
                raise AssertionError(f"StubBackend 不可用：{exc}") from exc
            from .loop import ToolLoop  # noqa: PLC0415
            ex = ctx.executor(dry_run=True)
            loop = ToolLoop(StubBackend(), ex, retriever=None, intel_enabled=False,
                            max_steps=3, only_trained_tools=True, grounding=False)
            result = loop.run("EDR 告警：fin-ws-07 每 5 分钟外连 203.0.113.9:443")
            assert result.steps, "闭环未产生任何步骤"
            assert result.stopped_reason, "闭环未给出停止原因"
            return (f"闭环跑通：{len(result.steps)} 步，停止原因={result.stopped_reason}，"
                    f"工具调用={sum(len(s['results']) for s in result.steps)} 次")
        add("loop: 工具调用闭环可运行（stub 后端）", c_loop_stub)

        def c_loop_blocks_pending() -> str:
            """闭环遇到待确认不可逆动作应立即停轮，不刷屏。"""
            from .loop import ToolLoop  # noqa: PLC0415

            class _OneShotBackend:
                name = "oneshot"
                def __init__(self) -> None:
                    self.n = 0
                def generate(self, system: str, user: str, max_new_tokens: int = 512) -> str:
                    self.n += 1
                    if self.n == 1:
                        return '```action\n{"action": "query_logs", "args": {"host_id": "fin-ws-07", "query": "rundll32"}}\n```'
                    if self.n == 2:
                        return '```action\n{"action": "isolate_host", "args": {"host_id": "fin-ws-07"}}\n```'
                    return "最终研判：已隔离并等待确认。"

            ex = ctx.executor(dry_run=False, allow_auto_confirm=False)
            loop = ToolLoop(_OneShotBackend(), ex, retriever=None, intel_enabled=False,
                            max_steps=6, grounding=False)
            result = loop.run("EDR 告警：fin-ws-07 疑似 beacon")
            assert result.stopped_reason == "awaiting_confirmation", \
                f"应在待确认时停轮，实际 {result.stopped_reason}"
            assert len(result.steps) == 2, f"不应继续刷轮：{len(result.steps)}"
            return "待确认的不可逆动作触发停轮（避免重复提交）"
        add("loop: 待确认动作立即停轮", c_loop_blocks_pending)

        def c_loop_no_progress_stops() -> str:
            """模型反复提同一动作（全是 duplicate）→ 应判为无进展并提前终止，而不是烧完 max_steps。"""
            from .loop import ToolLoop  # noqa: PLC0415

            class _StuckBackend:
                name = "stuck"
                def __init__(self) -> None:
                    self.n = 0
                def generate(self, system: str, user: str, max_new_tokens: int = 512) -> str:
                    # 永远提同一个动作，永不收敛
                    return '```action\n{"action": "query_logs", "args": {"host_id": "fin-ws-07", "query": "x"}}\n```'

            ex = ctx.executor(dry_run=False)
            loop = ToolLoop(_StuckBackend(), ex, retriever=None, intel_enabled=False,
                            max_steps=8, grounding=False)
            result = loop.run("EDR 告警：fin-ws-07 疑似 beacon")
            assert result.stopped_reason.startswith("no_progress"), \
                f"应判为无进展终止，实际 {result.stopped_reason}"
            assert len(result.steps) == 2, f"应在第 2 步即停，实际 {len(result.steps)} 步"
            assert result.final_answer, "提前终止后仍应收敛出最终研判"
            return "重复无进展的调用触发提前终止（不烧穿 max_steps）"
        add("loop: 无进展提前终止", c_loop_no_progress_stops)

        # ---------------- 汇总 ---------------- #
        def c_coverage_matrix() -> str:
            from .pdcerf import PHASE_META, PHASE_ORDER, phases_of
            per_phase = {p.value: 0 for p in PHASE_ORDER}
            for name in ACTION_SPECS:
                for p in phases_of(name):
                    per_phase[p.value] += 1
            empty = [k for k, v in per_phase.items() if v == 0]
            assert not empty, f"以下阶段没有任何可用动作（PDCERF 不完整）：{empty}"
            return "各阶段可用动作数：" + ", ".join(
                f"{k}({PHASE_META[Phase(k)]['zh']})={v}" for k, v in per_phase.items())
        add("pdcerf: 六阶段均有动作覆盖", c_coverage_matrix)

    finally:
        ctx.cleanup()

    passed = sum(1 for c in checks if c.ok and not c.skipped)
    failed = sum(1 for c in checks if not c.ok)
    skipped = sum(1 for c in checks if c.skipped)
    return {
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "total": len(checks),
        "checks": [c.to_dict() for c in checks],
    }


def _main(argv: Optional[List[str]] = None) -> int:
    result = run_selftest()
    for c in result["checks"]:
        mark = "PASS" if c["ok"] else "FAIL"
        print(f"[{mark}] {c['name']}")
        if c["detail"]:
            print(f"       {c['detail']}")
    print(f"\n通过 {result['passed']} / 失败 {result['failed']} / 共 {result['total']}")
    return 0 if result["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(_main())
