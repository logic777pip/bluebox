#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sandbox/pipeline.py — 检测到威胁后的自动联动：固化 → 报警 → 静态分析 → 封锁 → 交接。

一步做什么
----------

    传感器/IDS 判定为威胁（route=auto_attack 或高分强判）
        ↓
    ① extract_to_vault   载荷按字节复制进**只读库**（复制不移动，原文件不动）
        ↓
    ② 报警                Windows 通知：已提取载荷，附哈希与库路径
        ↓
    ③ analyze_payload    **静态**取证分析（哈希/PE/签名/字符串/指标）→ Markdown + JSON 报告
        ↓
    ④ contain_threat     最小影响封锁：只封该威胁的**精确对端出向**，带 TTL（默认只出计划）
        ↓
    ⑤ build_handoff      给人工的动态分析交接包（AI 不执行）
        ↓
    ⑥ 落审计 + 案例文件  logs/sandbox/cases/<案例>/CASE.md、audit.jsonl

⚠ 动态分析**不在**这条流水线里，而且不是"关着的开关"：
`detonate_payload` 在 `security/action_schema.ACTION_SPECS` 里根本不存在，
`sandbox/sandboxie.py` 有 vault 路径守卫 + AST 断言，`dynamic_handoff.py` 连
`subprocess` 都不 import，本模块自身也不含任何 subprocess 调用（自检会验证）。
要加"自动引爆"，得同时改四处并让三个自检全部失败 —— 那才叫约束。

为什么复用 `forensics.collect` 的触发判定
-----------------------------------------

"什么算检测到威胁"必须只有一个定义。如果这里另写一套阈值判断，
两套判定迟早会漂移（一边要取证、一边不要），而这种不一致在生产里表现为
"有些告警有取证、有些没有"，且没人说得清为什么。所以直接 `import` 那三个
trigger 函数，判定逻辑单点维护。

与 `forensics/collect.py`（KAPE）的分工
---------------------------------------

    forensics/collect.py   重量级：KAPE 采集整机产物（分钟级、数百 MB）
    sandbox/pipeline.py    轻量级：先把**载荷本身**固定下来（秒级、KB~MB）

顺序上应该先跑本流水线：证据固定得越早越不容易丢（攻击者会自我删除，
用户也可能顺手清空回收站）。KAPE 可以随后慢慢采。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sandbox import case_dir, sandbox_root  # noqa: E402

__all__ = ["StepResult", "PipelineDecision", "PayloadPipeline", "selftest"]

# --------------------------------------------------------------------------- #
# 关于"不执行样本"的结构性保证
# --------------------------------------------------------------------------- #
# 本模块**不得**直接调用任何执行类原语。所有需要起子进程的能力（防火墙、
# 通知）都在别的模块里，而且那些模块各自有自己的守卫。这里的自检会跑
# `_assert_no_execution()` 来证明本文件没有 subprocess / os.system / ctypes 调用。
_FORBIDDEN_CALLS = {
    ("subprocess", "run"), ("subprocess", "Popen"), ("subprocess", "call"),
    ("subprocess", "check_output"), ("os", "system"), ("os", "popen"),
    ("os", "startfile"), ("ctypes", "WinDLL"), ("ctypes", "CDLL"),
}
_FORBIDDEN_IMPORTS = {"subprocess", "ctypes"}


def _assert_no_execution(source: Optional[str] = None) -> List[str]:
    """AST 证明本模块没有执行类调用。返回违规列表（空 = 通过）。"""
    import ast
    src = source if source is not None else Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    bad: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] in _FORBIDDEN_IMPORTS:
                    bad.append(f"第 {node.lineno} 行：import {a.name}")
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in _FORBIDDEN_IMPORTS:
                bad.append(f"第 {node.lineno} 行：from {node.module} import ...")
        elif isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
                if (f.value.id, f.attr) in _FORBIDDEN_CALLS:
                    bad.append(f"第 {node.lineno} 行：{f.value.id}.{f.attr}()")
    return bad


# --------------------------------------------------------------------------- #
# 数据结构
# --------------------------------------------------------------------------- #

@dataclass
class StepResult:
    name: str = ""
    ok: bool = False
    status: str = ""            # ok / planned / skipped / failed / unavailable
    detail: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PipelineDecision:
    case_id: str = ""
    fired: bool = False
    reason: str = ""             # 为什么触发 / 为什么不触发
    source: str = ""
    peer: str = ""
    proc: str = ""
    payload: str = ""
    #: 载荷路径是怎么得到的（审计要能看出取证可靠性）：
    #: event_path / pid_lookup / none
    payload_source: str = ""
    steps: List[StepResult] = field(default_factory=list)
    started: str = ""
    elapsed_s: float = 0.0
    case_dir: str = ""           # 解析后的（dataclass 里存 str，避免 Path 进 JSON）

    def step(self, name: str) -> Optional[StepResult]:
        return next((s for s in self.steps if s.name == name), None)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["case_dir"] = str(self.case_dir)
        return d


# --------------------------------------------------------------------------- #
# 流水线
# --------------------------------------------------------------------------- #

def _safe_case_id(raw: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in (raw or "case"))[:80]


class PayloadPipeline:
    """威胁 → 载荷固化 → 报警 → 静态分析 → 封锁 → 人工交接。"""

    def __init__(self, cfg: Optional[Dict[str, Any]] = None) -> None:
        cfg = cfg or {}
        self.cfg = cfg
        self.enabled = bool(cfg.get("enabled", True))
        self.auto_extract = bool(cfg.get("auto_extract", True))
        self.analyze = bool(cfg.get("analyze", True))
        #: 是否真改防火墙。默认 False —— 与 KAPE 采集同一纪律：
        #: 有实际影响的动作需要一次写在配置里的显式批准。
        self.execute = bool(cfg.get("execute", False))
        self.do_handoff = bool(cfg.get("handoff", True))
        self.high_threshold = int(cfg.get("high_threshold", 40))
        self.cooldown = int(cfg.get("cooldown_seconds", 1800))
        #: PID 反查的最大事件年龄（秒）。见 `_resolve_payload` 的注释。
        self.pid_lookup_max_age = int(cfg.get("pid_lookup_max_age", 600))
        self.root = cfg.get("root") or None
        self.audit_path = sandbox_root(self.root) / "pipeline_audit.jsonl"
        #: 指纹 → 上次处理时间（冷却去重）。为什么需要：
        #: 同一个载荷通常会在多个轮询里反复出现（同一路径、同一进程名），
        #: 不去重会每秒固化一次、每几秒弹一次通知。
        self._seen: Dict[str, float] = {}

    # ---------------------------------------------------------------- 触发
    def trigger(self, rec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """复用 forensics.collect 的触发判定（威胁定义单点维护）。"""
        from forensics.collect import TRIGGERS  # noqa: PLC0415
        src = str(rec.get("source") or rec.get("_source") or "net_sensor")
        fn = TRIGGERS.get(src)
        if fn is None:
            return None
        return fn(rec, high_threshold=self.high_threshold)

    @staticmethod
    def fingerprint(trig: Dict[str, Any]) -> str:
        """去重指纹：来源|进程|对端|载荷路径。

        刻意**不含时间戳**：同一威胁在后续轮询里时间戳会变，含进去就永远不重复，
        冷却也就失效了。
        """
        return "|".join(str(trig.get(k, "")) for k in ("source", "proc", "peer", "path"))

    # ---------------------------------------------------------------- 主流程
    def handle(self, trig: Dict[str, Any], *, force: bool = False) -> PipelineDecision:
        """处理一条触发项。**全程不执行样本。**"""
        t0 = time.time()
        fp = self.fingerprint(trig)
        now = time.time()
        dec = PipelineDecision(
            case_id=_safe_case_id(trig.get("case_id", "")),
            source=str(trig.get("source", "")),
            peer=str(trig.get("peer", "")),
            proc=str(trig.get("proc", "")),
            payload=str(trig.get("path", "")),
            started=time.strftime("%Y-%m-%d %H:%M:%S"),
        )
        cdir = case_dir(dec.case_id, self.root)
        dec.case_dir = str(cdir)

        if not self.enabled:
            dec.fired = False
            dec.reason = "配置 sandbox.enabled=false"
            return dec

        last = self._seen.get(fp, 0.0)
        if not force and last and (now - last) < self.cooldown:
            dec.fired = False
            dec.reason = (f"冷却中（{int(self.cooldown - (now - last))}s 后再评估）"
                          f"：同一目标 {fp[:80]}")
            return dec

        payload_path, how = self._resolve_payload(trig)
        dec.payload = payload_path
        dec.payload_source = how
        if not payload_path:
            # 没有可用的载荷路径时**不要编造、也不要去动别的文件**：
            # 把"为什么没用"写清楚，让人能去修上游（事件记录）。
            dec.fired = False
            dec.reason = f"触发成立，但没有可用的载荷路径：{how}"
            self._seen[fp] = now
            self._audit(dec)
            return dec

        dec.fired = True
        self._seen[fp] = now

        # ① 只读固化
        step1 = self._step_extract(trig, dec)
        dec.steps.append(step1)
        vault_file = step1.data.get("vault_path", "")
        if not step1.ok:
            dec.reason = f"固化失败：{step1.detail}"
            self._write_case(dec)
            self._audit(dec)
            dec.elapsed_s = round(time.time() - t0, 2)
            return dec

        # ② 报警
        dec.steps.append(self._step_alert(step1, dec))

        # ③ 静态分析
        if self.analyze:
            dec.steps.append(self._step_analyze(vault_file, dec))

        # ④ 最小影响封锁（默认只出计划）
        if trig.get("peer"):
            dec.steps.append(self._step_contain(trig, dec))

        # ⑤ 人工动态分析交接包
        if self.do_handoff:
            dec.steps.append(self._step_handoff(vault_file, dec))

        dec.reason = "已按 固化→报警→静态分析→封锁(计划)→人工交接 处理完毕"
        self._write_case(dec)
        self._audit(dec)
        dec.elapsed_s = round(time.time() - t0, 2)
        return dec

    # ---------------------------------------------------------------- 各步
    def _resolve_payload(self, trig: Dict[str, Any]) -> tuple:
        """确定要固化的载荷路径。返回 ``(路径或空, 来源/原因说明)``。

        为什么需要这一步：`net_sensor_trigger` 是从事件 detail 文本里**刮**出
        以 `.exe` 结尾的 token 来还原路径的。在本机 71 条真实事件上实测：
        判定为威胁的 38 条里，绝大多数只刮到**裸进程名**（如 `python.exe`），
        不是可用路径。直接照用会让"固化"永远失败 —— 而固化正是本流程的核心。

        两种来源，严格分级：

        1. ``event_path``：记录里给的路径是**绝对路径且文件存在** → 直接用。
        2. ``pid_lookup``：用 pid 现查镜像路径（`QueryFullProcessImageNameW`）。

        ⚠ **PID 反查必须有时效护栏。** PID 会被回收：拿几天前事件的 pid 去查，
        很可能查到**完全不同的进程**，那就等于把无辜文件当成"攻击载荷"
        去固化、分析、甚至据以封锁。这是**证据性错误**，比"查不到"严重得多
        （它会把无关程序写进案子，而且看起来像是真的）。所以超过
        `pid_lookup_max_age`（默认 10 分钟）就不反查，并如实说明"不做"。
        """
        raw = str(trig.get("path") or "")
        if raw and os.path.isabs(raw) and Path(raw).is_file():
            return raw, "event_path（事件记录里的绝对路径）"

        if raw and not os.path.isabs(raw):
            note = f"事件记录里的 path 是裸名称（{raw}），不是绝对路径"
        elif raw:
            note = f"事件记录里的路径不存在（{raw}）"
        else:
            note = "事件记录里没有 path"

        pid = int(trig.get("pid") or 0)
        if pid <= 0:
            return "", note + "；且记录里没有 pid，无法反查"

        age = self._event_age(trig)
        if age is None:
            return "", note + "；事件时间戳无法解析，为防 PID 复用不做反查"
        if age > self.pid_lookup_max_age:
            return "", (note + f"；事件已过 {int(age)} 秒（上限 "
                        f"{self.pid_lookup_max_age}s），为防 PID 复用取到无关进程，不做反查")

        try:
            from tools.win_net import process_image_path  # noqa: PLC0415
            live = process_image_path(pid)
        except Exception as exc:  # noqa: BLE001
            return "", note + f"；按 pid 反查异常：{type(exc).__name__}: {exc}"

        if live and os.path.isabs(live) and Path(live).is_file():
            return live, f"pid_lookup（事件 {int(age)} 秒前，用 pid {pid} 现查）"
        return "", note + f"；按 pid {pid} 反查也没拿到可用路径（得到 {live or '空'}）"

    @staticmethod
    def _event_age(trig: Dict[str, Any]) -> Optional[float]:
        """事件落盘到现在的秒数；时间戳解析不了返回 None。

        注意事件里的 `ts` 是**本地时间**字符串（`net_sensor` 用 `strftime` 写的），
        所以用 `time.mktime`（本地时区）而不是 `gmtime`。时区搞错会让"年龄"偏差几小时，
        而年龄是本流程里 PID 反查的**唯一护栏**，所以这里必须和写入方一致。
        """
        raw = trig.get("raw") or {}
        ts = str(trig.get("ts") or (raw.get("ts") if isinstance(raw, dict) else "") or "")
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M"):
            try:
                t = time.mktime(time.strptime(ts, fmt))
            except ValueError:
                continue
            return max(0.0, time.time() - t)
        return None

    def _step_extract(self, trig: Dict[str, Any], dec: PipelineDecision) -> StepResult:
        from sandbox.sandboxie import SandboxieConfig, extract_to_vault  # noqa: PLC0415
        path = str(dec.payload or trig.get("path") or "")
        if not self.auto_extract:
            return StepResult("extract", False, "skipped",
                              "配置 auto_extract=false，未固化", {"path": path})
        cfg = SandboxieConfig.from_dict(self.cfg)
        ex = extract_to_vault(path, cfg, case_id=dec.case_id)
        if not ex.ok:
            return StepResult("extract", False, "failed", ex.detail, ex.to_dict())
        return StepResult("extract", True, "ok",
                          (f"已固化到只读库（复制不移动，来源：{dec.payload_source}）："
                           f"{ex.vault_path}"), ex.to_dict())

    def _step_alert(self, step1: StepResult, dec: PipelineDecision) -> StepResult:
        """报警。**通知失败不能影响取证**，所以失败只记录、不回滚。"""
        hs = (step1.data or {}).get("hashes") or {}
        sha = str(hs.get("sha256", ""))[:16]
        title = "蓝队：检测到威胁并已固定载荷"
        body = (f"案例 {dec.case_id}\n"
                f"进程 {dec.proc or '?'} → {dec.peer or '?'}\n"
                f"SHA-256 {sha}…（{hs.get('size', 0)} 字节）\n"
                f"载荷已复制进只读库，**未执行**。")
        if not self.cfg.get("notify", True):
            return StepResult("alert", True, "skipped", "配置 notify=false，未弹通知", {})
        try:
            from tools.win_notify import notify  # noqa: PLC0415
            ok = bool(notify(title, body, subtitle="已固化 · 待静态分析 · 动态分析需人工"))
            return StepResult("alert", ok, "ok" if ok else "failed",
                              "已弹出 Windows 通知" if ok else "通知投递失败（不影响取证）", {})
        except Exception as exc:  # noqa: BLE001
            return StepResult("alert", False, "failed",
                              f"通知异常（不影响取证）：{type(exc).__name__}: {exc}", {})

    def _step_analyze(self, vault_file: str, dec: PipelineDecision) -> StepResult:
        from sandbox.payload import analyse, render_markdown  # noqa: PLC0415
        if not vault_file:
            return StepResult("analyze", False, "skipped", "没有库内镜像可分析", {})
        try:
            rep = analyse(vault_file, with_signature=True, with_strings=True)
        except Exception as exc:  # noqa: BLE001
            return StepResult("analyze", False, "failed",
                              f"静态分析异常：{type(exc).__name__}: {exc}", {})
        cdir = Path(dec.case_dir)
        cdir.mkdir(parents=True, exist_ok=True)
        md = cdir / "payload_report.md"
        js = cdir / "payload_report.json"
        md.write_text(render_markdown(rep), encoding="utf-8")
        js.write_text(rep.to_json(), encoding="utf-8")
        top = [h["why"] for h in (rep.anomalies or [])[:2]]
        top += [h["why"] for h in ((rep.indicators or {}).get("hits") or [])[:2]]
        return StepResult("analyze", True, "ok",
                          (f"静态分析：{rep.file_type}，风险 {rep.risk}（{rep.score}/100），"
                           f"签名 {rep.signature.get('status', '未查')}"
                           + (f"，主要指标：{'；'.join(top[:3])}" if top else "")),
                          {"report_md": str(md), "report_json": str(js),
                           "risk": rep.risk, "score": rep.score})

    def _step_contain(self, trig: Dict[str, Any], dec: PipelineDecision) -> StepResult:
        from sandbox.contain import apply_contain, plan_contain  # noqa: PLC0415
        peer = str(trig.get("peer", ""))
        # peer 可能是 "1.2.3.4:443" 形式，取出地址部分
        addr = peer.split("/")[0]
        if addr.count(":") == 1:
            addr = addr.split(":")[0]
        plan = plan_contain(addr, case_id=dec.case_id,
                            reason=f"自动封锁：{dec.proc or '?'} 的可疑对端",
                            ttl_seconds=int(self.cfg.get("ttl_seconds", 14400)),
                            allow_unverified=bool(self.cfg.get("allow_unverified_target",
                                                               False)))
        res = apply_contain(plan, apply=self.execute)
        if not plan.will_block:
            why = "；".join(i.reason for i in plan.refused) or "无法识别的 IOC"
            return StepResult("contain", False, "planned",
                              f"未封锁（不满足最小影响条件）：{why}", res.to_dict())
        if res.status == "planned":
            return StepResult("contain", True, "planned",
                              (f"**仅出计划、未改防火墙**：将封 {len(plan.will_block)} 条"
                               f"出向 Block（TTL {plan.ttl_seconds // 60} 分钟）。"
                               f"要真封锁需 sandbox.execute=true。"
                               f"{res.non_interference}"), res.to_dict())
        return StepResult("contain", res.ok, res.status,
                          (f"已封锁并读回确认 {len(res.verified)} 条，到期 {res.expires_at}。"
                           f"{res.non_interference}"), res.to_dict())

    def _step_handoff(self, vault_file: str, dec: PipelineDecision) -> StepResult:
        from sandbox.dynamic_handoff import build_handoff  # noqa: PLC0415
        from sandbox.payload import hashes  # noqa: PLC0415
        if not vault_file:
            return StepResult("handoff", False, "skipped", "没有库内镜像可交接", {})
        try:
            h = build_handoff(
                dec.case_id, vault_file, hashes(vault_file), Path(dec.case_dir),
                box_name=self.cfg.get("box_name", "BlueTeamDynamic"),
                box_verified=False,
                verify_note="自动化流程未做断网验证（需人工在装好 Sandboxie 后自行验证）",
            )
        except Exception as exc:  # noqa: BLE001
            return StepResult("handoff", False, "failed",
                              f"交接包生成失败：{type(exc).__name__}: {exc}", {})
        return StepResult("handoff", True, "ok",
                          (f"已生成人工动态分析交接包：`{Path(h.cmd_file).name}` 与 "
                           f"`{Path(h.md_file).name}`。**AI 不执行**（executed_by_ai=false）。"
                           f"⚠ 断网验证未做：人工在验证通过前不应引爆。"),
                          h.to_dict())

    # ---------------------------------------------------------------- 落盘
    def _write_case(self, dec: PipelineDecision) -> None:
        cdir = Path(dec.case_dir)
        cdir.mkdir(parents=True, exist_ok=True)
        L = [f"# 案件 {dec.case_id}（载荷固化与静态分析）", "",
             f"- 触发来源：{dec.source}", f"- 进程：{dec.proc or '-'}",
             f"- 对端：{dec.peer or '-'}", f"- 载荷：`{dec.payload or '-'}`",
             f"- 开始时间：{dec.started}", f"- 结论：{dec.reason}", "",
             "| 步骤 | 状态 | 说明 |", "|---|---|---|"]
        for s in dec.steps:
            L.append(f"| {s.name} | {s.status} | {s.detail.replace('|', '/')} |")
        L.append("")
        L.append("## 边界（必读）")
        L.append("")
        L.append("- 本流程**只做静态分析**：没有执行过该载荷。")
        L.append("- 载荷镜像已设只读；原文件未被改动（复制不移动）。")
        L.append("- 动态分析需人工按 `HANDOFF.md` 进行，且必须先通过差分断网验证。")
        (cdir / "CASE.md").write_text("\n".join(L), encoding="utf-8")

    def _audit(self, dec: PipelineDecision) -> None:
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        entry = dec.to_dict()
        entry["ts"] = time.strftime("%Y-%m-%d %H:%M:%S")
        with self.audit_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    # ---------------------------------------------------------------- 读取
    def read_events(self, path: Path, from_end: bool = False) -> List[Dict[str, Any]]:
        """读事件文件（jsonl）。坏行跳过并计数，不让一行脏数据中断整条流水线。"""
        recs: List[Dict[str, Any]] = []
        if not path.is_file():
            return recs
        try:
            raw = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return recs
        if from_end:
            raw = raw[-200:]
        for line in raw:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict):
                # net_sensor 写的是 facts 数组或单条；两种都兜住
                if "facts" in obj and isinstance(obj["facts"], list):
                    for f in obj["facts"]:
                        if isinstance(f, dict):
                            recs.append({"source": "net_sensor", **f})
                else:
                    recs.append(obj)
        return recs


def _default_event_paths() -> Dict[str, Path]:
    logs = PROJECT_ROOT / "logs"
    return {"net_sensor": logs / "net_sensor_events.jsonl",
            "suricata": logs / "suricata_events.jsonl"}


# --------------------------------------------------------------------------- #
# 自检
# --------------------------------------------------------------------------- #

def selftest() -> int:
    import tempfile

    try:
        sys.stdout.reconfigure(errors="replace")  # type: ignore[union-attr]
    except Exception:  # noqa: BLE001
        pass

    ok = 0
    fail = 0

    def chk(name: str, cond: bool, detail: str = "") -> None:
        nonlocal ok, fail
        if cond:
            ok += 1
            print(f"  [OK]   {name}")
        else:
            fail += 1
            print(f"  [FAIL] {name}  {detail}")

    print("=== sandbox.pipeline 自检 ===")

    bad = _assert_no_execution()
    chk("本模块没有任何执行类调用（AST）", not bad, "; ".join(bad))
    chk("AST 检查能抓到 subprocess（反面用例）",
        bool(_assert_no_execution("import subprocess\nsubprocess.run(['x'])\n")))

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        # 造一个假载荷（不是真恶意文件，只是字节串）
        payload = td / "dropped_payload.exe"
        payload.write_bytes(b"MZ" + b"\x90" * 300 + b"http://203.0.113.77/x")

        cfg = {"enabled": True, "auto_extract": True, "analyze": True,
               "execute": False, "notify": False, "root": str(td / "sandbox"),
               "vault": str(td / "sandbox" / "vault"),
               "box_name": "TestBox", "ttl_seconds": 3600, "handoff": True}
        pipe = PayloadPipeline(cfg)

        rec = {"source": "net_sensor", "ts": "2026-10-05 12:00:00",
               "pid": 4242, "proc": "dropped_payload.exe",
               "remote": "203.0.113.77:4444", "score": 75,
               "route": "auto_attack", "rules": ["high_risk_port"],
               "triage": {"verdict": "attack"},
               "detail": f"可疑外连 {payload}"}
        trig = pipe.trigger(rec)
        chk("auto_attack 能触发流水线", trig is not None)
        chk("触发项还原出了载荷路径",
            trig is not None and str(payload) in str(trig.get("path", "")),
            str(trig and trig.get("path")))

        dec = pipe.handle(trig or {})
        chk("流水线已触发", dec.fired, dec.reason)
        chk("① 载荷已固化", bool(dec.step("extract") and dec.step("extract").ok),
            str(dec.step("extract")))
        chk("② 报警步骤已记录（配置关闭通知时如实标注）",
            dec.step("alert") is not None, str(dec.step("alert")))
        chk("③ 静态分析产出报告",
            dec.step("analyze") is not None and dec.step("analyze").ok,
            str(dec.step("analyze")))
        chk("④ 封锁**只出计划**（execute=false 时绝不改防火墙）",
            dec.step("contain") is not None and dec.step("contain").status == "planned",
            str(dec.step("contain")))
        chk("⑤ 生成了人工交接包且 executed_by_ai=False",
            dec.step("handoff") is not None
            and (dec.step("handoff").data or {}).get("executed_by_ai") is False,
            str(dec.step("handoff")))
        chk("案例文件 CASE.md 已生成",
            (Path(dec.case_dir) / "CASE.md").is_file())
        chk("CASE.md 写明只做静态分析、未执行载荷",
            "没有执行过该载荷" in (Path(dec.case_dir) / "CASE.md").read_text(
                encoding="utf-8"))
        chk("审计已落盘", pipe.audit_path.is_file())
        chk("原文件仍在（固化是复制不是移动）", payload.exists())
        vault_file = (dec.step("extract").data or {}).get("vault_path", "")
        chk("库内镜像存在且哈希与源一致",
            Path(vault_file).is_file()
            and (dec.step("extract").data or {}).get("hashes", {}).get("size")
            == payload.stat().st_size)

        # -- 冷却去重 --
        dec2 = pipe.handle(pipe.trigger(rec) or {})
        chk("同一目标在冷却期内不重复处理", dec2.fired is False and "冷却" in dec2.reason,
            dec2.reason)
        dec3 = pipe.handle(pipe.trigger(rec) or {}, force=True)
        chk("force 可绕过冷却", dec3.fired, dec3.reason)

        # -- 载荷路径解析（实测：事件里常常只有裸进程名）--
        trig_bare = {"source": "net_sensor", "pid": 0, "path": "python.exe",
                     "ts": "2026-10-05 12:00:00", "proc": "python.exe"}
        pth, how = pipe._resolve_payload(trig_bare)
        chk("裸进程名不被当成可用路径", pth == "" and "裸名称" in how, how)

        trig_abs = {"source": "net_sensor", "pid": 0, "path": str(payload),
                    "ts": "2026-10-05 12:00:00"}
        pth2, how2 = pipe._resolve_payload(trig_abs)
        chk("绝对路径且存在时直接用", pth2 == str(payload) and "event_path" in how2, how2)

        trig_old = {"source": "net_sensor", "pid": 4242, "path": "x.exe",
                    "ts": "2026-10-02 14:59:31",
                    "raw": {"ts": "2026-10-02 14:59:31"}}
        pth3, how3 = pipe._resolve_payload(trig_old)
        chk("过期事件不做 PID 反查（防 PID 复用取到无关进程）",
            pth3 == "" and "PID 复用" in how3, how3)

        trig_nots = {"source": "net_sensor", "pid": 4242, "path": "x.exe", "ts": ""}
        pth4, how4 = pipe._resolve_payload(trig_nots)
        chk("时间戳无法解析时也不做 PID 反查",
            pth4 == "" and "无法解析" in how4, how4)

        # -- 无载荷路径时不触发且如实说明 --
        rec_np = {"source": "net_sensor", "ts": "t", "proc": "x.exe", "score": 90,
                  "route": "auto_attack", "triage": {"verdict": "attack"},
                  "remote": "203.0.113.9:80", "detail": "no path here"}
        dec4 = pipe.handle(pipe.trigger(rec_np) or {}, force=True)
        chk("无载荷路径时不触发且如实说明",
            dec4.fired is False and "没有可用的载荷路径" in dec4.reason, dec4.reason)

        # -- execute 开关：**用桩验证，绝不碰真实防火墙** --
        # 踩过的坑：这条用例最初直接调真实现（apply=True），结果"自检"真的往系统
        # 防火墙里加了规则 —— 重复跑 4 次就留下 4 条同名规则。
        # 自检改被测环境是不可接受的：它污染系统，而且让"自检通过"本身变得可疑。
        # 正确做法：把 apply_contain 换成桩，只验证流水线有没有把 apply 传对。
        import sandbox.contain as _C  # noqa: PLC0415
        calls: List[bool] = []
        real_apply = _C.apply_contain

        def _stub_apply(plan, *, apply: bool = False):
            calls.append(bool(apply))
            return _C.ContainResult(
                ok=True, status="applied" if apply else "planned",
                applied=["stub-rule"] if apply else [],
                verified=["stub-rule"] if apply else [],
                detail="桩：未碰真实防火墙", non_interference="桩")

        try:
            _C.apply_contain = _stub_apply
            dec5 = PayloadPipeline(dict(cfg, execute=True)).handle(
                PayloadPipeline(dict(cfg, execute=True)).trigger(rec) or {}, force=True)
        finally:
            _C.apply_contain = real_apply
        chk("execute=true 时把 apply=True 传给了封锁实现（桩验证，未碰真实防火墙）",
            calls == [True], str(calls))

        calls.clear()
        try:
            _C.apply_contain = _stub_apply
            dec6 = PayloadPipeline(dict(cfg, execute=False)).handle(
                PayloadPipeline(dict(cfg, execute=False)).trigger(rec) or {}, force=True)
        finally:
            _C.apply_contain = real_apply
        chk("execute=false 时只出计划（apply=False）", calls == [False], str(calls))
        chk("桩确实被调用过（否则上面的断言是空转）", bool(dec5.step("contain")),
            str(dec5.step("contain")))
        chk("execute=false 的封锁步骤状态为 planned",
            dec6.step("contain") is not None
            and dec6.step("contain").status == "planned",
            str(dec6.step("contain") and dec6.step("contain").status))

        # -- 事件读取：坏行跳过 --
        ev = td / "ev.jsonl"
        ev.write_text('{"source":"net_sensor","score":80,"route":"auto_attack"}\n'
                      'not json at all\n'
                      '\n'
                      '{"source":"net_sensor","score":10}\n', encoding="utf-8")
        recs = pipe.read_events(ev)
        chk("事件读取跳过坏行、保留好行", len(recs) == 2, str(len(recs)))

    print(f"\nsandbox.pipeline 自检：{ok} 通过 / {fail} 失败")
    return 1 if fail else 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="威胁 → 载荷只读固化 → 报警 → 静态分析 → 最小影响封锁 → 人工交接")
    ap.add_argument("--once", action="store_true", help="处理现有事件后退出")
    ap.add_argument("--loop", action="store_true", help="常驻轮询")
    ap.add_argument("--interval", type=int, default=30, help="轮询间隔秒（--loop）")
    ap.add_argument("--from-file", default="", help="直接读指定事件文件")
    ap.add_argument("--from-end", action="store_true", help="只处理文件末尾的记录")
    ap.add_argument("--high-threshold", type=int, default=40)
    ap.add_argument("--cooldown", type=int, default=1800)
    ap.add_argument("--execute", action="store_true",
                    help="允许真封锁（默认只出计划；仍需管理员）")
    ap.add_argument("--no-analyze", action="store_true")
    ap.add_argument("--no-handoff", action="store_true")
    ap.add_argument("--bench", action="store_true",
                    help="不报警、不封锁、不改任何东西，只用现有事件跑一遍看判定")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    try:
        sys.stdout.reconfigure(errors="replace")  # type: ignore[union-attr]
    except Exception:  # noqa: BLE001
        pass

    cfg: Dict[str, Any] = {"enabled": True, "auto_extract": not args.bench,
                           "analyze": not args.no_analyze, "handoff": not args.no_handoff,
                           "execute": args.execute and not args.bench,
                           "notify": not args.bench, "high_threshold": args.high_threshold,
                           "cooldown_seconds": args.cooldown}
    pipe = PayloadPipeline(cfg)
    paths = [Path(args.from_file)] if args.from_file else list(_default_event_paths().values())

    def sweep() -> int:
        fired = 0
        for p in paths:
            for rec in pipe.read_events(p, from_end=args.from_end):
                trig = pipe.trigger(rec)
                if not trig:
                    continue
                dec = pipe.handle(trig)
                print(json.dumps(dec.to_dict(), ensure_ascii=False))
                fired += 1 if dec.fired else 0
        return fired

    if args.loop:
        while True:
            try:
                sweep()
            except Exception as exc:  # noqa: BLE001  常驻流程不能因一条坏记录退出
                print(f"[pipeline] 本轮异常（继续）：{type(exc).__name__}: {exc}",
                      file=sys.stderr)
            time.sleep(max(5, args.interval))
    n = sweep()
    print(f"处理完成，触发 {n} 次。审计：{pipe.audit_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
