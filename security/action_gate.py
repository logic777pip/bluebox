#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""security/action_gate.py — 动作**准入闸门**：在交出建议动作之前做语义级审查。

为什么需要它（`security/action_schema.py` 的白名单管不了这些）
------------------------------------------------------------

白名单只能校验「字段合法」，管不了「语义合理」。隐蔽信道评测实测出三类问题，
全部是**字段合法但语义有害**的动作：

| 实测现象 | 占比 | 白名单能拦吗 |
| --- | --- | --- |
| `block_ip` 打到**受害主机自己的 IP** | 41.7% | ❌ 字段完全合法 |
| `block_ip` 方向写成 `inbound`（反向回连应堵出向） | 95.8% | ❌ `inbound` 是合法枚举值 |
| 对已声明业务归属的良性流量下不可逆动作 | 42.5% | ❌ 字段完全合法 |

闸门规则（确定性，不依赖模型自我约束）
--------------------------------------

* **G1 目标角色**：`block_ip.src_ip` 必须是**对端**；若等于本机 IP → **拒绝**。
  封自己的 IP 会切断受害人自己而留下 C2 通道，是纯自伤。
* **G2 方向**：本机发起的回连应堵**出向**；`inbound` → 纠正为 `outbound`（不是拒绝，
  否则会丢掉整个处置动作）。缺失 → 补 `outbound`。
* **G3 TTL**：`block_ip` 必须带 `ttl_seconds`（≤ 86400）便于回溯；缺失 → 补默认值。
* **G4 业务归属**：遥测里已声明业务归属（白名单域名/已登记网关/标准进程）时，
  任何不可逆动作都要求回答**显式反驳**该归属；否则 → **拒绝**。
* **G5 取证先行**：对主机做不可逆牽制前必须已提交 `collect_forensics`；
  否则 → **拒绝**（隔离会中断会话并销毁易失证据）。
* **G6 确认门**：不可逆动作必须有两阶段确认（由 `security.action_schema.TwoPhaseGuard`
  强制）；本闸门只做记录，不重复实现。

输出是 allow / reject / correct 三类判定，**拒绝必须给出可执行的理由**，
便于回灌给模型重试，也便于审计复盘。

用法::

    python security/action_gate.py --selftest
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security.action_schema import ACTION_SPECS  # noqa: E402
from security.asset_inventory import (  # noqa: E402
    Inventory, default_inventory, parse_endpoint_roles,
)
from security.sanitize import get_logger  # noqa: E402

LOG = get_logger("security.action_gate")

DEFAULT_TTL = 86400
MAX_TTL = 86400

# 对主机生效的不可逆牽制动作（需要「取证先行」）
HOST_CONTAINMENT = frozenset({
    "isolate_host", "rebuild_host", "restore_host", "restore_from_backup",
    "remove_persistence", "kill_process", "delete_file", "quarantine_file",
})


@dataclass
class GateFinding:
    action: str
    status: str                     # allow / reject / correct
    rule: str
    reason: str
    original_args: Dict[str, Any] = field(default_factory=dict)
    corrected_args: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GateDecision:
    allowed: List[Dict[str, Any]] = field(default_factory=list)
    rejected: List[GateFinding] = field(default_factory=list)
    corrected: List[GateFinding] = field(default_factory=list)
    findings: List[GateFinding] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    attribution: List[str] = field(default_factory=list)

    @property
    def rejected_names(self) -> List[str]:
        return [f.action for f in self.rejected]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "rejected": [f.to_dict() for f in self.rejected],
            "corrected": [f.to_dict() for f in self.corrected],
            "findings": [f.to_dict() for f in self.findings],
            "context": self.context,
            "attribution": self.attribution,
        }


class ActionGate:
    """语义级动作准入闸门。"""

    def __init__(self, inventory: Optional[Inventory] = None) -> None:
        self.inv = inventory or default_inventory()

    # ------------------------------------------------------------------ #

    def admit(self, alert: str, answer: str,
              actions: Sequence[Dict[str, Any]]) -> GateDecision:
        """审查一批动作。`actions` 元素形如 {"action":…, "args":{…}}。"""
        roles = parse_endpoint_roles(alert)
        attribution = self.inv.business_attribution_in(alert)
        rebutted = self.inv.attribution_rebutted(answer)

        dec = GateDecision(
            context={**roles.to_dict(), "attribution_rebutted": rebutted},
            attribution=attribution,
        )

        names = [str(a.get("action") or a.get("name") or "") for a in actions]
        has_forensics = any(n == "collect_forensics" for n in names)

        for raw in actions:
            name = str(raw.get("action") or raw.get("name") or "")
            args = dict(raw.get("args") or {})
            spec = ACTION_SPECS.get(name)
            irreversible = bool(spec.irreversible) if spec else True
            findings: List[GateFinding] = []
            cur = args

            # ---- G1 目标角色：不许封自己的 IP ----
            if name == "block_ip":
                tgt = str(cur.get("src_ip", ""))
                if roles.host_ip and tgt == roles.host_ip:
                    findings.append(GateFinding(
                        name, "reject", "G1",
                        f"封禁目标是本机 IP {tgt}（受害主机自身）。反向回连应封对端 "
                        f"{roles.peer_ip or '对端地址'}；封自己会切断受害主机而留下 C2 通道。",
                        cur))
                elif roles.peer_ip and tgt and tgt != roles.peer_ip:
                    findings.append(GateFinding(
                        name, "reject", "G1",
                        f"封禁目标 {tgt} 既非本机也非本案对端 {roles.peer_ip}，"
                        f"属于打错目标（勿臆测地址）。", cur))

            # ---- G2 方向：本机发起的回连应堵出向 ----
            if name == "block_ip" and not any(f.status == "reject" for f in findings):
                d = str(cur.get("direction") or "").lower()
                if d != "outbound":
                    fixed = {**cur, "direction": "outbound"}
                    findings.append(GateFinding(
                        name, "correct", "G2",
                        f"方向为 {d or '未指定'}；本机主动发起的回连应堵**出向**，"
                        f"已纠正为 outbound。", cur, fixed))
                    cur = fixed

            # ---- G3 TTL：封禁要可回溯 ----
            if name == "block_ip" and not any(f.status == "reject" for f in findings):
                ttl = cur.get("ttl_seconds")
                try:
                    ttl_v = int(ttl) if ttl is not None else 0
                except (TypeError, ValueError):
                    ttl_v = 0
                if ttl_v <= 0 or ttl_v > MAX_TTL:
                    fixed = {**cur, "ttl_seconds": DEFAULT_TTL}
                    findings.append(GateFinding(
                        name, "correct", "G3",
                        f"封禁未带有效 TTL；已补 {DEFAULT_TTL}s（便于回溯，避免永久误封）。",
                        cur, fixed))
                    cur = fixed

            # ---- G4 业务归属未被反驳 ----
            if irreversible and attribution and not rebutted:
                findings.append(GateFinding(
                    name, "reject", "G4",
                    f"遥测已声明业务归属（{'；'.join(attribution[:3])}），"
                    f"但回答未显式反驳该归属就下了不可逆动作。"
                    f"需先排除业务解释（引用形状判据并说明业务归属为何不成立）。",
                    cur))

            # ---- G5 取证先行 ----
            if name in HOST_CONTAINMENT and irreversible and not has_forensics:
                findings.append(GateFinding(
                    name, "reject", "G5",
                    "对主机做不可逆牽制前必须先提交 collect_forensics："
                    "隔离会中断会话并销毁易失证据（内存、对端与密钥材料）。",
                    cur))

            # ---- 归档 ----
            rej = [f for f in findings if f.status == "reject"]
            dec.findings.extend(findings)
            if rej:
                dec.rejected.extend(rej)
                continue
            corr = [f for f in findings if f.status == "correct"]
            if corr:
                dec.corrected.extend(corr)
            dec.allowed.append({"action": name, "args": cur,
                                "irreversible": irreversible,
                                "rationale": raw.get("rationale", "")})
        return dec


# --------------------------------------------------------------------------- #
#  自检
# --------------------------------------------------------------------------- #

_ALERT_COVERT = (
    "[NDR] 主机 ws-108（192.0.2.86）与 198.51.100.13:443 之间存在持续 UDP 会话，"
    "累计 1224 个报文 / 0.4 MB。\n"
    "报文长度取值：192B 占 24.0%、288B 占 26.5%、384B 占 24.7%、448B 占 24.9%。\n"
    "主机侧：进程 svchost.exe 路径位于 C:\\Users\\Public\\AppData\\Local\\Temp\\，无签名"
)
_ALERT_BENIGN = (
    "[NDR] 主机 db-229（192.0.2.39）与 203.0.113.216:443 之间存在持续 UDP 会话，"
    "累计 2286 个报文 / 2.0 MB。\n"
    "主机侧：进程 chrome.exe，浏览器正常网络行为；域名命中企业白名单"
)


def selftest() -> int:
    gate = ActionGate()
    ok = total = 0

    def check(name: str, cond: bool, detail: str = "") -> None:
        nonlocal ok, total
        total += 1
        if cond:
            ok += 1
        print(f"  [{'ok  ' if cond else 'FAIL'}] {name}{(' — ' + detail) if detail and not cond else ''}")

    # G1 拒绝：封自己的 IP
    d = gate.admit(_ALERT_COVERT, "已取证", [{"action": "block_ip",
                                             "args": {"src_ip": "192.0.2.86"}}])
    check("G1 封本机 IP 被拒", len(d.rejected) == 1 and d.rejected[0].rule == "G1")

    # G1 允许：封对端
    d = gate.admit(_ALERT_COVERT, "已取证", [{"action": "block_ip",
                                             "args": {"src_ip": "198.51.100.13",
                                                      "direction": "outbound",
                                                      "ttl_seconds": 86400}}])
    check("G1 封对端放行", len(d.rejected) == 0 and len(d.allowed) == 1)

    # G2 纠正 inbound → outbound
    d = gate.admit(_ALERT_COVERT, "已取证", [{"action": "block_ip",
                                             "args": {"src_ip": "198.51.100.13",
                                                      "direction": "inbound",
                                                      "ttl_seconds": 86400}}])
    check("G2 inbound 被纠正为 outbound",
          any(f.rule == "G2" for f in d.corrected)
          and d.allowed and d.allowed[0]["args"]["direction"] == "outbound")

    # G3 补 TTL
    d = gate.admit(_ALERT_COVERT, "已取证", [{"action": "block_ip",
                                             "args": {"src_ip": "198.51.100.13",
                                                      "direction": "outbound"}}])
    check("G3 缺 TTL 被补齐",
          any(f.rule == "G3" for f in d.corrected)
          and d.allowed and d.allowed[0]["args"]["ttl_seconds"] == DEFAULT_TTL)

    # G4 拒绝：有业务归属且未反驳
    d = gate.admit(_ALERT_BENIGN, "判定为隐蔽信道。",
                   [{"action": "block_ip", "args": {"src_ip": "203.0.113.216",
                                                    "direction": "outbound",
                                                    "ttl_seconds": 86400}}])
    check("G4 业务归属未反驳被拒",
          any(f.rule == "G4" for f in d.rejected))

    # G4 放行：显式反驳
    d = gate.admit(_ALERT_BENIGN,
                   "虽然是浏览器，但报文长度被限制在 4 档且占比接近均匀，业务解释不成立。",
                   [{"action": "block_ip", "args": {"src_ip": "203.0.113.216",
                                                    "direction": "outbound",
                                                    "ttl_seconds": 86400}}])
    check("G4 显式反驳后放行", len(d.rejected) == 0)

    # G5 拒绝：无取证就隔离
    d = gate.admit(_ALERT_COVERT, "已研判", [{"action": "isolate_host",
                                             "args": {"host_id": "ws-108"}}])
    check("G5 未取证先隔离被拒", any(f.rule == "G5" for f in d.rejected))

    # G5 放行：有取证
    d = gate.admit(_ALERT_COVERT, "已研判",
                   [{"action": "collect_forensics",
                     "args": {"host_id": "ws-108", "artifacts": ["memory"]}},
                    {"action": "isolate_host", "args": {"host_id": "ws-108"}}])
    check("G5 取证后隔离放行", len(d.rejected) == 0 and len(d.allowed) == 2)

    # 只读动作永远放行
    d = gate.admit(_ALERT_BENIGN, "无", [{"action": "query_logs",
                                         "args": {"host_id": "db-229", "query": "x"}}])
    check("只读动作放行", len(d.rejected) == 0 and len(d.allowed) == 1)

    # 解析端点角色
    r = parse_endpoint_roles(_ALERT_COVERT)
    check("端点角色解析正确",
          r.host == "ws-108" and r.host_ip == "192.0.2.86" and r.peer_ip == "198.51.100.13")

    # 回归：清单里「已知但未获准」的进程名不得被当成业务归属
    # （covert 用例用的是 svchost.exe；若把「已知」当「已解释」，G4 会把恶意用例也放行/误拒）
    check("已知但未获准的进程不构成业务归属",
          gate.inv.business_attribution_in(_ALERT_COVERT) == [])
    check("已获准的业务进程构成业务归属",
          len(gate.inv.business_attribution_in(_ALERT_BENIGN)) > 0)

    print(f"  {ok}/{total} 通过")
    return 0 if ok == total else 1


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="动作准入闸门")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--alert-file", default=None)
    ap.add_argument("--actions", default=None, help="动作 JSON 数组")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    if args.alert_file and args.actions:
        alert = Path(args.alert_file).read_text(encoding="utf-8")
        acts = json.loads(args.actions)
        d = ActionGate().admit(alert, "", acts)
        print(json.dumps(d.to_dict(), ensure_ascii=False, indent=2))
        return 0
    ap.error("需要 --selftest，或同时提供 --alert-file 与 --actions")


if __name__ == "__main__":
    raise SystemExit(main())
