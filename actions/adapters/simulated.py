#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""actions/adapters/simulated.py — 本地隔离仿真靶场适配器（确定性、无副作用）。

为什么需要它：
  本项目在单机（RTX 5060 / 8GB）上开发，没有真实 EDR / SOAR / 防火墙可接。
  但「AI 系统具备动作能力」必须**可验证**——否则只是产出 JSON 文本，无法证明它会用。

它做什么：
  维护一份内存态的小型 SOC 环境（主机 / 账号 / 服务 / 检测规则 / 证据库），
  对全部 PDCERF 动作给出**确定性的、结构化的观测**：
      * 未知主机/账号 → 如实失败（不幻觉出结果）
      * 检索类动作 → 返回可被 grounding_check 核对的真实条目
      * 破坏性动作 → 改变内存状态，重复执行可观察到「已隔离」等幂等语义

安全边界：
  纯内存、无网络、无文件系统写入、无进程操作。绝不触碰真实主机。
"""

from __future__ import annotations

import hashlib
import json
import random
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from security.action_schema import Action

from .base import Adapter, ExecutionFailed, STATUS_OK, ToolContext, ToolResult

__all__ = ["SimulatedRangeAdapter", "RANGE_HOSTS"]


# --------------------------------------------------------------------------- #
#  靶场种子数据（一律使用 RFC5737 文档网段，避免与真实资产混淆）
# --------------------------------------------------------------------------- #

RANGE_HOSTS: Dict[str, Dict[str, Any]] = {
    "fin-ws-07": {"ip": "192.0.2.17", "role": "财务工作站", "os": "Windows 11 23H2",
                  "criticality": "medium", "owner": "finance-it@corp.example.com"},
    "fin-ws-08": {"ip": "192.0.2.18", "role": "财务工作站", "os": "Windows 11 23H2",
                  "criticality": "medium", "owner": "finance-it@corp.example.com"},
    "hr-ws-03": {"ip": "192.0.2.31", "role": "人事工作站", "os": "Windows 10 22H2",
                 "criticality": "low", "owner": "hr-it@corp.example.com"},
    "web-01": {"ip": "198.51.100.11", "role": "对外 Web 前端", "os": "Ubuntu 22.04",
               "criticality": "high", "owner": "sre@corp.example.com"},
    "app-02": {"ip": "198.51.100.12", "role": "业务应用服务器", "os": "Ubuntu 22.04",
               "criticality": "high", "owner": "sre@corp.example.com"},
    "dc-01": {"ip": "203.0.113.5", "role": "域控", "os": "Windows Server 2022",
              "criticality": "critical", "owner": "iam@corp.example.com"},
    "jump-01": {"ip": "203.0.113.20", "role": "运维跳板机", "os": "Ubuntu 22.04",
                "criticality": "critical", "owner": "sre@corp.example.com"},
    "backup-01": {"ip": "203.0.113.30", "role": "备份服务器", "os": "Ubuntu 22.04",
                  "criticality": "high", "owner": "sre@corp.example.com"},
}

RANGE_ACCOUNTS: Dict[str, Dict[str, Any]] = {
    "svc-web": {"type": "service", "privilege": "app", "owner": "sre@corp.example.com"},
    "zhang.wei": {"type": "user", "privilege": "finance-operator", "owner": "finance-it@corp.example.com"},
    "li.na": {"type": "user", "privilege": "hr-operator", "owner": "hr-it@corp.example.com"},
    "admin-ops": {"type": "admin", "privilege": "domain-admin", "owner": "iam@corp.example.com"},
    "svc-backup": {"type": "service", "privilege": "backup-operator", "owner": "sre@corp.example.com"},
}

RANGE_SERVICES = ("nginx", "tomcat", "postgresql", "sshd", "samba")

# 检测规则库（防"拍脑袋编规则号"）
RANGE_RULES: Dict[str, Dict[str, Any]] = {
    "rule-ou-001": {"title": "Office 子进程创建计划任务", "severity": "high", "enabled": True},
    "rule-dns-014": {"title": "高熵域名批量解析", "severity": "medium", "enabled": True},
    "rule-lolbin-007": {"title": "LOLBin 下载执行", "severity": "high", "enabled": True},
}

# 可被检索到的遥测语料（键 = 主机，值 = 日志行模板）
_TELEMETRY: Dict[str, List[str]] = {
    "fin-ws-07": [
        "EDR: process=excel.exe pid={p1} cmdline=\"EXCEL.EXE /dde\"",
        "EDR: child=rundll32.exe pid={p2} parent=excel.exe path=C:\\Users\\Public\\7z.lock7z.dll",
        "DNS: query=cf-update-svc.example node=fin-ws-07 rcode=NOERROR",
        "NET: dst=203.0.113.9:443 proto=tcp bytes_out=18234 dur=41s",
        "FILE: write C:\\Users\\Public\\7z.lock7z.dll size=214016 sha256={h1}",
        "SCHTASK: create \\Microsoft\\Windows\\FinSyncUpdate trigger=logon",
        "AUTH: account=zhang.wei src=192.0.2.17 logon_type=2 result=success",
    ],
    "web-01": [
        "HTTP: POST /api/upload 500 src=203.0.113.9 ua=\"curl/8.4.0\"",
        "WAF: signature=java-deser blocked=false path=/api/import",
        "FILE: write /tmp/.cache/jetty-helper.jar size=51200 sha256={h2}",
        "EDR: exec java -jar /tmp/.cache/jetty-helper.jar pid={p3}",
    ],
    "dc-01": [
        "AUTH: kerberos TGS-REQ account=admin-ops spn=cifs/dc-01 result=success",
        "AUTH: account=admin-ops src=192.0.2.17 logon_type=3 result=success",
        "AUTH: account=admin-ops failed_logons=0 (异常：来源为非管理网段)",
    ],
}


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class SimulatedRangeAdapter(Adapter):
    """内存态 SOC 靶场适配器。"""

    name = "sim"
    real_effects = False

    def __init__(self, seed: int = 3407, case_note: str = "") -> None:
        self.seed = int(seed)
        self.note = case_note
        # 可变状态
        self.isolated: Dict[str, Dict[str, Any]] = {}
        self.blocked_ips: Dict[str, Dict[str, Any]] = {}
        self.blocked_domains: Dict[str, Dict[str, Any]] = {}
        self.killed_pids: Dict[str, List[int]] = {}
        self.quarantined: List[Dict[str, Any]] = {}
        self.deleted: List[Dict[str, Any]] = []
        self.snapshots: Dict[str, List[Dict[str, Any]]] = {}
        self.credentials_reset: Set[str] = set()
        self.sessions_revoked: Set[str] = set()
        self.restricted_accounts: Set[str] = set()
        self.patches: List[Dict[str, Any]] = []
        self.rebuilt: Set[str] = set()
        self.restored: List[Dict[str, Any]] = []
        self.restarted: List[Dict[str, Any]] = []
        self.log_levels: Dict[str, str] = {}
        self.pcap: List[Dict[str, Any]] = []
        self.persistence_removed: List[Dict[str, Any]] = []
        self.evidence: List[Dict[str, Any]] = []
        self.published_iocs: Dict[str, Dict[str, Any]] = {}
        self.rule_updates: List[Dict[str, Any]] = []
        self.postmortems: List[Dict[str, Any]] = []
        self.timeline_queries: List[Dict[str, Any]] = []
        # 沙箱联动（仿真）：只记事件，不写任何真实目录。
        self.extracted_payloads: List[Dict[str, Any]] = []
        self.payload_reports: List[Dict[str, Any]] = []
        self.handoffs: List[Dict[str, Any]] = []
        self.contained_indicators: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    def capabilities(self) -> Set[str]:
        return {
            "asset_lookup", "snapshot_host", "verify_backup", "raise_log_level",
            "query_logs", "query_flow", "enrich_ioc", "collect_timeline", "capture_pcap",
            "isolate_host", "block_ip", "block_domain", "revoke_session", "restrict_account",
            "disable_account", "collect_forensics",
            "kill_process", "quarantine_file", "delete_file", "remove_persistence",
            "reset_credential", "patch_vulnerability", "rebuild_host",
            "restore_host", "restore_from_backup", "restart_service", "lift_isolation",
            "verify_integrity",
            "archive_evidence", "write_postmortem", "update_detection_rule",
            "publish_ioc", "close_case", "notify_analyst",
            # 沙箱联动。⚠ **没有** detonate_payload —— 动作白名单里就不存在它：
            # 需求是「禁止 AI 进行动态分析」，所以仿真靶场也不提供这个能力，
            # 否则评测时会跑出一个"AI 可以引爆样本"的假象。
            "extract_payload", "analyze_payload", "prepare_dynamic_analysis",
            "contain_threat",
        }

    def health(self) -> Tuple[bool, str]:
        return True, "内存靶场，恒可用（无真实副作用）"

    # ------------------------------------------------------------------ #
    #  内部工具
    # ------------------------------------------------------------------ #
    def _rng(self, action: Action) -> random.Random:
        payload = json.dumps({"a": action.name, "g": action.args}, sort_keys=True)
        return random.Random(f"{self.seed}:{payload}")

    @staticmethod
    def _require_host(args: Dict[str, Any]) -> str:
        host = str(args.get("host_id", ""))
        if host not in RANGE_HOSTS:
            raise ExecutionFailed(f"资产台账中不存在主机 {host!r}（勿臆测资产，请先 asset_lookup）")
        return host

    @staticmethod
    def _require_account(args: Dict[str, Any]) -> str:
        acct = str(args.get("account", ""))
        if acct not in RANGE_ACCOUNTS:
            raise ExecutionFailed(f"账号 {acct!r} 不存在（请先用 query_logs 确认账号名）")
        return acct

    # ------------------------------------------------------------------ #
    #  执行入口
    # ------------------------------------------------------------------ #
    def execute(self, action: Action, ctx: ToolContext) -> ToolResult:
        t0 = time.time()
        handler: Optional[Callable[[Action, Dict[str, Any]], Tuple[Dict[str, Any], str]]] = \
            getattr(self, f"_do_{action.name}", None)
        if handler is None:  # 理论上不会发生：capabilities 与 handler 由自检保证一致
            return ToolResult.failed(action.name, self.name, f"靶场未实现动作 {action.name}")
        try:
            output, obs = handler(action, action.args)
        except ExecutionFailed as exc:
            return ToolResult.failed(action.name, self.name, str(exc))
        except Exception as exc:  # noqa: BLE001 — 靶场内部错误也必须如实上报
            return ToolResult.failed(action.name, self.name, f"{type(exc).__name__}: {exc}")
        output = {"simulated": True, **output}
        return ToolResult(
            ok=True, action=action.name, adapter=self.name, status=STATUS_OK,
            output=output, observations=f"[仿真靶场] {obs}",
            latency_ms=int((time.time() - t0) * 1000), simulated=True,
        )

    # ------------------------------------------------------------------ #
    #  沙箱联动（仿真）—— 只记事件，不碰真实磁盘/防火墙
    # ------------------------------------------------------------------ #
    # 为什么要在这里实现：自检有一条不变量「仿真靶场必须覆盖全部白名单动作」，
    # 它保证评测台能跑到每个动作。如果靶场不支持某个动作，那个动作就永远不会
    # 在评测里出现，模型在这方面的表现也就从未被测量过 —— 这是评测盲区。
    @staticmethod
    def _fake_hex(rng: random.Random, n: int) -> str:
        return "".join(rng.choice("0123456789abcdef") for _ in range(n))

    def _do_extract_payload(self, action: Action,
                            args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        host = self._require_host(args)
        path = str(args.get("path", ""))
        if not path:
            raise ExecutionFailed("缺少 path：要固化的载荷路径")
        rng = self._rng(action)
        sha = self._fake_hex(rng, 64)
        case_id = str(args.get("case_id") or "sim-case")
        rec = {"case_id": case_id, "host_id": host, "source": path,
               "vault_path": f"logs/sandbox/vault/{sha[:12]}_payload.bin",
               "sha256": sha, "readonly": True}
        self.extracted_payloads.append(rec)
        return ({"sha256": sha, "vault_path": rec["vault_path"], "readonly": True},
                f"已把 `{path}` 复制进只读库（**复制不移动**，原文件保持原样），"
                f"SHA-256 {sha[:16]}…，已设只读。已报警。"
                f"注意：这是仿真记录，未碰真实磁盘。")

    def _do_analyze_payload(self, action: Action,
                            args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        path = str(args.get("path", ""))
        if not path:
            raise ExecutionFailed("缺少 path：要静态分析的文件")
        rng = self._rng(action)
        score = rng.randrange(10, 90)
        risk = ("critical" if score >= 70 else "high" if score >= 45
                else "medium" if score >= 25 else "low")
        rec = {"path": path, "score": score, "risk": risk,
               "sha256": self._fake_hex(rng, 64)}
        self.payload_reports.append(rec)
        return (rec,
                f"仿真静态分析：风险 **{risk}**（{score}/100）。"
                f"**未执行样本**；静态结论只是指标，不等于判决。")

    def _do_prepare_dynamic_analysis(self, action: Action,
                                     args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        case_id = str(args.get("case_id", ""))
        if not case_id:
            raise ExecutionFailed("缺少 case_id")
        rng = self._rng(action)
        rec = {"case_id": case_id,
               "cmd_file": f"logs/sandbox/cases/{case_id}/run_dynamic_analysis.cmd",
               "md_file": f"logs/sandbox/cases/{case_id}/HANDOFF.md",
               "executed_by_ai": False, "box_verified": False}
        self.handoffs.append(rec)
        return (rec,
                f"已生成人工动态分析交接包（`run_dynamic_analysis.cmd` + `HANDOFF.md`）。"
                f"**AI 不执行它**（executed_by_ai=false）。断网验证：未通过/未验证 —— "
                f"人工在差分断网验证通过前不应引爆样本。")

    def _do_contain_threat(self, action: Action,
                           args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        host = self._require_host(args)
        indicator = str(args.get("indicator", ""))
        if not indicator:
            raise ExecutionFailed("缺少 indicator：要封的 IP/域名/URL")
        ttl = int(args.get("ttl_seconds") or 14400)
        rng = self._rng(action)
        rec = {"host_id": host, "indicator": indicator, "ttl_seconds": ttl,
               "direction": "Outbound", "action": "Block",
               "rule": f"BlueTeamAgent-Contain-{self._fake_hex(rng, 8)}"}
        self.contained_indicators.append(rec)
        return (rec,
                f"已对 `{indicator}` 加**出向 Block** 规则（TTL {ttl // 60} 分钟），"
                f"不含入向规则、不动 hosts/DNS/网卡、不隔离主机。"
                f"真实实现（sandbox/contain.py）还会硬性拒绝网段与"
                f"本机地址/网关/DNS 服务器。")

    # ------------------------------------------------------------------ #
    #  P — 准备
    # ------------------------------------------------------------------ #
    def _do_asset_lookup(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        asset = str(args["asset"])
        hits = {h: v for h, v in RANGE_HOSTS.items()
                if asset.lower() in h.lower() or asset == v.get("ip") or asset.lower() in str(v.get("role", "")).lower()}
        if not hits:
            return {"found": False}, f"资产台账未收录 {asset}；请勿假设其存在。"
        lines = [f"{h}: ip={v['ip']} role={v['role']} os={v['os']} "
                 f"criticality={v['criticality']} owner={v['owner']}" for h, v in hits.items()]
        return {"found": True, "assets": hits}, "台账命中：\n" + "\n".join(lines)

    def _do_snapshot_host(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        host = self._require_host(args)
        rng = self._rng(action)
        snap_id = f"snap-{host}-{rng.randrange(10000, 99999)}"
        rec = {"snapshot_id": snap_id, "host_id": host, "label": args.get("label", ""),
               "created_at": time.time(), "consistent": True}
        self.snapshots.setdefault(host, []).append(rec)
        return {"snapshot": rec}, f"已为 {host} 创建快照 {snap_id}（一致性快照，可作回滚点）。"

    def _do_verify_backup(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        host = self._require_host(args)
        snaps = self.snapshots.get(host, [])
        target = args.get("snapshot_id")
        if target:
            found = next((s for s in snaps if s["snapshot_id"] == target), None)
            if not found:
                raise ExecutionFailed(f"{host} 上不存在快照 {target}")
            return ({"verified": True, "snapshot": found},
                    f"快照 {target} 校验通过：可挂载、校验和一致。")
        if not snaps:
            # 诚实回答：没有回滚点就是没有
            return ({"verified": False, "snapshots": []},
                    f"{host} 当前**没有可用快照**。继续执行不可逆动作将无法回滚，"
                    f"应先 snapshot_host 创建回滚点或确认离线备份。")
        return ({"verified": True, "snapshots": snaps},
                f"{host} 可用快照 {len(snaps)} 个：{', '.join(s['snapshot_id'] for s in snaps)}")

    def _do_raise_log_level(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        host = self._require_host(args)
        scope = str(args.get("scope", "all"))
        self.log_levels[host] = scope
        return ({"host_id": host, "scope": scope, "effective_in_seconds": 30},
                f"{host} 遥测粒度已提升（范围={scope}），约 30s 后生效；"
                f"注意：进程创建与网络连接的采样率提高会显著增加日志量。")

    # ------------------------------------------------------------------ #
    #  D — 检测
    # ------------------------------------------------------------------ #
    def _do_query_logs(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        host = self._require_host(args)
        query = str(args["query"])
        rng = self._rng(action)
        pool = list(_TELEMETRY.get(host, []))
        if not pool:
            pool = [f"EDR: process=unknown pid={rng.randrange(1000, 9999)} host={host}",
                    f"NET: dst=203.0.113.9:443 host={host}"]
        fmt = {"p1": rng.randrange(1000, 9999), "p2": rng.randrange(1000, 9999),
               "p3": rng.randrange(1000, 9999), "h1": _sha(f"{host}:1"), "h2": _sha(f"{host}:2")}
        lines = [ln.format(**fmt) for ln in pool]
        kw = query.lower()
        hits = [ln for ln in lines if kw in ln.lower()] or []
        strict = [ln for ln in lines if any(t in ln.lower() for t in kw.split())]
        matched = hits or strict
        if not matched:
            return ({"host_id": host, "query": query, "matches": 0, "lines": []},
                    f"{host} 在检索条件「{query}」下**未命中任何日志**"
                    f"（该主机共有 {len(lines)} 条已采集遥测）。"
                    f"未命中不等于排除，请调整检索条件或扩大时间窗。")
        return ({"host_id": host, "query": query, "matches": len(matched), "lines": matched},
                f"{host} 命中 {len(matched)} 条：\n" + "\n".join(matched))

    def _do_query_flow(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        host = self._require_host(args)
        minutes = int(args.get("window_minutes", 60))
        rng = self._rng(action)
        peers = ["203.0.113.9", "203.0.113.44", "192.0.2.0/24"]
        flows = []
        for peer in peers:
            n = rng.randrange(3, 60)
            flows.append({"dst": peer, "sessions": n, "bytes_out": n * rng.randrange(400, 3000),
                          "first_seen_offset_min": rng.randrange(1, max(2, minutes))})
        return ({"host_id": host, "window_minutes": minutes, "flows": flows},
                f"{host} 近 {minutes} 分钟会话（按对端聚合）：\n" +
                "\n".join(f"- dst={f['dst']} sessions={f['sessions']} bytes_out={f['bytes_out']}" for f in flows))

    def _do_enrich_ioc(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        ind = str(args["indicator"])
        rng = self._rng(action)
        if rng.random() < 0.25:
            return ({"indicator": ind, "verdict": "not_found", "sources": []},
                    f"{ind} 在各情报源中**未获取到记录**（未命中不等于无害，"
                    f"也不等于已被标记）。")
        score = rng.randrange(40, 95)
        sources = rng.sample(["otx", "threatfox", "abuseipdb"], k=min(2, 3))
        return ({"indicator": ind, "verdict": "malicious", "score": score, "sources": sources},
                f"{ind} 情报命中：score={score}/100，来源={', '.join(sources)}，"
                f"家族标签=lock7z。注意：情报有 TTL，需与本案遥测交叉验证。")

    def _do_collect_timeline(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        case_id = str(args["case_id"])
        host = args.get("host_id")
        hosts = [host] if host else sorted(RANGE_HOSTS)[:3]
        rng = self._rng(action)
        events = []
        base = 0
        for h in hosts:
            if h not in RANGE_HOSTS:
                raise ExecutionFailed(f"资产台账中不存在主机 {h!r}")
            base += rng.randrange(20, 200)
            events.append({"offset_s": base, "host": h, "stage": "exec",
                           "detail": f"{h} 出现异常子进程"})
            events.append({"offset_s": base + rng.randrange(5, 60), "host": h, "stage": "c2",
                           "detail": f"{h} 外连 203.0.113.9:443"})
        self.timeline_queries.append({"case_id": case_id, "events": len(events)})
        return ({"case_id": case_id, "events": events},
                f"案例 {case_id} 时间线聚合完成（{len(events)} 个事件，跨 {len(hosts)} 台主机）：\n" +
                "\n".join(f"+{e['offset_s']}s {e['host']} [{e['stage']}] {e['detail']}" for e in events))

    def _do_capture_pcap(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        host = self._require_host(args)
        dur = int(args["duration_seconds"])
        rec = {"host_id": host, "duration_seconds": dur, "artifact": f"pcap/{host}-{int(time.time())}.pcap"}
        self.pcap.append(rec)
        return ({"capture": rec},
                f"已在 {host} 上启动 {dur}s 抓包 → {rec['artifact']}。"
                f"注意：抓包会占用磁盘，且 TLS 流量需结合 JA3/证书才能归因。")

    # ------------------------------------------------------------------ #
    #  C — 遏制
    # ------------------------------------------------------------------ #
    def _do_isolate_host(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        host = self._require_host(args)
        mode = str(args.get("mode", "soft"))
        if host in self.isolated:
            return ({"host_id": host, "already_isolated": True},
                    f"{host} 已处于隔离状态（{self.isolated[host]['mode']}），本次为幂等重复调用。")
        self.isolated[host] = {"mode": mode, "at": time.time()}
        warn = ("硬隔离会中断所有会话，含正在进行的取证传输与业务连接。"
                if mode == "hard" else
                "软隔离仅切断出向到非管理网段，保留管理通道。")
        return ({"host_id": host, "mode": mode, "isolated": True},
                f"{host} 已{mode}隔离。{warn} 隔离时机需在取证之后，否则易失证据会丢失。")

    def _do_block_ip(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        ip = str(args["src_ip"])
        direction = str(args.get("direction", "both"))
        ttl = int(args.get("ttl_seconds", 3600))
        prev = self.blocked_ips.get(ip)
        if prev:
            return ({"src_ip": ip, "already_blocked": True, "previous": prev},
                    f"{ip} 已在封禁表中（方向={prev['direction']}，剩余 TTL）。本次为幂等重复调用。")
        self.blocked_ips[ip] = {"direction": direction, "ttl_seconds": ttl, "at": time.time()}
        return ({"src_ip": ip, "direction": direction, "ttl_seconds": ttl},
                f"已封禁 {ip}（方向={direction}，TTL={ttl}s）。"
                f"请确认该 IP 是 C2 对端而非受害主机自身——方向写反会导致内网主机被切断。")

    def _do_block_domain(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        dom = str(args["domain"])
        ttl = int(args.get("ttl_seconds", 3600))
        self.blocked_domains[dom] = {"ttl_seconds": ttl, "at": time.time()}
        return ({"domain": dom, "ttl_seconds": ttl},
                f"已在 DNS/出口层封禁 {dom}（TTL={ttl}s）。"
                f"注意 DGA 域名需配合熵检测规则，单点封禁会漏。")

    def _do_revoke_session(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        acct = self._require_account(args)
        self.sessions_revoked.add(acct)
        return ({"account": acct, "sessions_revoked": True},
                f"已吊销 {acct} 的全部活动会话与刷新令牌。"
                f"用户需重新认证；若该账号是服务账号，需同步更新依赖方配置（否则业务中断）。")

    def _do_restrict_account(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        acct = self._require_account(args)
        self.restricted_accounts.add(acct)
        return ({"account": acct, "privilege": "read-only"},
                f"{acct} 已降权为只读。相比直接禁用，降权保留了审计与值守能力，"
                f"适用于「疑似被滥用但业务仍需要」的账号。")

    def _do_disable_account(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        acct = self._require_account(args)
        self.sessions_revoked.add(acct)
        self.restricted_accounts.add(acct)
        return ({"account": acct, "disabled": True},
                f"{acct} 已禁用并吊销全部会话。请确认其非关键服务账号，"
                f"否则会引发比攻击本身更大的可用性事故。")

    def _do_collect_forensics(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        host = self._require_host(args)
        arts = list(args["artifacts"])
        rec = {"host_id": host, "artifacts": arts, "case_id": args.get("case_id", ctx_placeholder()),
               "at": time.time(), "hash": _sha(f"{host}:{'-'.join(arts)}")}
        self.evidence.append({"kind": "forensics", **rec})
        return ({"forensic": rec},
                f"已采集 {host} 的取证产物：{', '.join(arts)}（哈希 {rec['hash'][:16]}…）。"
                f"取证必须先于隔离：隔离会销毁内存与活动会话等易失证据。")

    # ------------------------------------------------------------------ #
    #  E — 根除
    # ------------------------------------------------------------------ #
    def _do_kill_process(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        host = self._require_host(args)
        pid = int(args["pid"])
        if pid in self.killed_pids.get(host, []):
            return ({"host_id": host, "pid": pid, "already_killed": True},
                    f"{host} 上 PID {pid} 之前已被终止（幂等）。")
        self.killed_pids.setdefault(host, []).append(pid)
        return ({"host_id": host, "pid": pid, "killed": True},
                f"已终止 {host} 上 PID {pid}。"
                f"仅杀进程不足以根除：持久化项会在下次登录/重启时拉活，必须继续 remove_persistence。")

    def _do_quarantine_file(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        host = self._require_host(args)
        path = str(args["path"])
        sha = str(args.get("sha256", "")) or _sha(path)
        rec = {"host_id": host, "path": path, "sha256": sha, "at": time.time()}
        self.quarantined.append(rec)
        return ({"quarantined": rec},
                f"已隔离 {host}:{path}（sha256={sha[:16]}…）。文件被保留而非删除，便于后续取证与回溯。")

    def _do_delete_file(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        host = self._require_host(args)
        path = str(args["path"])
        if any(q["host_id"] == host and q["path"] == path for q in self.deleted):
            return ({"host_id": host, "path": path, "already_deleted": True},
                    f"{host}:{path} 已被删除（幂等）。")
        self.deleted.append({"host_id": host, "path": path, "at": time.time()})
        return ({"host_id": host, "path": path, "deleted": True},
                f"已删除 {host}:{path}。"
                f"⚠ 删除不可逆：若未先 quarantine_file，将失去样本；请确认已有副本。")

    def _do_remove_persistence(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        host = self._require_host(args)
        mech = str(args["mechanism"])
        rec = {"host_id": host, "mechanism": mech, "path": args.get("path", ""), "at": time.time()}
        self.persistence_removed.append(rec)
        detail = {
            "scheduled_task": "计划任务 \\Microsoft\\Windows\\FinSyncUpdate 已删除",
            "registry_run": "Run 键值 FinSync 已删除",
            "service": "服务 FinSyncSvc 已停止并删除",
            "cron": "crontab 条目已移除",
            "startup": "启动目录快捷方式已移除",
            "ssh_authorized_key": "authorized_keys 中的可疑公钥已移除",
            "wmi_subscription": "WMI 事件订阅已移除",
            "all": "已枚举并清除全部已知持久化机制",
        }.get(mech, f"已清除 {mech}")
        extra = ("⚠ 清除后必须重新枚举，攻击者常布设多处持久化（含 WMI 订阅这类隐蔽位置）。"
                 if mech != "all" else "建议再跑一次全量枚举确认无残留。")
        return ({"removed": rec}, f"{host}: {detail}。{extra}")

    def _do_reset_credential(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        acct = self._require_account(args)
        self.credentials_reset.add(acct)
        return ({"account": acct, "rotated": True},
                f"{acct} 凭据已强制轮换，原凭据立即失效。"
                f"请同步检查该凭据在配置文件/CI 变量中的引用，否则会出现大面积认证失败。")

    def _do_patch_vulnerability(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        host = self._require_host(args)
        cve = str(args["cve"])
        rec = {"host_id": host, "cve": cve, "service": args.get("service", ""), "at": time.time()}
        self.patches.append(rec)
        return ({"patched": rec},
                f"{host} 已针对 {cve} 应用修补"
                + (f"（服务 {args.get('service')}）" if args.get("service") else "")
                + "。补丁需重启服务才生效，请一并规划 restart_service（属 R 阶段）。")

    def _do_rebuild_host(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        host = self._require_host(args)
        image = str(args.get("image", "golden-image"))
        self.rebuilt.add(host)
        return ({"host_id": host, "image": image, "rebuilt": True},
                f"{host} 已从黄金镜像 {image} 重建。"
                f"⚠ 重建前必须已完成取证与证据归档，否则证据链断裂；"
                f"重建后需重新纳入监控并做完整性校验。")

    # ------------------------------------------------------------------ #
    #  R — 恢复
    # ------------------------------------------------------------------ #
    def _do_restore_from_backup(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        host = self._require_host(args)
        snap = str(args["snapshot_id"])
        rec = {"host_id": host, "snapshot_id": snap, "at": time.time()}
        self.restored.append(rec)
        return ({"restored": rec},
                f"{host} 已从 {snap} 恢复。恢复点之后的业务数据会丢失"
                f"（回滚窗口需与业务方确认）；恢复后必须 verify_integrity 并观察是否有再次失陷迹象。")

    def _do_restore_host(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        host = self._require_host(args)
        snap = str(args.get("snapshot_id", "latest"))
        self.restored.append({"host_id": host, "snapshot_id": snap, "at": time.time()})
        return ({"host_id": host, "snapshot_id": snap, "restored": True},
                f"{host} 已回滚到 {snap}。回滚**不会**自动移除持久化——"
                f"若恶意项在快照之前就存在，回滚后会再次出现。")

    def _do_restart_service(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        host = self._require_host(args)
        svc = str(args["service"])
        if svc not in RANGE_SERVICES:
            raise ExecutionFailed(f"{host} 上未发现服务 {svc}（可用：{', '.join(RANGE_SERVICES)}）")
        self.restarted.append({"host_id": host, "service": svc, "at": time.time()})
        return ({"host_id": host, "service": svc, "restarted": True},
                f"{host} 服务 {svc} 已重启。重启会短暂中断依赖该服务的业务，"
                f"请确认已过变更窗口审批。")

    def _do_lift_isolation(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        host = self._require_host(args)
        if host not in self.isolated:
            return ({"host_id": host, "isolated": False},
                    f"{host} 当前未处于隔离状态，无需解除（可能重复调用或对象记错）。")
        self.isolated.pop(host)
        return ({"host_id": host, "lifted": True},
                f"{host} 隔离已解除。解除前应确认：持久化已清除、凭据已轮换、"
                f"监控观察期内无再次外连。")

    def _do_verify_integrity(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        host = self._require_host(args)
        rng = self._rng(action)
        ok = rng.random() > 0.25
        arts = list(args.get("artifacts", []) or [])
        if not ok:
            return ({"host_id": host, "intact": False, "mismatches": ["/opt/app/lib/helper.so"]},
                    f"{host} 完整性校验**发现 1 处不匹配**：/opt/app/lib/helper.so。"
                    f"不得直接解除隔离，需先定位该差异来源。")
        return ({"host_id": host, "intact": True, "checked": arts or ["system-binaries", "service-libs"]},
                f"{host} 完整性校验通过（核对项：{', '.join(arts or ['system-binaries', 'service-libs'])}）。")

    # ------------------------------------------------------------------ #
    #  F — 复盘
    # ------------------------------------------------------------------ #
    def _do_archive_evidence(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        case_id = str(args["case_id"])
        arts = list(args["artifacts"])
        digest = _sha(f"{case_id}:{'-'.join(sorted(arts))}")
        rec = {"case_id": case_id, "artifacts": arts, "manifest_sha256": digest,
               "host_id": args.get("host_id", ""), "at": time.time()}
        self.evidence.append({"kind": "archive", **rec})
        return ({"archive": rec},
                f"证据链已归档（case={case_id}，{len(arts)} 项，manifest sha256={digest[:16]}…）。"
                f"归档是只读复核的基础，且应早于任何破坏性动作。")

    def _do_write_postmortem(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        case_id = str(args["case_id"])
        summary = str(args.get("summary", "")) or "（未提供摘要，需人工补全）"
        rec = {"case_id": case_id, "summary": summary, "at": time.time(),
               "path": f"postmortem/{case_id}.md"}
        self.postmortems.append(rec)
        return ({"postmortem": rec},
                f"复盘报告已生成 → {rec['path']}。内容应覆盖：根因、时间线、"
                f"检测盲区、处置有效性、改进项与责任人。")

    def _do_update_detection_rule(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        rid = str(args["rule_id"])
        rule = str(args["rule"])
        if rid not in RANGE_RULES:
            raise ExecutionFailed(
                f"未找到规则 {rid}（现有：{', '.join(sorted(RANGE_RULES))}）。"
                f"新增规则请使用规则库认可的 ID 命名。")
        rec = {"rule_id": rid, "rule": rule, "at": time.time(), "version": len(self.rule_updates) + 1}
        self.rule_updates.append(rec)
        return ({"rule_update": rec},
                f"检测规则 {rid}（{RANGE_RULES[rid]['title']}）已更新到 v{rec['version']}。"
                f"上线前必须用历史流量回放验证误报率，否则会淹没值班。")

    def _do_publish_ioc(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        ind = str(args["indicator"])
        ttl = int(args.get("ttl_seconds", 86400))
        self.published_iocs[ind] = {"ttl_seconds": ttl, "at": time.time()}
        return ({"indicator": ind, "ttl_seconds": ttl, "published": True},
                f"IOC {ind} 已登记并共享（TTL={ttl}s）。"
                f"共享前需确认该 IOC 已与本案遥测交叉验证——误报的 IOC 会污染整个情报面。")

    def _do_close_case(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        case_id = str(args["case_id"])
        verdict = str(args.get("verdict", "true_positive"))
        return ({"case_id": case_id, "verdict": verdict, "closed": True},
                f"工单 {case_id} 已关闭（判定={verdict}）。"
                f"关闭前确认：证据已归档、IOC 已登记、检测盲区已建改进项。")

    def _do_notify_analyst(self, action: Action, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        sev = str(args.get("severity", "MEDIUM"))
        return ({"severity": sev, "notified": True},
                f"已通知值班分析员（严重度={sev}）。通知内容应包含：资产、证据摘要、"
                f"已执行动作、待确认动作。")


def ctx_placeholder() -> str:
    """占位（collect_forensics 未传 case_id 时使用）。"""
    return "case-unspecified"
