#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""security/asset_inventory.py — 业务归属参考表 + 端点角色判定。

存在理由（对应隐蔽信道评测里暴露的三类失败）：

1. **分不清「源」**：模型把 `block_ip` 打到受害主机自己的 IP 上（实测 41.7%），
   把「本机 IP」当成「攻击源」。→ 本模块提供 `EndpointRoles`，从遥测文本里
   **确定性地**解析出「内网受影响主机 / 对端」，让准入闸门有据可依。

2. **认不出业务归属**：良性会议软件定长帧、浏览器抗量子 HTTPS、运维跳板机
   被当作隐蔽信道并封禁（误伤率最高 1.00）。→ 本模块提供
   `business_attribution_in()`，从遥测里抽出**已声明的业务归属**，
   并要求破坏性动作**显式反驳**它。

3. **事实性错误**：实测模型称 UDP **443** 为「非标准端口」。→ 提供
   `well_known_ports` 查表，供编造/事实检查器使用。

⚠ 定位：本表是**参考与准入依据**，不是绝对真相。真实环境应接 CMDB / 资产库 API。
`approved=True` 只说明「该进程是企业标准软件」，**不等于**该主机上的该进程一定无恶。
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security.sanitize import get_logger  # noqa: E402

LOG = get_logger("security.asset_inventory")

DEFAULT_PATH = PROJECT_ROOT / "data" / "assets.json"

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# 遥测里的「主机 X（A）与 B:port 之间存在…」
_HOST_IP_RE = re.compile(r"主机\s+(?P<host>[A-Za-z0-9][\w.\-]*)\s*[（(]\s*(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s*[)）]")
_PEER_RE = re.compile(r"与\s*(?P<ip>(?:\d{1,3}\.){3}\d{1,3})(?::(?P<port>\d{1,5}))?")


# --------------------------------------------------------------------------- #
#  端点角色
# --------------------------------------------------------------------------- #

@dataclass
class EndpointRoles:
    """从告警文本里解析出的端点角色（确定性，不依赖模型）。"""

    host: str = ""            # 内网受影响主机标识
    host_ip: str = ""         # 该主机 IP（**不得**作为封禁目标）
    peer_ip: str = ""         # 对端 IP（C2 / 业务对端，封禁应指向它）
    peer_port: int = 0
    conflicting: bool = False  # 解析结果自相矛盾（如 host_ip == peer_ip）

    def to_dict(self) -> Dict[str, Any]:
        return {"host": self.host, "host_ip": self.host_ip,
                "peer_ip": self.peer_ip, "peer_port": self.peer_port,
                "conflicting": self.conflicting}


def parse_endpoint_roles(alert: str) -> EndpointRoles:
    """从 NDR/EDR 告警文本解析「谁是本机、谁是对端」。

    只认明确句式；解析不出就返回空角色（**不猜**）——
    猜错会把准入闸门引向错误方向，比不判更糟。
    """
    roles = EndpointRoles()
    m = _HOST_IP_RE.search(alert or "")
    if m:
        roles.host = m.group("host")
        roles.host_ip = m.group("ip")
    pm = _PEER_RE.search(alert or "")
    if pm:
        roles.peer_ip = pm.group("ip")
        roles.peer_port = int(pm.group("port") or 0)
    if roles.host_ip and roles.peer_ip and roles.host_ip == roles.peer_ip:
        roles.conflicting = True
    return roles


# --------------------------------------------------------------------------- #
#  清单
# --------------------------------------------------------------------------- #

@dataclass
class Inventory:
    critical_assets: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    business_services: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    known_gateway_roles: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    well_known_ports: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    approved_processes_by_host_pattern: Dict[str, List[str]] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    # ---------------- 查表 ---------------- #

    def ip_to_asset(self, ip: str) -> Optional[Tuple[str, Dict[str, Any]]]:
        for name, meta in self.critical_assets.items():
            if meta.get("ip") == ip:
                return name, meta
        return None

    def lookup(self, asset: str) -> Dict[str, Any]:
        """`asset_lookup` 工具的查表实现：主机名 / IP / 角色 / 进程名都能查。"""
        key = (asset or "").strip()
        if not key:
            return {"found": False, "reason": "未提供查询目标"}
        low = key.lower()

        for name, meta in self.critical_assets.items():
            if low == name.lower() or low == str(meta.get("ip", "")).lower() \
                    or low in str(meta.get("role", "")).lower():
                return {"found": True, "kind": "critical_asset", "name": name, **meta}

        for proc, meta in self.business_services.items():
            if low == proc.lower():
                return {"found": True, "kind": "business_process", "name": proc, **meta}

        if key.isdigit():
            meta = self.well_known_ports.get(key)
            if meta:
                return {"found": True, "kind": "well_known_port", "port": int(key), **meta}
            return {"found": False, "kind": "port", "reason": "非常见端口（本身不代表可疑）"}

        if _IPV4_RE.fullmatch(key):
            hit = self.ip_to_asset(key)
            if hit:
                return {"found": True, "kind": "critical_asset", "name": hit[0], **hit[1]}
            return {"found": True, "kind": "unknown_ip",
                    "reason": "不在关键资产表内；IP 所属需由流量会话上下文判定，"
                              "不能据 IP 本身断定内外网"}

        return {"found": False, "reason": "清单中无此条目"}

    def approved_process(self, host: str, process: str) -> Optional[bool]:
        """该主机上这个进程是否属于企业标准软件。返回 None 表示主机模式未覆盖。"""
        for pat, procs in self.approved_processes_by_host_pattern.items():
            prefix = pat.rstrip("*")
            if host.lower().startswith(prefix.lower()):
                return process.lower() in {p.lower() for p in procs}
        return None

    def port_note(self, port: int) -> str:
        meta = self.well_known_ports.get(str(port))
        if not meta:
            return f"{port} 不在常见端口表内"
        return f"{port} 是标准 {meta['service']} 端口（{meta['note']}）"

    # ---------------- 业务归属识别 ---------------- #

    def business_attribution_in(self, text: str) -> List[str]:
        """从遥测文本里抽出**已声明的业务归属**证据。

        命中即表示「该流量已有业务解释」→ 破坏性动作必须显式反驳它。
        """
        text = text or ""
        low = text.lower()
        hits: List[str] = []

        for proc, meta in self.business_services.items():
            # ⚠ 只有 `approved=true` 的才算业务归属证据。
            #   清单里「已知但未获准」的进程（如 svchost.exe，需核对路径与签名）
            #   只说明它是系统常见名，**不构成**业务解释 —— 否则恶意用例只要套个
            #   常见进程名就能把闸门绕过去（这正是实测中 G4 误拒的根因）。
            if proc.lower() in low and meta.get("approved"):
                hits.append(f"进程 {proc} = {meta['justification']}")

        for role, meta in self.known_gateway_roles.items():
            for kw in meta["keywords"]:
                if kw.lower() in low:
                    hits.append(f"对端角色 {meta['keywords'][0]}（封禁后果：{meta['block_effect']}）")
                    break

        # 通用归属措辞：按长度降序，避免「企业白名单」与「命中企业白名单」重复命中
        generic = ("命中企业白名单", "已登记的日志源", "资产库已登记", "与 cmdb 一致",
                   "it 统一下发", "已注册系统服务", "备份窗口", "已配置的 ntp 服务器",
                   "为内部自研监控代理", "企业白名单")
        added = " ".join(hits).lower()
        for kw in sorted(generic, key=len, reverse=True):
            if kw.lower() in low and kw.lower() not in added:
                hits.append(f"归属声明：{kw}")
                added += " " + kw.lower()

        # 去重保序
        seen, out = set(), []
        for h in hits:
            if h not in seen:
                seen.add(h)
                out.append(h)
        return out

    def attribution_rebutted(self, answer: str) -> bool:
        """回答是否**显式反驳**了业务归属（而不是无视它）。"""
        a = answer or ""
        markers = ("但", "然而", "不过", "尽管如此", "尽管有", "虽有", "虽然",
                   "与业务归属不符", "不符合业务", "无法用业务解释", "不能用业务解释",
                   "异常于", "偏离基线", "业务解释不成立", "已排除业务")
        return any(m in a for m in markers)


_DEFAULT: Optional[Inventory] = None


def default_inventory(path: Optional[Path] = None) -> Inventory:
    """加载（并缓存）默认清单。缺失时返回空清单而不是崩溃。"""
    global _DEFAULT
    if path is None and _DEFAULT is not None:
        return _DEFAULT
    p = Path(path) if path else DEFAULT_PATH
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        LOG.warning("资产清单不存在: %s（将以空清单运行）", p)
        raw = {}
    except json.JSONDecodeError as exc:
        LOG.error("资产清单解析失败: %s（将以空清单运行）", exc)
        raw = {}
    inv = Inventory(
        critical_assets=raw.get("critical_assets", {}),
        business_services=raw.get("business_services", {}),
        known_gateway_roles=raw.get("known_gateway_roles", {}),
        well_known_ports=raw.get("well_known_ports", {}),
        approved_processes_by_host_pattern=raw.get("approved_processes_by_host_pattern", {}),
        notes=raw.get("notes", []),
    )
    if path is None:
        _DEFAULT = inv
    return inv


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="资产清单查询")
    ap.add_argument("--lookup", default=None)
    ap.add_argument("--roles", default=None, help="对一段告警文本解析端点角色")
    ap.add_argument("--attribution", default=None, help="抽出一段文本里的业务归属证据")
    args = ap.parse_args()
    inv = default_inventory()
    if args.lookup:
        print(json.dumps(inv.lookup(args.lookup), ensure_ascii=False, indent=2))
    if args.roles:
        print(json.dumps(parse_endpoint_roles(args.roles).to_dict(), ensure_ascii=False, indent=2))
    if args.attribution:
        print(json.dumps(inv.business_attribution_in(args.attribution), ensure_ascii=False, indent=2))
    if not any([args.lookup, args.roles, args.attribution]):
        print(f"关键资产 {len(inv.critical_assets)} / 业务进程 {len(inv.business_services)} / "
              f"网关角色 {len(inv.known_gateway_roles)} / 常见端口 {len(inv.well_known_ports)}")
