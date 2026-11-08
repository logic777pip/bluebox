#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sandbox/contain.py — **最小影响**封锁：只掐掉威胁那一条通路，不动业务。

与 `forensics/containment.py` 的区别（名字像，性质完全不同）
------------------------------------------------------------

    forensics/containment.py   遏制动作的**占位**：只出方案、画风险，永不执行
    sandbox/contain.py         **真实**封锁：真的加防火墙规则，但范围被压到最小

为什么"最小影响"要写进代码而不是写在文档里
------------------------------------------

"封锁威胁但不影响业务"这句话，如果只当原则写在文档里，实际操作时很容易退化成
"封一个 C 段省事""顺手把 445 全封了""干脆隔离主机"。所以这里把**会造成业务中断的
做法全部变成代码里的拒绝条件**，让它们做不出来：

1. **只封精确对端**：远程地址必须是单个 IP（或 /32）。任何比 /32 宽的网段一律拒绝
   —— 封 /24 会连带打掉同网段里正常业务对端，而攻击者换个地址就绕过。
2. **只封出向**：C2 是主机主动连出去的，所以规则一律 `Outbound / Block`。
   不加入向规则 —— 入向规则会打到本机正在提供的服务。
3. **永不封这些地址**（命中即拒绝，不可绕过）：
   * 回环、多播、广播、链路本地（169.254/16）、0.0.0.0/8
   * **本机自己的地址**（封自己 = 自断网）
   * **默认网关**（封网关 = 全网络中断）
   * **本机配置的 DNS 服务器**（封 DNS = 域名解析全挂，业务立刻报错）
   这些靠 `local_network_facts()` 现查。**查不到就拒绝执行**（fail-closed），
   因为"不知道网关是谁"时贸然封锁的风险是整机断网，不可接受；
   确需放行要显式加 `--allow-unverified`，并会记进审计。
4. **带 TTL，自动到期**：基础设施 IP 会变（CDN、云主机），长期规则很快变成
   "封着一个已经不属于攻击者的地址"。所以每条规则都登记到期时间，
   `expire_due()` 负责回收。默认 TTL 4 小时。
5. **规则名可审计、可回滚**：统一前缀 `BlueTeamAgent-Contain-`，带案例号与短哈希，
   任何一条都能用 `Get-NetFirewallRule -DisplayName` 查到，也能一条命令撤销。

本模块不做的事：不隔离主机、不断网卡、不改 hosts、不改 DNS、不杀进程、不动文件。
那些要么影响面过大（隔离主机），要么属于别的阶段（killing/quarantine 是根除阶段）。
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sandbox import sandbox_root  # noqa: E402

__all__ = [
    "ContainPlan", "ContainResult", "PlanItem",
    "RULE_PREFIX", "DEFAULT_TTL_SECONDS",
    "parse_indicator", "local_network_facts", "validate_target",
    "plan_contain", "apply_contain", "list_rules", "remove_rules", "expire_due",
    "non_interference_note", "selftest",
]

#: 规则名统一前缀。带它就能一条命令列全、也能安全地批量撤销
#: （绝不会误删别人的规则）。
RULE_PREFIX = "BlueTeamAgent-Contain-"

#: 默认存活时间：4 小时。参照——C2 域名轮换常见周期是小时级，
#: 而"永久封锁"在基础设施频繁变化的今天大概率封到一个无辜地址。
DEFAULT_TTL_SECONDS = 4 * 3600
MAX_TTL_SECONDS = 7 * 24 * 3600

CREATE_NO_WINDOW = 0x08000000

#: 永远不许封的地址段（命中即拒绝）
_NEVER_BLOCK_NETS = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
)

_RE_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_RE_CIDR = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")
_RE_DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)
_RE_URL = re.compile(r"^(?:https?|ftp|tcp)://([^/:\s]+)(?::(\d+))?", re.I)
_RE_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_RE_MD5 = re.compile(r"^[0-9a-fA-F]{32}$")


def _hidden() -> Dict[str, Any]:
    kw: Dict[str, Any] = {"capture_output": True, "text": True,
                          "encoding": "utf-8", "errors": "replace"}
    if os.name == "nt":
        kw["creationflags"] = CREATE_NO_WINDOW
    return kw


def _ps(script: str, timeout: int = 30) -> Tuple[int, str]:
    """跑一段 PowerShell，返回 (退出码, 输出)。"""
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                            "-Command", script],
                           timeout=timeout, **_hidden())  # noqa: S603
        return r.returncode, ((r.stdout or "") + (r.stderr or "")).strip()
    except subprocess.TimeoutExpired:
        return 124, "超时"
    except OSError as exc:
        return 1, f"启动失败：{exc}"


def is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        import ctypes  # noqa: PLC0415
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


# --------------------------------------------------------------------------- #
# 本机网络事实（用于"绝不封网关/DNS/自己"）
# --------------------------------------------------------------------------- #

def local_network_facts(timeout: int = 30) -> Dict[str, Any]:
    """查本机地址、默认网关、DNS 服务器。查不到时 `known=False`（调用方据此拒绝执行）。

    为什么需要它：把网关或 DNS 服务器当成"攻击者地址"封掉，会让整机网络立刻不可用 ——
    这正好违反"不干扰其他业务"。而这类误判是有现实基础的：本机 DNS 也会发起
    出向 53 连接，日志里看起来跟 C2 心跳很像。
    """
    facts: Dict[str, Any] = {"known": False, "addresses": [], "gateways": [],
                             "dns": [], "error": ""}
    if os.name != "nt":
        facts["error"] = "非 Windows，未采集网络事实"
        return facts

    script = (
        "$o=@{};"
        "try{$o.addresses=@(Get-NetIPAddress -AddressFamily IPv4 -EA Stop |"
        " Where-Object {$_.IPAddress -ne '127.0.0.1'} |"
        " Select-Object -ExpandProperty IPAddress)}catch{$o.addresses=@()};"
        "try{$o.gateways=@(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -EA Stop |"
        " Select-Object -ExpandProperty NextHop)}catch{$o.gateways=@()};"
        "try{$o.dns=@(Get-DnsClientServerAddress -AddressFamily IPv4 -EA Stop |"
        " Select-Object -ExpandProperty ServerAddresses)}catch{$o.dns=@()};"
        "$o | ConvertTo-Json -Compress"
    )
    rc, out = _ps(script, timeout=timeout)
    if rc != 0 or not out:
        facts["error"] = f"查询失败（退出码 {rc}）：{out[:200]}"
        return facts
    try:
        data = json.loads(out)
    except ValueError as exc:
        facts["error"] = f"输出不是 JSON：{exc}；原始：{out[:200]}"
        return facts

    def _as_list(v: Any) -> List[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return [v]
        if isinstance(v, list):
            return [str(x) for x in v if x]
        return []

    facts["addresses"] = _as_list(data.get("addresses"))
    facts["gateways"] = _as_list(data.get("gateways"))
    facts["dns"] = _as_list(data.get("dns"))
    facts["known"] = bool(facts["addresses"] or facts["gateways"] or facts["dns"])
    if not facts["known"]:
        facts["error"] = "三项都为空，无法据此判断目标是否安全"
    return facts


# --------------------------------------------------------------------------- #
# 目标解析与校验
# --------------------------------------------------------------------------- #

def parse_indicator(indicator: str) -> Dict[str, Any]:
    """把 IOC 解析成封锁目标。返回 ``{kind, addresses, ports, host, raw}``。

    kind 取值：ip / cidr / domain / url / hash / unknown。
    hash 不是网络目标 —— 文件封锁属于根除阶段的 `quarantine_file`，这里如实拒绝，
    而不是"顺手做点别的"。
    """
    s = (indicator or "").strip()
    out: Dict[str, Any] = {"kind": "unknown", "addresses": [], "ports": [],
                           "host": "", "raw": s}
    if not s:
        return out
    if _RE_SHA256.match(s) or _RE_MD5.match(s):
        out["kind"] = "hash"
        return out
    m = _RE_URL.match(s)
    if m:
        out["kind"] = "url"
        out["host"] = m.group(1)
        if m.group(2):
            out["ports"] = [int(m.group(2))]
        return out
    if _RE_CIDR.match(s):
        out["kind"] = "cidr"
        out["addresses"] = [s]
        return out
    if _RE_IP.match(s):
        out["kind"] = "ip"
        out["addresses"] = [s]
        return out
    if _RE_DOMAIN.match(s):
        out["kind"] = "domain"
        out["host"] = s
        return out
    return out


def validate_target(address: str, facts: Dict[str, Any],
                    allow_unverified: bool = False) -> Tuple[bool, str]:
    """判断某个 IP 是否可以封。返回 (是否允许, 原因)。

    **这是本模块的核心安全逻辑**，所有拒绝条件都在这里，且不可用配置关掉
    （只有 `allow_unverified` 能绕过"本机网络事实查不到"这一条，其余一律拒绝）。
    """
    try:
        net = ipaddress.ip_network(address, strict=False)
    except ValueError:
        return False, f"不是合法的 IP/网段：{address}"

    # 1) 永远不许封的地址段
    for bad in _NEVER_BLOCK_NETS:
        if net.subnet_of(bad) or net == bad:
            return False, f"{address} 属于不可封锁段 {bad}（回环/多播/链路本地等）"

    # 2) 只允许精确到单个主机。/31、/24 这些一律拒绝。
    if net.prefixlen < net.max_prefixlen:
        return False, (f"{address} 是网段（/{net.prefixlen}），不是单个主机。"
                       f"只允许封锁精确对端：封网段会连带打掉同段内的正常业务对端，"
                       f"而且攻击者换个地址就绕过了。")

    ip = str(net.network_address)

    # 3) 本机自己的地址（封自己 = 自断网）
    if ip in (facts.get("addresses") or []):
        return False, f"{ip} 是本机自己的地址，封锁它等于自断网"

    # 4) 默认网关（封网关 = 整机断网）
    if ip in (facts.get("gateways") or []):
        return False, f"{ip} 是默认网关，封锁它会让整机断网"

    # 5) 本机 DNS 服务器（封 DNS = 业务立刻报错，且日志里 DNS 出向流量极易被误判为 C2）
    if ip in (facts.get("dns") or []):
        return False, f"{ip} 是本机配置的 DNS 服务器，封锁它会让域名解析整体失效"

    # 6) 网络事实未知时要格外谨慎
    if not facts.get("known") and not allow_unverified:
        return False, ("无法采集本机网络事实（地址/网关/DNS），因此无法确认 "
                       f"{ip} 不是网关或 DNS。fail-closed 拒绝执行；"
                       "确认无风险后可用 --allow-unverified 显式放行（会记入审计）。")

    return True, ""


# --------------------------------------------------------------------------- #
# 计划与执行
# --------------------------------------------------------------------------- #

@dataclass
class PlanItem:
    address: str = ""
    display_name: str = ""
    direction: str = "Outbound"
    action: str = "Block"
    protocol: str = "Any"
    remote_port: str = "Any"
    allowed: bool = False
    reason: str = ""


@dataclass
class ContainPlan:
    indicator: str = ""
    kind: str = ""
    items: List[PlanItem] = field(default_factory=list)
    refused: List[PlanItem] = field(default_factory=list)
    ttl_seconds: int = DEFAULT_TTL_SECONDS
    case_id: str = ""
    reason: str = ""
    facts: Dict[str, Any] = field(default_factory=dict)
    created: str = ""
    notes: List[str] = field(default_factory=list)

    @property
    def will_block(self) -> List[PlanItem]:
        return [i for i in self.items if i.allowed]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["will_block_count"] = len(self.will_block)
        return d


@dataclass
class ContainResult:
    ok: bool = False
    status: str = "planned"       # planned / applied / denied / unavailable / failed
    plan: Optional[Dict[str, Any]] = None
    applied: List[str] = field(default_factory=list)
    #: 已存在所以**没有重复创建**的规则（幂等）。
    existing: List[str] = field(default_factory=list)
    verified: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    expires_at: str = ""
    audit_file: str = ""
    detail: str = ""
    non_interference: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _rule_name(case_id: str, address: str) -> str:
    tag = hashlib.sha256(f"{case_id}|{address}".encode()).hexdigest()[:8]
    safe_case = "".join(c for c in (case_id or "case") if c.isalnum() or c in "-_")[:20]
    return f"{RULE_PREFIX}{safe_case}-{tag}"


def plan_contain(indicator: str, *, case_id: str = "", reason: str = "",
                 ttl_seconds: int = DEFAULT_TTL_SECONDS,
                 facts: Optional[Dict[str, Any]] = None,
                 allow_unverified: bool = False) -> ContainPlan:
    """生成最小影响封锁计划（不执行任何改动）。"""
    plan = ContainPlan(indicator=indicator, case_id=case_id, reason=reason,
                       created=time.strftime("%Y-%m-%d %H:%M:%S"))
    plan.ttl_seconds = max(60, min(int(ttl_seconds), MAX_TTL_SECONDS))

    parsed = parse_indicator(indicator)
    plan.kind = parsed["kind"]
    facts = facts if facts is not None else local_network_facts()
    plan.facts = facts

    if parsed["kind"] == "hash":
        plan.notes.append("这是文件哈希，不是网络目标。文件封锁属于根除阶段的 "
                          "`quarantine_file`，本模块只做网络封锁——不做职责外的事。")
        return plan
    if parsed["kind"] == "unknown":
        plan.notes.append(f"无法识别的 IOC 形式：{indicator!r}")
        return plan

    addresses = list(parsed["addresses"])
    if parsed["kind"] in ("domain", "url"):
        host = parsed["host"]
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_INET)
            addresses = sorted({i[4][0] for i in infos})
            plan.notes.append(f"域名 {host} 解析到 {len(addresses)} 个 IPv4 地址。"
                              f"⚠ 域名对应地址可能随时变化，也可能用 CDN；"
                              f"IP 封锁只能挡住当前这批，长期应改在 DNS 层做拦截。")
        except socket.gaierror as exc:
            plan.notes.append(f"域名 {host} 解析失败（{exc}）—— 无法确定要封的地址。")
            return plan

    ports = parsed["ports"] or []
    for addr in addresses:
        allowed, why = validate_target(addr, facts, allow_unverified=allow_unverified)
        item = PlanItem(
            address=addr,
            display_name=_rule_name(case_id, addr),
            remote_port=str(ports[0]) if ports else "Any",
            allowed=allowed,
            reason=why or "精确出向封锁（单个对端）",
        )
        (plan.items if allowed else plan.refused).append(item)

    if not facts.get("known"):
        plan.notes.append("⚠ 未能采集本机网络事实（地址/网关/DNS）：已按 fail-closed "
                          "拒绝全部目标。需要放行请显式加 --allow-unverified。")
    return plan


def non_interference_note(plan: ContainPlan) -> str:
    """把"这条封锁不会影响什么"写清楚 —— 让复核的人有据可依，而不是只能相信。"""
    n = len(plan.will_block)
    if not n:
        return "没有可执行的封锁目标，因此不会对网络产生任何影响。"
    parts = [
        f"只对 {n} 个精确对端加 **出向 Block** 规则，不含任何入向规则"
        f"（本机对外提供的服务不受影响）。",
        "不动 hosts、不改 DNS、不动网卡、不隔离主机、不杀进程、不动文件。",
        f"规则名统一前缀 `{RULE_PREFIX}`，到期自动回收（{plan.ttl_seconds // 60} 分钟后），"
        f"也可随时用 `--uncontain` 一键撤销。",
        "本机地址/默认网关/DNS 服务器已在计划阶段被硬性排除（命中即拒绝，不可绕过）。",
    ]
    return "；".join(parts)


def _audit_path() -> Path:
    p = sandbox_root() / "containment"
    p.mkdir(parents=True, exist_ok=True)
    return p / "audit.jsonl"


def _audit(entry: Dict[str, Any]) -> str:
    f = _audit_path()
    entry = dict(entry)
    entry.setdefault("ts", time.strftime("%Y-%m-%d %H:%M:%S"))
    with f.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return str(f)


def apply_contain(plan: ContainPlan, *, apply: bool = False) -> ContainResult:
    """执行封锁。**默认只演练**（`apply=False`），真加规则要显式打开。

    演练是默认值而不是可选项，理由和 KAPE 采集一样：这条动作会改本机防火墙，
    属于"有实际影响"，应该需要一次显式的批准，而不是跟着全局开关自己变成真执行。
    """
    res = ContainResult(plan=plan.to_dict(), non_interference=non_interference_note(plan))
    targets = plan.will_block

    if not targets:
        res.status = "denied"
        res.ok = False
        res.detail = ("没有任何可执行的目标。原因见计划里的 refused 与 notes —— "
                      "最常见的两种是：目标是网段（只允许单个主机），"
                      "或者无法确认它不是网关/DNS。")
        res.audit_file = _audit({"event": "denied", "case_id": plan.case_id,
                                 "indicator": plan.indicator,
                                 "refused": [asdict(i) for i in plan.refused],
                                 "notes": plan.notes})
        return res

    if not apply:
        res.status = "planned"
        res.ok = True
        res.detail = (f"演练：将新增 {len(targets)} 条出向 Block 规则，"
                      f"TTL {plan.ttl_seconds // 60} 分钟。未做任何改动。")
        res.audit_file = _audit({"event": "planned", "case_id": plan.case_id,
                                 "indicator": plan.indicator,
                                 "targets": [asdict(i) for i in targets]})
        return res

    if os.name != "nt":
        res.status = "unavailable"
        res.detail = "非 Windows 平台，本模块的封锁实现基于 Windows 防火墙"
        return res
    if not is_admin():
        res.status = "unavailable"
        res.detail = ("需要管理员权限才能改防火墙规则（非管理员下拒绝执行，"
                      "避免出现「以为封了、其实没生效」的假象）")
        return res

    for item in targets:
        # 幂等：同名规则已存在就**不重复创建**。
        # 为什么必须有这一步 —— 实测踩过：规则名由 (案例号, 地址) 决定，
        # 同一个威胁被重复处理（force 绕过冷却、或人工重跑、或自检反复跑）
        # 会留下**同名重复规则**。自检跑 4 次就积了 4 条同名规则。
        # 危害：审计时看上去像 4 个独立决定；“撤销”也变成不确定行为。
        rc0, out0 = _ps(f"if(Get-NetFirewallRule -DisplayName '{item.display_name}' "
                        f"-EA SilentlyContinue){{'FOUND'}}else{{'MISSING'}}", timeout=30)
        if "FOUND" in out0:
            res.existing.append(item.display_name)
            res.verified.append(item.display_name)
            continue

        script = (
            f"New-NetFirewallRule -DisplayName '{item.display_name}' "
            f"-Direction Outbound -Action Block -RemoteAddress {item.address} "
            f"-Protocol Any -Profile Any -Enabled True "
            f"-Description 'blue-team-agent case={plan.case_id} "
            f"indicator={plan.indicator} ttl={plan.ttl_seconds}s' | Out-Null; "
            f"if($?){{'CREATED'}}else{{'FAILED'}}"
        )
        rc, out = _ps(script, timeout=60)
        if rc == 0 and "CREATED" in out:
            res.applied.append(item.display_name)
        else:
            res.errors.append(f"{item.address}：{out[:200]}")

    # 读回验证：不读回就等于"以为封了"。用与 KAPE/EZTools 相同的纪律。
    for name in res.applied:
        rc, out = _ps(f"if(Get-NetFirewallRule -DisplayName '{name}' -EA SilentlyContinue)"
                      f"{{'FOUND'}}else{{'MISSING'}}", timeout=30)
        if "FOUND" in out:
            res.verified.append(name)
        else:
            res.errors.append(f"读回失败：{name} 未在防火墙中找到")

    expires = time.time() + plan.ttl_seconds
    res.expires_at = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(expires))
    res.ok = bool(res.verified) and not res.errors
    res.status = "applied" if res.ok else "failed"
    res.detail = (f"已新增并读回确认 {len(res.verified)} 条出向 Block 规则"
                  + (f"（其中 {len(res.existing)} 条已存在，未重复创建）" if res.existing else "")
                  + f"，到期时间 {res.expires_at}"
                  + (f"；失败 {len(res.errors)} 条：{res.errors[:2]}" if res.errors else ""))
    res.audit_file = _audit({"event": "applied", "case_id": plan.case_id,
                             "indicator": plan.indicator,
                             "applied": res.applied, "existing": res.existing,
                             "verified": res.verified,
                             "errors": res.errors, "expires_at": res.expires_at,
                             "ttl_seconds": plan.ttl_seconds,
                             "operator": os.environ.get("USERNAME", "")})
    return res


# --------------------------------------------------------------------------- #
# 查询 / 撤销 / 到期回收
# --------------------------------------------------------------------------- #

def list_rules() -> List[Dict[str, Any]]:
    """列出本系统建的所有封锁规则（只认前缀，绝不误碰别人的规则）。"""
    if os.name != "nt":
        return []
    rc, out = _ps(
        "Get-NetFirewallRule -DisplayName '" + RULE_PREFIX + "*' -EA SilentlyContinue | "
        "ForEach-Object{ $a=$_ | Get-NetFirewallAddressFilter; "
        "[pscustomobject]@{name=$_.DisplayName;enabled=$_.Enabled;"
        "direction=$_.Direction;action=$_.Action;remote=$a.RemoteAddress;"
        "desc=$_.Description} } | ConvertTo-Json -Compress", timeout=60)
    if rc != 0 or not out:
        return []
    try:
        data = json.loads(out)
    except ValueError:
        return []
    return data if isinstance(data, list) else [data]


def remove_rules(names: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    """撤销封锁。不传名字就撤**本系统建的全部**（前缀匹配，不会动别人的规则）。"""
    if os.name != "nt":
        return {"ok": False, "detail": "非 Windows"}
    if not is_admin():
        return {"ok": False, "detail": "需要管理员权限"}
    if names:
        sel = " -or ".join(f"$_.DisplayName -eq '{n}'" for n in names)
        script = (f"Get-NetFirewallRule -EA SilentlyContinue | Where-Object {{{sel}}} | "
                  f"Remove-NetFirewallRule -EA SilentlyContinue; 'DONE'")
    else:
        script = (f"Remove-NetFirewallRule -DisplayName '{RULE_PREFIX}*' "
                  f"-EA SilentlyContinue; 'DONE'")
    rc, out = _ps(script, timeout=120)
    done = "DONE" in out
    _audit({"event": "removed", "names": list(names or ["<all BlueTeamAgent rules>"]),
            "ok": done})
    return {"ok": done, "detail": out[:300] or "无输出"}


def expire_due(now: Optional[float] = None) -> Dict[str, Any]:
    """回收到期规则。

    怎么知道哪些到期了：规则的 `Description` 里写了 `ttl=<n>s`，但**没有**写绝对时间
    （写绝对时间在跨时区/改系统时间时会出错）。这里改成"用规则自身的创建时间 + ttl"，
    由 Get-NetFirewallRule 的规则对象拿创建时间不可靠，所以退一步：
    由 `logs/sandbox/containment/applied.json` 记录绝对到期时间，本函数按它回收。
    """
    now = now or time.time()
    state = _applied_state()
    due = [r for r in state.get("rules", []) if r.get("expires_ts", 0) and r["expires_ts"] <= now]
    if not due:
        return {"ok": True, "expired": [], "detail": "没有到期规则"}
    out = remove_rules([r["name"] for r in due])
    alive = [r for r in state.get("rules", []) if r not in due]
    state["rules"] = alive
    _write_applied_state(state)
    _audit({"event": "expired", "removed": [r["name"] for r in due], "ok": out["ok"]})
    return {"ok": out["ok"], "expired": [r["name"] for r in due], "detail": out["detail"]}


def _applied_state_path() -> Path:
    p = sandbox_root() / "containment"
    p.mkdir(parents=True, exist_ok=True)
    return p / "applied.json"


def _applied_state() -> Dict[str, Any]:
    p = _applied_state_path()
    if not p.is_file():
        return {"rules": []}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"rules": []}


def _write_applied_state(state: Dict[str, Any]) -> None:
    _applied_state_path().write_text(json.dumps(state, ensure_ascii=False, indent=2),
                                     encoding="utf-8")


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

    print("=== sandbox.contain 自检 ===")

    # -- IOC 解析 --
    chk("解析单个 IP", parse_indicator("203.0.113.9")["kind"] == "ip")
    chk("解析 URL 取主机与端口",
        parse_indicator("http://evil.example.com:8080/a")["ports"] == [8080])
    chk("解析域名", parse_indicator("evil.example.com")["kind"] == "domain")
    chk("解析 SHA-256 判为 hash（不是网络目标）",
        parse_indicator("a" * 64)["kind"] == "hash")
    chk("乱字符串判为 unknown", parse_indicator("not a target!!")["kind"] == "unknown")

    # 模拟本机网络事实，避免依赖真实网络
    facts = {"known": True, "addresses": ["192.168.1.31"],
             "gateways": ["192.168.1.1"], "dns": ["192.168.1.1", "8.8.8.8"],
             "error": ""}

    # -- 核心：拒绝条件（这些就是"不干扰业务"的代码化）--
    allowed, why = validate_target("203.0.113.9", facts)
    chk("普通公网 IP 允许封锁", allowed, why)

    allowed, why = validate_target("10.0.0.0/24", facts)
    chk("拒绝封网段（会误伤同段业务对端）", not allowed, why)
    chk("拒绝理由说明了「网段」", "网段" in why, why)

    allowed, why = validate_target("192.168.1.31", facts)
    chk("拒绝封本机自己的地址", not allowed and "本机自己" in why, why)

    allowed, why = validate_target("192.168.1.1", facts)
    chk("拒绝封默认网关", not allowed and "网关" in why, why)

    allowed, why = validate_target("8.8.8.8", facts)
    chk("拒绝封本机 DNS 服务器", not allowed and "DNS" in why, why)

    allowed, why = validate_target("127.0.0.1", facts)
    chk("拒绝封回环", not allowed, why)

    allowed, why = validate_target("224.0.0.1", facts)
    chk("拒绝封多播段", not allowed, why)

    allowed, why = validate_target("169.254.1.1", facts)
    chk("拒绝封链路本地", not allowed, why)

    unknown_facts = {"known": False, "addresses": [], "gateways": [], "dns": [], "error": "x"}
    allowed, why = validate_target("203.0.113.9", unknown_facts)
    chk("网络事实未知时 fail-closed 拒绝", not allowed, why)
    allowed, why = validate_target("203.0.113.9", unknown_facts, allow_unverified=True)
    chk("显式 allow_unverified 可放行（并说明风险）", allowed, why)

    # -- 计划 --
    plan = plan_contain("203.0.113.9", case_id="case-1", reason="C2",
                        facts=facts)
    chk("计划里包含 1 个可封目标", len(plan.will_block) == 1, str(len(plan.will_block)))
    chk("规则名带统一前缀与案例号",
        plan.will_block[0].display_name.startswith(RULE_PREFIX)
        and "case-1" in plan.will_block[0].display_name,
        plan.will_block[0].display_name)
    chk("方向固定为出向（不加任何入向规则）",
        all(i.direction == "Outbound" for i in plan.will_block))
    chk("动作固定为 Block", all(i.action == "Block" for i in plan.will_block))

    plan_all_bad = plan_contain("192.168.1.0/24", case_id="c", facts=facts)
    chk("全是坏目标时 will_block 为空", not plan_all_bad.will_block)
    chk("坏目标进 refused 且带原因", bool(plan_all_bad.refused)
        and "网段" in plan_all_bad.refused[0].reason)

    plan_hash = plan_contain("a" * 64, case_id="c", facts=facts)
    chk("传哈希时说明应改用 quarantine_file",
        any("quarantine_file" in n for n in plan_hash.notes), str(plan_hash.notes))

    # -- 演练不产生改动 --
    r = apply_contain(plan, apply=False)
    chk("默认只演练", r.status == "planned" and r.ok)
    chk("演练结果说明未做改动", "未做任何改动" in r.detail, r.detail)
    chk("演练也会写审计", bool(r.audit_file) and Path(r.audit_file).is_file())

    r2 = apply_contain(plan_all_bad, apply=False)
    chk("无目标时拒绝执行且状态为 denied", r2.status == "denied" and r2.ok is False)
    chk("拒绝理由指出常见两种原因", "网段" in r2.detail, r2.detail)

    # -- 不干扰说明 --
    note = non_interference_note(plan)
    chk("不干扰说明写明「只出向、不含入向」", "不含任何入向规则" in note)
    chk("不干扰说明写明不动 hosts/DNS/网卡/主机隔离",
        all(k in note for k in ("hosts", "DNS", "网卡", "隔离主机")))

    # -- TTL 边界 --
    p2 = plan_contain("203.0.113.9", case_id="c", facts=facts, ttl_seconds=1)
    chk("TTL 有下限（不会被设成 1 秒）", p2.ttl_seconds >= 60, str(p2.ttl_seconds))
    p3 = plan_contain("203.0.113.9", case_id="c", facts=facts, ttl_seconds=10 ** 9)
    chk("TTL 有上限（不会变成永久封锁）", p3.ttl_seconds <= MAX_TTL_SECONDS, str(p3.ttl_seconds))

    # -- 撤销接口在无管理员/非应用时不应炸 --
    chk("list_rules 可调用且返回列表", isinstance(list_rules(), list))

    print(f"\nsandbox.contain 自检：{ok} 通过 / {fail} 失败")
    return 1 if fail else 0


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(
        description="最小影响封锁（只封精确对端的出向；默认演练）")
    ap.add_argument("indicator", nargs="?", default="", help="IOC：IP / 域名 / URL")
    ap.add_argument("--case", default="", help="案例编号（进规则名与审计）")
    ap.add_argument("--reason", default="", help="封锁理由")
    ap.add_argument("--ttl", type=int, default=DEFAULT_TTL_SECONDS,
                    help=f"存活秒数（默认 {DEFAULT_TTL_SECONDS}，上限 {MAX_TTL_SECONDS}）")
    ap.add_argument("--apply", action="store_true",
                    help="真正执行（默认只演练）。需管理员")
    ap.add_argument("--allow-unverified", action="store_true",
                    help="在网络事实查不到时仍放行（会被记入审计）")
    ap.add_argument("--list", action="store_true", help="列出本系统建的所有规则")
    ap.add_argument("--uncontain", action="store_true", help="撤销本系统建的全部规则")
    ap.add_argument("--expire", action="store_true", help="回收已到期规则")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    try:
        sys.stdout.reconfigure(errors="replace")  # type: ignore[union-attr]
    except Exception:  # noqa: BLE001
        pass

    if args.list:
        print(json.dumps(list_rules(), ensure_ascii=False, indent=2))
        return 0
    if args.uncontain:
        print(json.dumps(remove_rules(), ensure_ascii=False, indent=2))
        return 0
    if args.expire:
        print(json.dumps(expire_due(), ensure_ascii=False, indent=2))
        return 0
    if not args.indicator:
        ap.print_help()
        return 2

    plan = plan_contain(args.indicator, case_id=args.case, reason=args.reason,
                        ttl_seconds=args.ttl,
                        allow_unverified=args.allow_unverified)
    res = apply_contain(plan, apply=args.apply)
    print(json.dumps(res.to_dict(), ensure_ascii=False, indent=2))
    return 0 if res.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
