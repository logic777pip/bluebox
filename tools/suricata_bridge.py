"""PC 侧：消费树莓派 Suricata 的 Redis Stream → 归一化 → 关联 → AI 研判 → 通知/报告。

它在整个系统里的位置：
    树莓派（旁路镜像口 Suricata）──Redis Stream──► **本模块** ──► 现有 AI 研判栈
                                                        └─► files: logs/suricata_findings.jsonl

三个设计要点（都是刻意的）：

1) **复用同一套研判栈**，不另起一套打分/提示词。
   `security.confidence.assess()`、`net_sensor._triage()` 已经在本项目里被
   240 条用例和真实误报回放校准过。这里只是把"输入"从本机连接换成了报文级告警。
   如果另写一份，两边的口径会漂移，之前做的误报率优化就白做了。

2) **Suricata 的告警不是结论，是线索**。
   签名引擎在镜像口上一定会产生误报（策略类规则尤其明显）。所以本模块
   **不直接转发告警**，而是把它当成"值得研判的事件"，交给多维度置信度决定
   是弹通知（auto_attack）还是只记录（review/auto_benign）。

3) **和本机传感器做关联，这是两端同时运行的核心价值**：
   树莓派看到的是**报文**（什么签名命中、什么 SNI/域名/UA），
   本机看到的是**进程**（哪个程序在连）。两者都指向同一对端时，
   证据链才闭合 —— 单看任一侧都可能是误报。
   关联命中会把 `discriminator` 置位（"能推翻业务解释的反证"），
   这正是降低误报的关键维度（见 docs/FALSE_POSITIVE_REDUCTION.md）。

⚠ 关于 Redis 版本：Ubuntu 22.04 自带 Redis 6.0，**没有 XAUTOCLAIM**（6.2 才加）。
   所以遗留未确认事件的回收走 XPENDING(扩展) + XCLAIM。

用法：
    # 正常消费（推荐由计划任务/终端常驻）
    python tools/suricata_bridge.py --broker 192.168.1.50:6379 --llm --notify

    # 不需要模型，只看规则与关联（省资源）
    python tools/suricata_bridge.py --broker 192.168.1.50:6379 --no-llm --notify

    # 离线测试整条链路（不需要树莓派、不需要 Redis、不需要模型）
    python tools/suricata_bridge.py --replay raspi-ids/tests/eve-sample.jsonl --no-llm

    # 出报告
    python tools/suricata_bridge.py --report 2026-10-04
    python tools/suricata_bridge.py --selftest
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Sequence, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security.confidence import BenignProfile, assess          # noqa: E402
from tools.redis_lite import Redis, RedisError                 # noqa: E402
from tools.win_notify import notify                            # noqa: E402
# 复用本机传感器的限速队列 / 模型生命周期 / 研判解析，保证两边口径一致
from tools.net_sensor import LlmController, LlmQueue, _triage  # noqa: E402

LOG_DIR = PROJECT_ROOT / "logs"
REPORT_DIR = PROJECT_ROOT / "reports"
DEFAULT_OUT = LOG_DIR / "suricata_findings.jsonl"
DEFAULT_SENSOR_EVENTS = LOG_DIR / "net_sensor_events.jsonl"
DEFAULT_PROFILE = LOG_DIR / "benign_profile.json"
DEFAULT_STREAM = "suricata:eve"
DEFAULT_STATS_STREAM = "suricata:stats"
DEFAULT_GROUP = "blue-team-ai"

# ---------------------------------------------------------------- 打分模型

# Suricata severity -> 基础分（与本机传感器的 40 分满档口径对齐）
SEV_BASE = {1: 45, 2: 35, 3: 22}

# 类别加权：命中这些类别的签名通常指向真实入侵
CAT_HIGH = ("trojan", "exploit", "shellcode", "malware", "ransomware", "c2",
            "command-and-control", "command and control", "credential", "backdoor",
            "rootkit", "coinmining", "crypto-mining", "attempted-admin", "attempted-user",
            "web-application-attack", "sql_injection", "xss", "phishing", "exfiltration",
            "targeted-activity", "lateral", "data-theft", "spyware", "keylogger")
# 命中这些类别的多半是"违规/信息"而不是"入侵" —— 镜像口上误报的主要来源
CAT_LOW = ("policy", "protocol-command-decode", "not-suspicious", "informational",
           "bad-unknown", "generic-protocol", "potential-corporate-privacy-violation",
           "string-detect", "misc-activity", "unknown traffic")

HIGH_RISK_PORTS = {4444, 1337, 31337, 45560, 6667, 9050, 9150, 14444, 10808, 10809,
                   2052, 2053, 2082, 2086, 33899, 8443, 53}


def _norm(s: str) -> str:
    """把类别名归一化后再比较。

    踩过：Suricata 的 category 是**空格分词**的（"Potential Corporate Privacy Violation"、
    "A Network Trojan was detected"），而我一开始把关键词写成连字符形式
    （"potential-corporate-privacy-violation"），子串匹配永远不中 ——
    结果"降权低信噪类别"这个开关静默失效，而它恰恰是镜像口降误报的主要手段。
    所以两边都先去掉空格/连字符/下划线/斜杠，再来比。
    """
    return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()


CAT_HIGH_N = tuple(_norm(k) for k in CAT_HIGH)
CAT_LOW_N = tuple(_norm(k) for k in CAT_LOW)


def is_private(ip: str) -> bool:
    if not ip:
        return False
    if ip.startswith(("10.", "127.", "169.254.", "192.168.", "::1", "fe80")):
        return True
    if ip.startswith("172."):
        try:
            return 16 <= int(ip.split(".")[1]) <= 31
        except (ValueError, IndexError):
            return False
    return False


def score_alert(ev: Dict[str, str], correlated: bool = False,
                local_ips: Optional[set] = None) -> Tuple[int, List[str], str]:
    """把一条 Suricata 告警打成 0..70 的规则分，并给出可解释的规则名。

    刻意保持**廉价且可解释**：分数只用于决定"要不要占用模型配额"，
    真正的定性交给 AI 与多维度置信度。规则名会写进记录，便于事后回溯"为什么报这条"。
    """
    rules: List[str] = []
    try:
        sev = int(ev.get("severity") or 3)
    except ValueError:
        sev = 3
    score = SEV_BASE.get(sev, 22)
    rules.append(f"suricata_sev{sev}")

    cat = _norm(ev.get("category") or "")
    if cat and any(k in cat for k in CAT_HIGH_N):
        score += 8
        rules.append("category_high_signal")
    elif cat and any(k in cat for k in CAT_LOW_N):
        score -= 12
        rules.append("category_low_signal")

    src, dst = ev.get("src_ip", ""), ev.get("dest_ip", "")
    src_local = is_private(src) or (local_ips is not None and src in local_ips)
    dst_local = is_private(dst) or (local_ips is not None and dst in local_ips)
    if ev.get("direction") == "outbound" or (src_local and not dst_local):
        score += 5
        rules.append("egress_intranet_to_internet")
    elif src_local and dst_local:
        score += 8
        rules.append("lateral_intranet")
    elif dst_local and not src_local:
        rules.append("inbound_to_intranet")

    try:
        dport = int(ev.get("dest_port") or 0)
    except ValueError:
        dport = 0
    if dport in HIGH_RISK_PORTS and dport not in (53, 443, 8443):
        score += 5
        rules.append("high_risk_port")

    if correlated:
        score += 10
        rules.append("correlated_local_process")

    notes = [f"Suricata 规则：{ev.get('sig', '?')}（sid {ev.get('sig_id', '?')}）",
             f"类别：{ev.get('category', '未知')} 优先级：{sev}"]
    return max(0, min(70, score)), rules, "；".join(notes)


# ---------------------------------------------------------------- 应用层上下文

class CtxCache:
    """按 (ip, port) 缓存应用层事实（SNI / 域名 / UA / JA3），用于给告警补上下文。

    为什么需要：Suricata 的 alert 事件本身往往只有五元组和签名名。
    研判"这是不是真的 C2"时，**这条流用的什么 SNI、什么证书、什么 UA**
    才是可核验的事实（也是 AI 给出"区分性证据"的素材来源）。
    这些事实散落在 dns/tls/http 事件里，必须自己攒。
    """

    def __init__(self, ttl: float = 900.0, cap: int = 20000) -> None:
        self.ttl, self.cap = ttl, cap
        self.d: Dict[Tuple[str, int], Dict[str, Any]] = {}

    def add(self, ev: Dict[str, str]) -> None:
        ip, port = ev.get("dest_ip", ""), _int(ev.get("dest_port"))
        if not ip:
            return
        facts: Dict[str, Any] = {}
        for k in ("tls_sni", "tls_subject", "tls_issuerdn", "tls_ja3", "tls_version",
                  "http_hostname", "http_user_agent", "dns_rrname", "dns_rrtype",
                  "file_filename", "ssh_client", "ssh_server"):
            if ev.get(k):
                facts[k] = ev[k][:200]
        if not facts:
            return
        key = (ip, port)
        cur = self.d.setdefault(key, {})
        cur.update(facts)
        cur["_ts"] = time.time()
        if len(self.d) > self.cap:
            # 简单修剪：丢掉最旧的一批（不需要 LRU 那么讲究）
            old = sorted(self.d.items(), key=lambda kv: kv[1].get("_ts", 0))
            for k, _ in old[: len(old) // 4]:
                self.d.pop(k, None)

    def get(self, ip: str, port: int) -> Dict[str, Any]:
        f = self.d.get((ip, port))
        if not f:
            return {}
        if time.time() - f.get("_ts", 0) > self.ttl:
            return {}
        return {k: v for k, v in f.items() if not k.startswith("_")}


def _int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------- 告警文本

def build_prompt(ev: Dict[str, str], score: int, rules: Sequence[str],
                 ctx: Dict[str, Any], corr: Optional[Dict[str, Any]]) -> str:
    """把告警 + 应用层上下文 + 关联结果写成给模型的中文材料（只给可观测事实）。"""
    lines = [
        "[旁路镜像 IDS 告警] 报文级（树莓派 Suricata，镜像口被动采集）",
        f"时间：{ev.get('t', '?')}    探针：{ev.get('host', 'ids-pi')}",
        f"方向：{ev.get('direction') or '未知'}   协议：{ev.get('proto')}"
        f"{' / ' + ev['app_proto'] if ev.get('app_proto') else ''}",
        f"五元组：{ev.get('src_ip')}:{ev.get('src_port')} -> "
        f"{ev.get('dest_ip')}:{ev.get('dest_port')}",
        f"命中签名：{ev.get('sig')}（sid {ev.get('sig_id')}"
        f"{'，rev ' + ev['sig_rev'] if ev.get('sig_rev') else ''}）",
        f"类别：{ev.get('category')}    优先级：{ev.get('severity')}"
        f"    动作：{ev.get('action') or 'allowed'}",
        f"本地规则打分为 {score}（{'、'.join(rules)}）",
    ]
    if ev.get("flow_pkts_toserver") or ev.get("flow_bytes_toserver"):
        lines.append(f"流统计：发 {ev.get('flow_pkts_toserver', '?')} 包 / "
                     f"{ev.get('flow_bytes_toserver', '?')} 字节，"
                     f"收 {ev.get('flow_pkts_toclient', '?')} 包 / "
                     f"{ev.get('flow_bytes_toclient', '?')} 字节，"
                     f"状态 {ev.get('flow_state', '?')}")
    if ctx:
        lines.append("应用层事实（来自同期 dns/tls/http 事件）：")
        for k, v in list(ctx.items())[:8]:
            lines.append(f"  - {k} = {v}")
    else:
        lines.append("应用层事实：无（未捕获到同期的 dns/tls/http 事件）")
    if corr:
        lines.append(
            f"**本机关联命中**：本机传感器同期记录了 {corr.get('proc') or '?'}"
            f"（pid {corr.get('pid')}）到 {corr.get('remote')} 的连接，"
            f"本地得分 {corr.get('score')}，规则 {'、'.join(corr.get('rules') or [])}"
            f"（时间差 {corr.get('delta_s')}s）")
    else:
        lines.append("本机关联：无（本机传感器同期没有指向该对端的记录）")
    lines.append("")
    lines.append("说明：以上是**镜像口报文级告警**，没有载荷内容；"
                 "签名命中不代表攻击成功，签名引擎在镜像口上会有误报。"
                 "请据此研判该行为是否构成攻击，并给出建议动作（本系统只读，不会执行）。")
    return "\n".join(lines)


# ---------------------------------------------------------------- 关联

class SensorIndex:
    """跟踪本机传感器的事件文件，用于"报文级告警 ↔ 主机级进程"关联。

    为什么用文件跟随而不是 IPC：本机传感器已经在写
    logs/net_sensor_events.jsonl（并且是权威来源）。再开一条 IPC 会引入
    两个进程谁先起、谁挂了的问题，而读文件几乎零成本（只读新增的尾部）。
    """

    TS_FMT = "%Y-%m-%d %H:%M:%S"

    def __init__(self, path: Path, window: float = 120.0, keep: int = 5000) -> None:
        self.path, self.window = path, window
        self.recs: Deque[Dict[str, Any]] = deque(maxlen=keep)
        self._offset = 0
        self._ino = 0
        self._last_poll = 0.0
        self.read_errors = 0

    def poll_if_stale(self, max_age: float = 2.0) -> int:
        """需要时才刷新。

        为什么要这个：本机传感器文件原来只在主循环里 poll。
        一旦有人直接调 `handle()`（回放、测试、以后可能的队列 worker），
        索引就是空的，**关联会静默失效** —— 表现为"关联命中率恒为 0"，
        而且不报任何错。让刷新变成 handle 自己的责任就不会漏。
        """
        if time.time() - self._last_poll < max_age:
            return 0
        return self.poll()

    def poll(self) -> int:
        self._last_poll = time.time()
        if not self.path.exists():
            return 0
        added = 0
        try:
            st = self.path.stat()
            if st.st_ino != self._ino:          # 轮转/重建
                self._ino, self._offset = st.st_ino, 0
            if st.st_size < self._offset:
                self._offset = 0
            with self.path.open("r", encoding="utf-8", errors="replace") as fh:
                fh.seek(self._offset)
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    self.recs.append(rec)
                    added += 1
                self._offset = fh.tell()
        except OSError:
            self.read_errors += 1
        return added

    def match(self, ip: str, port: int, when: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """找本机同期指向 (ip, port) 的记录，返回最接近的一条。"""
        if not ip:
            return None
        now = when or time.time()
        best: Optional[Dict[str, Any]] = None
        best_delta = self.window + 1
        for rec in reversed(self.recs):
            remote = str(rec.get("remote") or "")
            if not remote.startswith(ip + ":") and not remote.startswith(ip):
                continue
            rport = _int(remote.split(":")[-1]) if ":" in remote else 0
            if port and rport and rport != port:
                continue
            delta = abs(self._ts(rec.get("ts")) - now)
            if delta <= self.window and delta < best_delta:
                best, best_delta = rec, delta
        if best is None:
            return None
        out = dict(best)
        out["delta_s"] = round(best_delta, 1)
        return out

    def _ts(self, s: Any) -> float:
        try:
            return time.mktime(time.strptime(str(s), self.TS_FMT))
        except (ValueError, TypeError):
            return 0.0


# ---------------------------------------------------------------- 统计快照

class StatsTracker:
    """跟踪探针的 stats 事件：**丢包率是判断这套装置能不能被信任的前提**。"""

    def __init__(self) -> None:
        self.last: Dict[str, str] = {}
        self.history: Deque[Dict[str, Any]] = deque(maxlen=200)
        self.warned = False

    def update(self, ev: Dict[str, str]) -> None:
        self.last = ev
        self.history.append({"t": time.time(), **ev})
        self.warned = False

    def drop_rate(self) -> Optional[float]:
        pk, dr = _int(self.last.get("cap_kernel_pkts")), _int(self.last.get("cap_kernel_drops"))
        if not pk:
            return None
        return dr / pk * 100.0

    def mbps(self) -> Optional[float]:
        up = float(self.last.get("uptime") or 0) or 0
        by = _int(self.last.get("dec_bytes"))
        if not up or not by:
            return None
        return by * 8 / up / 1e6

    def summary(self) -> str:
        if not self.last:
            return "未收到探针统计（探针没起来？或 stats 未启用）"
        rate = self.drop_rate()
        mb = self.mbps()
        return (f"探针 uptime {self.last.get('uptime', '?')}s，"
                f"内核收包 {_int(self.last.get('cap_kernel_pkts')):,}，"
                f"丢包 {_int(self.last.get('cap_kernel_drops')):,}"
                f"{f'（{rate:.4f}%）' if rate is not None else ''}，"
                f"平均采集 {mb:.2f} Mbps" if mb is not None else
                f"探针 uptime {self.last.get('uptime', '?')}s")


# ---------------------------------------------------------------- 主流程

def resolve_addr(args: argparse.Namespace) -> Tuple[str, int]:
    """把 --broker / --host / --port 归一化成 (host, port)。

    放在 Bridge 内部调用（而不只在 main 里）是因为：任何绕开 main 的构造路径
    （测试、脚本、别的模块 import）都会直接撞上 host=None，
    报的是 `int() argument must be ... not 'NoneType'` 这种看不出病因的错。
    """
    host, port = args.host, args.port
    if not host or not port:
        h, _, p = str(args.broker or "").partition(":")
        host = host or h or "127.0.0.1"
        port = port or _int(p, 6379)
    return str(host), int(port)


class Bridge:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        args.host, args.port = resolve_addr(args)
        self.log = _setup_logging(args.log_file)
        self.ctx = CtxCache()
        self.sensor = SensorIndex(Path(args.sensor_events), args.corr_window)
        self.stats = StatsTracker()
        self.queue = LlmQueue(cap=args.queue_cap)
        self.llm = LlmController(args.llm_port, args.ctx_size, args.ngl, args.idle_stop,
                                 autostart=not args.no_llm_autostart, lean=args.lean)
        self.profile = None if args.no_baseline else BenignProfile(
            Path(args.baseline) if args.baseline else DEFAULT_PROFILE)
        self.eve = Redis(args.host, args.port, args.password, args.db)
        self.stats_conn = Redis(args.host, args.port, args.password, args.db)
        self.last_seen: Dict[str, float] = {}
        self.llm_calls: Deque[float] = deque()
        self.ctr: Dict[str, int] = {
            "events": 0, "alerts": 0, "scored": 0, "below_threshold": 0, "cooldown": 0,
            "queued": 0, "triaged": 0, "deferred_done": 0, "correlated": 0,
            "reclaimed": 0, "ack_fail": 0, "route_auto_attack": 0, "route_review": 0,
            "route_auto_benign": 0, "notified": 0, "notify_suppressed": 0,
            "heuristic_hits": 0, "errors": 0, "spawn": 0,
        }
        self.out = Path(args.out)
        self.out.parent.mkdir(parents=True, exist_ok=True)
        # 离线回放时没有 Redis 可 ACK。不做这一步的话，每个事件都会去连一次
        # 并不存在的 127.0.0.1:6379，白等连接超时（实测每条事件多花数秒，
        # 整个回放从几百毫秒变成一分多钟）。
        self.ack_enabled = True

    # -- Redis 组 -------------------------------------------------
    def ensure_groups(self) -> None:
        for key, group in ((self.args.stream, self.args.group),
                           (self.args.stats_stream, self.args.group + "-stats")):
            try:
                created = self.eve.ensure_group(key, group)
                if created:
                    self.log.info("已创建消费组 %s / %s", group, key)
            except RedisError as exc:
                self.log.warning("创建消费组失败（%s/%s）：%s", group, key, exc)

    def reclaim(self) -> None:
        """回收上一次运行（崩溃/重启）遗留的未确认事件。

        ⚠ Redis 6.0（Ubuntu 22.04 自带）没有 XAUTOCLAIM，只能 XPENDING + XCLAIM。
        不回收的话，这些事件会永远挂着：既不会被处理，也不会被重新投递 ——
        表现为"某个时间点之后告警就少了"，极难发现。
        """
        for key, group in ((self.args.stream, self.args.group),
                           (self.args.stats_stream, self.args.group + "-stats")):
            try:
                pend = self.eve.pending_range(key, group, count=self.args.count)
            except RedisError:
                continue
            stale = [p["id"] for p in pend if p["idle_ms"] >= self.args.reclaim_idle * 1000]
            if not stale:
                continue
            ids = [p["id"] for p in pend if p["idle_ms"] >= 0]
            try:
                got = self.eve.xclaim(key, group, self.args.consumer, self.args.reclaim_idle * 1000,
                                      ids)
            except RedisError as exc:
                self.log.warning("回收遗留事件失败 %s：%s", key, exc)
                continue
            self.ctr["reclaimed"] += len(got)
            self.log.warning("回收了 %d 条遗留未确认事件（上一次运行没处理完）", len(got))
            for sid, fields in got:
                self.handle(fields, sid, ack_key=key, group=group)

    # -- 单事件处理 ------------------------------------------------
    def handle(self, ev: Dict[str, str], sid: str, ack_key: str, group: str) -> None:
        try:
            self.ctr["events"] += 1
            etype = ev.get("type") or ""
            if etype == "stats":
                self.stats.update(ev)
                return
            if etype == "banner":
                self.log.info("探针上线：%s（%s）", ev.get("host"), ev.get("msg"))
                return
            if etype in ("alert", "anomaly", "fileinfo"):
                self.handle_alert(ev, sid)
                return
            # dns/tls/http/ssh：只当上下文，不单独定性
            self.ctx.add(ev)
            self.maybe_heuristic(ev, sid)
        except Exception as exc:  # noqa: BLE001
            self.ctr["errors"] += 1
            self.log.warning("处理事件出错（%s）：%s", ev.get("type"), exc)
        finally:
            # 无论如何都要 ACK：否则毒消息会被反复投递，把队列堵死
            if self.ack_enabled:
                try:
                    self.eve.ack(ack_key, group, [sid])
                except RedisError:
                    self.ctr["ack_fail"] += 1

    def maybe_heuristic(self, ev: Dict[str, str], sid: str) -> None:
        """少数几个"无签名但形状可疑"的启发式。

        分数刻意压低（20~28），因为它们的可靠度远不如签名：
        自签证书在非标准端口在内网设备上很常见，长域名也不一定是隧道。
        所以设计成"**记录但不直接叫模型**"：低于阈值时照样写进 findings，
        以后做统计/回溯/TI 対照时看得到；只有叠上关联或其他规则才够格进 AI。
        早期版本在低于阈值时直接 return（连记录都没有），等于算了白算。
        """
        if not self.args.heuristics:
            return
        score, rules = 0, []
        if ev.get("type") == "dns":
            name = ev.get("dns_rrname") or ""
            longest = max((len(x) for x in name.split(".")), default=0)
            if longest >= 40:
                score, rules = 25, ["dns_very_long_label"]
            elif ev.get("dns_rrtype") in ("TXT", "NULL", "ANY") and len(name) > 60:
                score, rules = 22, ["dns_txt_long_name"]
        elif ev.get("type") == "tls":
            subj, iss = ev.get("tls_subject") or "", ev.get("tls_issuerdn") or ""
            dport = _int(ev.get("dest_port"))
            if subj and iss and subj == iss and dport not in (443, 8443):
                score, rules = 28, ["tls_selfsigned_nonstandard_port"]
        if score < self.args.heuristic_min:
            return
        self.ctr["heuristic_hits"] += 1
        self.process(ev, score, rules, None)

    def handle_alert(self, ev: Dict[str, str], sid: str) -> None:
        self.ctr["alerts"] += 1
        dst, dport = ev.get("dest_ip", ""), _int(ev.get("dest_port"))
        src, sport = ev.get("src_ip", ""), _int(ev.get("src_port"))

        # 关联：哪个方向是"本机"就按哪边找
        corr = None
        if self.args.correlate:
            # 先保证本机传感器索引是新的（见 poll_if_stale 的注释）
            self.sensor.poll_if_stale()
            local_side = None
            if is_private(dst):
                local_side = (dst, dport, time.time())
            if src and is_private(src) and not is_private(dst):
                local_side = (src, sport, time.time())
            if local_side:
                peer_ip = ev.get("dest_ip") if local_side[0] == src else src
                peer_port = dport if local_side[0] == src else sport
                corr = self.sensor.match(peer_ip, peer_port)
        if corr:
            self.ctr["correlated"] += 1

        score, rules, detail = score_alert(ev, correlated=bool(corr))
        self.process(ev, score, rules, corr, detail)

    def process(self, ev: Dict[str, str], score: int, rules: List[str],
                corr: Optional[Dict[str, Any]], detail: str = "") -> None:
        self.ctr["scored"] += 1
        if score < self.args.threshold:
            self.ctr["below_threshold"] += 1

        fp = f"{ev.get('sig_id') or ev.get('sig') or ev.get('type')}|{ev.get('src_ip')}|" \
             f"{ev.get('dest_ip')}|{ev.get('dest_port')}"
        now = time.time()
        if now - self.last_seen.get(fp, 0.0) < self.args.cooldown:
            self.ctr["cooldown"] += 1
            return
        self.last_seen[fp] = now

        ctx = self.ctx.get(ev.get("dest_ip", ""), _int(ev.get("dest_port")))
        rec: Dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "source": "suricata-mirror",
            "type": ev.get("type"),
            "sig": ev.get("sig"), "sid": ev.get("sig_id"), "category": ev.get("category"),
            "severity": ev.get("severity"), "app_proto": ev.get("app_proto"),
            "direction": ev.get("direction"), "proto": ev.get("proto"),
            "src": f"{ev.get('src_ip')}:{ev.get('src_port')}",
            "dest": f"{ev.get('dest_ip')}:{ev.get('dest_port')}",
            "score": score, "rules": rules, "detail": detail, "ctx": ctx,
            "correlated": bool(corr),
            "corr": ({k: corr.get(k) for k in ("ts", "proc", "pid", "remote", "score",
                                               "rules", "delta_s")} if corr else None),
        }
        self.log.info("[告警] score=%d %s -> %s  %s%s", score, ev.get("sig") or ev.get("type"),
                      rec["dest"], "关联命中 " if corr else "", "/".join(rules[:3]))

        if score < self.args.threshold:
            self._write(rec)
            return

        if self.args.llm:
            if self._allow_llm(now) and not self.queue:
                self._do_triage(rec, ev, ctx, corr)
            else:
                self.queue.push(score, (rec, ev, ctx, corr))
                self.ctr["queued"] += 1
                self._write(rec)
        else:
            self._write(rec)

    def _allow_llm(self, now: float) -> bool:
        while self.llm_calls and now - self.llm_calls[0] > 60:
            self.llm_calls.popleft()
        return len(self.llm_calls) < self.args.max_llm_per_min

    def _do_triage(self, rec: Dict[str, Any], ev: Dict[str, str], ctx: Dict[str, Any],
                   corr: Optional[Dict[str, Any]], deferred: bool = False) -> None:
        agent = self.llm.ensure()
        if agent is None:
            rec["triage"] = {"verdict": "skipped", "reason": "模型不可用"}
            self._write(rec)
            return
        self.llm_calls.append(time.time())
        self.ctr["triaged"] += 1
        rec["triage"] = _triage(agent, build_prompt(ev, rec["score"], rec["rules"], ctx, corr))
        if deferred:
            rec["triage"]["deferred"] = True
            self.ctr["deferred_done"] += 1
        v = rec["triage"].get("verdict")

        # 多维度置信度：关联命中作为 discriminator 的**充分条件之一**
        # （"报文侧签名 + 主机侧进程"同时成立，本身就是能推翻业务解释的反证）。
        conf = assess(
            rule_score=rec["score"], verdict=str(v),
            attack_strict=bool(rec["triage"].get("attack_strict")),
            hedged=bool(rec["triage"].get("hedged")),
            grounded_ok=bool(rec["triage"].get("grounded_ok", True)),
            discriminator=bool(rec["triage"].get("discriminator")) or bool(corr),
            contradictory=bool(rec["triage"].get("contradictory")),
            injection_flagged=bool(rec["triage"].get("injection_flagged")),
            signature="", baseline_hit=False,
            high_band=self.args.high_band, low_band=self.args.low_band)
        rec["confidence"] = conf.to_dict()
        rec["route"] = conf.route
        self.ctr["route_" + conf.route] = self.ctr.get("route_" + conf.route, 0) + 1
        self.log.info("    研判=%s 置信度=%.2f 路由=%s 关联=%s 耗时=%ss",
                      v, conf.score, conf.route, bool(corr), rec["triage"].get("latency_s"))
        self._write(rec)

        if (self.args.notify and conf.route == "auto_attack"
                and rec["score"] >= self.args.notify_min_score):
            actions = rec["triage"].get("actions") or "需人工复核"
            ok, channel = notify(
                f"IDS 告警：{rec['sig'] or rec['type']}",
                f"{rec['src']} → {rec['dest']}\n{actions}"
                f"{'（本机关联命中）' if corr else ''}",
                f"score {rec['score']} 置信度 {conf.score:.2f}")
            rec["notified"] = bool(ok)
            rec["notify_channel"] = channel
            if ok:
                self.ctr["notified"] += 1
        else:
            self.ctr["notify_suppressed"] += 1

    def _write(self, rec: Dict[str, Any]) -> None:
        with self.out.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    # -- 主循环 ---------------------------------------------------
    def loop(self) -> int:
        self.ensure_groups()
        self.reclaim()
        self.log.info("开始消费 %s（组 %s / 消费者 %s），阈值 %d，模型 %s，通知 %s",
                      self.args.stream, self.args.group, self.args.consumer,
                      self.args.threshold, "开" if self.args.llm else "关",
                      "开" if self.args.notify else "关")
        polls = 0
        last_hb = time.time()
        last_stats = 0.0
        while True:
            polls += 1
            try:
                self.sensor.poll()
                got = self.eve.read_group(self.args.group, self.args.consumer,
                                          [self.args.stream], count=self.args.count,
                                          block_ms=self.args.block_ms)
                for _stream, items in got.items():
                    for sid, fields in items:
                        self.handle(fields, sid, ack_key=self.args.stream, group=self.args.group)
            except RedisError as exc:
                self.ctr["errors"] += 1
                self.log.warning("Redis 读失败：%s（5s 后重试）", exc)
                time.sleep(5)
            except KeyboardInterrupt:
                self.log.info("收到中断，退出")
                break

            # 探针统计（不阻塞）
            if time.time() - last_stats > self.args.stats_interval:
                last_stats = time.time()
                try:
                    sg = self.stats_conn.read_group(self.args.group + "-stats", self.args.consumer,
                                                    [self.args.stats_stream],
                                                    count=32, block_ms=0)
                    for _s, items in sg.items():
                        for sid, fields in items:
                            self.stats.update(fields)
                            try:
                                self.stats_conn.ack(self.args.stats_stream,
                                                    self.args.group + "-stats", [sid])
                            except RedisError:
                                pass
                except RedisError:
                    pass

            # 配额恢复后补待办（**从高分开始**，与本机传感器一致）
            while self.args.llm and len(self.queue) and self._allow_llm(time.time()):
                item = self.queue.pop_best()
                if item:
                    self._do_triage(item[0], item[1], item[2], item[3], deferred=True)

            if self.args.llm:
                self.llm.maybe_stop()

            if self.args.once:
                break
            if self.args.heartbeat and polls % self.args.heartbeat == 0:
                self.heartbeat()
            if time.time() - last_hb > self.args.heartbeat_sec:
                last_hb = time.time()
                self.heartbeat()

        self.heartbeat()
        return 0

    def heartbeat(self) -> None:
        c = self.ctr
        lag = None
        try:
            xlen = self.eve.xlen(self.args.stream)
            pend = self.eve.pending_count(self.args.stream, self.args.group)
            lag = {"xlen": xlen, "pending": pend}
        except RedisError:
            pass
        rate = self.stats.drop_rate()
        warn = ""
        if rate is not None and rate > 0.1:
            warn = f"  ⚠ 探针丢包率 {rate:.3f}% —— 告警可能不全，先修采集"
        self.log.info(
            "心跳：事件 %d / 告警 %d / 超阈值 %d / 低于阈值 %d / 冷却跳过 %d / 队列 %d(补 %d) / "
            "研判 %d / 关联命中 %d / 回收 %d / 路由 告警%d 复核%d 静默%d（抑制通知 %d）/ "
            "启发式 %d / 错误 %d / 流 %s / %s%s",
            c["events"], c["alerts"], c["scored"] - c["below_threshold"], c["below_threshold"],
            c["cooldown"], len(self.queue), c["deferred_done"], c["triaged"], c["correlated"],
            c["reclaimed"], c["route_auto_attack"], c["route_review"], c["route_auto_benign"],
            c["notify_suppressed"], c["heuristic_hits"], c["errors"],
            lag or "?", self.stats.summary(), warn)


def _setup_logging(log_file: Optional[str]) -> Any:
    import logging
    logger = logging.getLogger("suricata_bridge")
    logger.setLevel(logging.INFO)
    if logger.handlers:
        return logger
    fmt = logging.Formatter("%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    if log_file:
        try:
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setFormatter(fmt)
            logger.addHandler(fh)
        except OSError:
            pass
    return logger


# ---------------------------------------------------------------- 离线回放 / 报告

def replay(args: argparse.Namespace, path: Path) -> int:
    """把一份 eve 格式文件跑完整条链路（不连 Redis、可选不连模型）。

    存在的意义：没有树莓派、没有 Redis 也能验证归一化、打分、关联、报告是否正确。
    """
    br = Bridge(args)
    br.ack_enabled = False          # 离线回放：没有 Redis 可 ACK（见 __init__ 注释）
    n = alerts = 0
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    for i, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        fields = _flatten(ev)
        if not fields.get("type"):
            continue
        n += 1
        if fields["type"] in ("alert", "anomaly", "fileinfo"):
            alerts += 1
        br.handle(fields, f"replay-{i}", ack_key=args.stream, group=args.group)
    br.log.info("回放完成：%d 条事件（其中告警 %d 条），%d 条记录写入 %s",
                n, alerts,
                sum(1 for _ in br.out.open(encoding="utf-8")) if br.out.exists() else 0,
                br.out)
    br.heartbeat()
    return 0


def _flatten(ev: Dict[str, Any]) -> Dict[str, str]:
    """把 Suricata 原始 eve JSON 压成与生产者输出一致的扁平字段。

    回放用的**独立实现**：故意不和生产者的 compact() 共用代码 ——
    否则生产者与消费者同时写错时，回放测试会一起通过（等于没测）。
    这里的规则来自 Suricata 官方 eve 格式文档。
    """
    out: Dict[str, str] = {}
    for k in ("timestamp", "event_type", "in_iface", "src_ip", "dest_ip", "proto",
              "app_proto", "pkt_src", "host", "flow_id", "direction"):
        if ev.get(k) is not None:
            out["t" if k == "timestamp" else ("type" if k == "event_type" else k)] = str(ev[k])
    for k in ("src_port", "dest_port"):
        if ev.get(k) is not None:
            out[k] = str(ev[k])
    al = ev.get("alert") or {}
    if al:
        out.update({"sig": str(al.get("signature") or ""), "sig_id": str(al.get("signature_id") or ""),
                    "category": str(al.get("category") or ""),
                    "severity": str(al.get("severity") or ""),
                    "action": str(al.get("action") or "")})
        if al.get("rev") is not None:
            out["sig_rev"] = str(al["rev"])
    fl = ev.get("flow") or {}
    for k in ("pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient", "state"):
        if fl.get(k) is not None:
            out[f"flow_{k}"] = str(fl[k])
    d = ev.get("dns") or {}
    for k in ("rrname", "rrtype", "type", "rcode"):
        if d.get(k) is not None:
            out[f"dns_{k}"] = str(d[k])[:200]
    tl = ev.get("tls") or {}
    for k in ("sni", "subject", "issuerdn", "version"):
        if tl.get(k):
            out[f"tls_{k}"] = str(tl[k])[:200]
    ja = tl.get("ja3")
    if isinstance(ja, dict) and ja.get("hash"):
        out["tls_ja3"] = str(ja["hash"])[:120]
    elif ja:
        out["tls_ja3"] = str(ja)[:120]
    h = ev.get("http") or {}
    for k in ("hostname", "url", "http_user_agent", "http_method", "status"):
        if h.get(k):
            out[f"http_{k}" if not k.startswith("http_") else k] = str(h[k])[:200]
    fi = ev.get("fileinfo") or {}
    for k in ("filename", "md5", "sha256", "size"):
        if fi.get(k):
            out[f"file_{k}"] = str(fi[k])[:200]
    an = ev.get("anomaly") or {}
    if an:
        out["j"] = json.dumps(an, ensure_ascii=False)[:800]
    st = ev.get("stats")
    if st is not None:
        cap = st.get("capture") or {}
        dec = st.get("decoder") or {}
        out.update({"cap_kernel_pkts": str(cap.get("kernel_packets") or 0),
                    "cap_kernel_drops": str(cap.get("kernel_drops") or 0),
                    "dec_pkts": str(dec.get("pkts") or 0),
                    "dec_bytes": str(dec.get("bytes") or 0),
                    "uptime": str(ev.get("uptime") or "")})
    return out


def report(args: argparse.Namespace, date: str) -> int:
    """生成 markdown 报告：覆盖情况 + 判定分布 + 需人工看的条目 + 关联命中。"""
    path = Path(args.out)
    if not path.exists():
        print(f"没有 {path}")
        return 1
    recs = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if str(r.get("ts", "")).startswith(date):
                recs.append(r)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    out = REPORT_DIR / f"suricata_{date}.md"
    triaged = [r for r in recs if (r.get("triage") or {}).get("verdict")
               not in (None, "skipped")]
    need = [r for r in recs if r.get("route") in ("auto_attack", "review")
            or (r.get("triage") or {}).get("verdict") == "attack"
            # `--no-llm` 模式下根本没有 triage，但超阈值的告警照样需要人看，
            # 否则"只记录"就变成"看不到"。
            or ((r.get("triage") or {}).get("verdict") in (None, "skipped")
                and (r.get("score") or 0) >= args.threshold)]
    corr = [r for r in recs if r.get("correlated")]

    lines = [
        f"# 旁路 IDS 检测报告（{date}）",
        "",
        f"> 数据来源：树莓派 4B 旁路镜像口 Suricata → Redis Stream `{args.stream}` → PC 侧 bridge",
        f"> 记录文件：`logs/suricata_findings.jsonl`（本报告只读它，不重新采集）",
        "",
        "## 1. 覆盖情况",
        "",
        f"- 记录条目：**{len(recs)}**",
        f"- 完成 AI 研判：**{len(triaged)}**",
        f"- **需人工复核：{len(need)}**",
        f"- 与本机进程关联命中：**{len(corr)}**",
        "",
    ]
    if recs:
        routes: Dict[str, int] = {}
        for r in recs:
            routes[r.get("route") or "未研判"] = routes.get(r.get("route") or "未研判", 0) + 1
        lines += ["| 路由 | 条数 |", "|---|---|"]
        for k, v in sorted(routes.items(), key=lambda kv: -kv[1]):
            lines.append(f"| {k} | {v} |")
        lines.append("")
        sigs: Dict[str, int] = {}
        for r in recs:
            sigs[str(r.get("sig") or r.get("type"))] = sigs.get(str(r.get("sig") or r.get("type")), 0) + 1
        lines += ["### 触发最多的签名", "", "| 签名 | 次数 |", "|---|---|"]
        for k, v in sorted(sigs.items(), key=lambda kv: -kv[1])[:15]:
            lines.append(f"| {k} | {v} |")
        lines.append("")

    lines += ["## 2. 需人工复核的条目", ""]
    if not need:
        lines.append("无。")
    else:
        lines += ["| 时间 | 签名 | 源 → 目的 | 分 | 置信度 | 路由 | 关联 | 模型判定 |",
                  "|---|---|---|---|---|---|---|---|"]
        for r in sorted(need, key=lambda x: -(x.get("score") or 0)):
            t = r.get("triage") or {}
            c = r.get("confidence") or {}
            lines.append(
                f"| {r.get('ts','')} | {(r.get('sig') or r.get('type') or '')[:48]} | "
                f"{r.get('src','')} → {r.get('dest','')} | {r.get('score')} | "
                f"{c.get('score','-')} | {r.get('route','-')} | "
                f"{'命中' if r.get('correlated') else '-'} | {t.get('verdict','-')} |")
        lines.append("")
        for r in sorted(need, key=lambda x: -(x.get("score") or 0))[:10]:
            t = r.get("triage") or {}
            c = r.get("confidence") or {}
            lines += [f"### {r.get('ts','')} {r.get('sig') or r.get('type')}", "",
                      f"- 五元组：`{r.get('src','')} → {r.get('dest','')}`（{r.get('proto','')}"
                      f"{' / ' + r['app_proto'] if r.get('app_proto') else ''}）",
                      f"- 本地分：{r.get('score')}（{'、'.join(r.get('rules') or [])}）",
                      f"- 置信度：{c.get('score')} → 路由 `{r.get('route')}`",
                      f"- 理由：{'；'.join(c.get('reasons') or []) or '无'}"]
            if r.get("ctx"):
                lines.append(f"- 应用层事实：`{json.dumps(r['ctx'], ensure_ascii=False)}`")
            if r.get("corr"):
                lines.append(f"- 本机关联：`{json.dumps(r['corr'], ensure_ascii=False)}`")
            if t.get("answer"):
                lines.append("")
                lines.append("模型回答：")
                lines.append("")
                lines.append("```")
                lines.append(str(t["answer"])[:1600])
                lines.append("```")
            lines.append("")

    lines += ["## 3. 关联命中（报文侧 + 主机侧证据闭合）", ""]
    if not corr:
        lines.append("无。")
    else:
        lines += ["| 时间 | 签名 | 对端 | 本机进程 | 关联时间差 |", "|---|---|---|---|---|"]
        for r in corr[:40]:
            cr = r.get("corr") or {}
            lines.append(f"| {r.get('ts','')} | {(r.get('sig') or '')[:40]} | {r.get('dest','')} | "
                         f"{cr.get('proc','?')}(pid {cr.get('pid','?')}) | {cr.get('delta_s','?')}s |")
        lines.append("")

    lines += [
        "## 4. 局限与前提（必须一起看）",
        "",
        "1. **丢包率决定可信度**：探针若丢包，告警就不全。bridge 心跳里会带丢包率，"
        "`raspi-ids/verify_pi.sh` 会单独检查。丢包率高时本报告的\"未发现\"不等于\"没有\"。",
        "2. **镜像口看不到加密内容**：TLS 流量只能靠 SNI/证书/JA3 与流特征判断，"
        "看不到内部指令。",
        "3. **签名引擎有误报**：本报告已经过多维置信度过滤，但 `review` 档仍需人工确认。",
        "4. **关联只覆盖本机**：其他内网主机之间的流量没有主机级进程证据，"
        "这类事件只做告警，不做自动定性。",
        "5. **只读**：本系统不阻断、不执行动作。所有建议动作都需要人工确认。",
        "",
    ]
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"已生成 {out}（{len(recs)} 条记录，{len(need)} 条需人工复核）")
    return 0


# ---------------------------------------------------------------- 自检

def selftest() -> int:
    ok = fail = 0

    def chk(name: str, cond: bool, extra: str = "") -> None:
        nonlocal ok, fail
        if cond:
            ok += 1
            print(f"  [OK] {name}")
        else:
            fail += 1
            print(f"  [FAIL] {name} {extra}")

    # --- 打分模型 ---
    hi, rules, _ = score_alert({"severity": "1", "category": "A Network Trojan was detected",
                                "src_ip": "10.0.0.5", "dest_ip": "45.1.2.3", "dest_port": "4444",
                                "sig": "ET TROJAN Cobalt Strike", "sig_id": "2024"})
    chk("高危告警得分高（>=45）", hi >= 45, str(hi))
    chk("高危规则可解释", "category_high_signal" in rules and "egress_intranet_to_internet" in rules,
        str(rules))
    lo, rules2, _ = score_alert({"severity": "3", "category": "Potential Corporate Privacy Violation",
                                 "src_ip": "10.0.0.5", "dest_ip": "10.0.0.9", "dest_port": "80"})
    chk("策略类低危得分低（<30）", lo < 30, str(lo))
    chk("低信噪类别被标记", "category_low_signal" in rules2, str(rules2))
    # 两种分隔符形式都必须命中（Suricata 用空格，文档/规则元数据里两种都见过）
    _, r_sp, _ = score_alert({"severity": "2", "category": "Misc activity"})
    chk("空格形式类别命中低信噪", "category_low_signal" in r_sp, str(r_sp))
    _, r_hy, _ = score_alert({"severity": "2", "category": "misc-activity"})
    chk("连字符形式类别命中低信噪", "category_low_signal" in r_hy, str(r_hy))
    _, r_hs, _ = score_alert({"severity": "2", "category": "A Network Trojan was detected"})
    chk("空格形式类别命中高信噪", "category_high_signal" in r_hs, str(r_hs))
    corr_hi, rules3, _ = score_alert({"severity": "2", "category": "Misc activity",
                                      "src_ip": "10.0.0.5", "dest_ip": "45.1.2.3",
                                      "dest_port": "8080"}, correlated=True)
    chk("关联命中加分且写规则", corr_hi > 35 and "correlated_local_process" in rules3,
        f"{corr_hi} {rules3}")
    chk("分数被封顶在 0..70",
        all(0 <= score_alert({"severity": str(s), "category": c})[0] <= 70
            for s in (1, 2, 3) for c in ("trojan", "policy", "")))

    # --- 上下文缓存 ---
    cc = CtxCache()
    cc.add({"dest_ip": "45.1.2.3", "dest_port": "443", "tls_sni": "c2.bad.tld"})
    cc.add({"dest_ip": "45.1.2.3", "dest_port": "443", "tls_ja3": "abc123"})
    chk("上下文按 (ip,port) 累积", cc.get("45.1.2.3", 443).get("tls_sni") == "c2.bad.tld"
        and cc.get("45.1.2.3", 443).get("tls_ja3") == "abc123")
    chk("上下文不串端口", cc.get("45.1.2.3", 80) == {})

    # --- 关联（用临时文件模拟本机传感器事件）---
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        ep = Path(td) / "ev.jsonl"
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        ep.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in [
            {"ts": now, "score": 40, "rules": ["high_risk_port"], "pid": 1234,
             "proc": "evil.exe", "remote": "45.1.2.3:4444"},
            {"ts": now, "score": 20, "rules": ["rare_port"], "pid": 99,
             "proc": "other.exe", "remote": "1.1.1.1:53"},
        ]) + "\n", encoding="utf-8")
        si = SensorIndex(ep, window=120)
        n = si.poll()
        chk("传感器事件被读入", n == 2, str(n))
        m = si.match("45.1.2.3", 4444)
        chk("关联命中同一对端", m is not None and m.get("proc") == "evil.exe", str(m))
        chk("关联带时间差", m is not None and "delta_s" in m)
        chk("不同对端不误关联", si.match("8.8.8.8", 53) is None)
        chk("端口不符不误关联", si.match("45.1.2.3", 9999) is None)
        chk("重复 poll 不重复读", si.poll() == 0)
        # 追加一行后应只读到新增的那行
        with ep.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": now, "score": 30, "pid": 7, "proc": "new.exe",
                                 "remote": "9.9.9.9:80"}) + "\n")
        chk("增量读取只读新增", si.poll() == 1)
        chk("新增记录可被关联", (si.match("9.9.9.9", 80) or {}).get("proc") == "new.exe")

    # --- 统计缺包率 ---
    st = StatsTracker()
    st.update({"cap_kernel_pkts": "1000000", "cap_kernel_drops": "250", "uptime": "600",
               "dec_bytes": "75000000"})
    chk("丢包率计算", abs((st.drop_rate() or 0) - 0.025) < 1e-6, str(st.drop_rate()))
    chk("采集速率计算", abs((st.mbps() or 0) - 1.0) < 1e-6, str(st.mbps()))

    # --- 两种归一化实现必须一致（防"两边同时写错"）---
    raw = {"timestamp": "t", "event_type": "alert", "src_ip": "10.0.0.5", "src_port": 1000,
           "dest_ip": "45.1.2.3", "dest_port": 4444, "proto": "TCP",
           "alert": {"signature": "ET TROJAN X", "signature_id": 1, "category": "c",
                     "severity": 1, "action": "allowed", "rev": 2},
           "flow": {"pkts_toserver": 3, "bytes_toserver": 300}}
    flat = _flatten(raw)
    chk("回放归一化：签名/端口/流统计都在",
        flat.get("type") == "alert" and flat.get("sig") == "ET TROJAN X"
        and flat.get("dest_port") == "4444" and flat.get("flow_pkts_toserver") == "3", str(flat))
    try:
        sys.path.insert(0, str(PROJECT_ROOT / "raspi-ids"))
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "prod", PROJECT_ROOT / "raspi-ids" / "suricata_redis_producer.py")
        prod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(prod)  # type: ignore[union-attr]
        pf = prod.compact(raw, prod.DEFAULT_FORWARD)
        same = (pf.get("type") == flat.get("type") and pf.get("sig") == flat.get("sig")
                and pf.get("dest_port") == flat.get("dest_port")
                and pf.get("flow_bytes_toserver") == flat.get("flow_bytes_toserver"))
        chk("生产者与回放的归一化结果一致（关键字段）", same, f"{pf} vs {flat}")
    except Exception as exc:  # noqa: BLE001
        chk("生产者与回放的归一化结果一致（关键字段）", False, f"无法加载生产者：{exc}")

    # --- 提示词只包含可观测事实 ---
    p = build_prompt({"t": "T", "src_ip": "10.0.0.5", "src_port": "1000", "dest_ip": "45.1.2.3",
                      "dest_port": "4444", "sig": "ET TROJAN X", "sig_id": "1",
                      "category": "c", "severity": "1", "proto": "TCP"},
                     55, ["suricata_sev1"], {"tls_sni": "c2.bad.tld"}, None)
    chk("提示词含签名与五元组", "ET TROJAN X" in p and "45.1.2.3:4444" in p)
    chk("提示词含应用层事实", "c2.bad.tld" in p)
    chk("提示词明确说明只读", "只读" in p)
    p2 = build_prompt({"sig": "x"}, 10, [], {}, {"proc": "evil.exe", "pid": 1,
                                                 "remote": "45.1.2.3:4444", "score": 40,
                                                 "rules": ["high_risk_port"], "delta_s": 3})
    chk("提示词含本机关联证据", "evil.exe" in p2 and "high_risk_port" in p2)

    print(f"\nsuricata_bridge 自检：{ok} 通过 / {fail} 失败")
    return 1 if fail else 0


# ---------------------------------------------------------------- CLI

def build_parser() -> argparse.ArgumentParser:
    """参数定义抽出来，便于端到端测试用**同一套**参数（避免测试与生产参数漂移）。"""
    ap = argparse.ArgumentParser(
        description="消费树莓派 Suricata 的 Redis Stream，做关联 + AI 研判 + 通知 + 报告")
    # Redis
    ap.add_argument("--broker", default="127.0.0.1:6379", help="Redis 地址（树莓派的 IP:端口）")
    ap.add_argument("--host", default=None)
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--password", default=os.environ.get("IDS_REDIS_PASSWORD", ""),
                    help="Redis 密码（默认读环境变量 IDS_REDIS_PASSWORD，避免写进命令行）")
    ap.add_argument("--db", type=int, default=0)
    ap.add_argument("--stream", default=DEFAULT_STREAM)
    ap.add_argument("--stats-stream", default=DEFAULT_STATS_STREAM)
    ap.add_argument("--group", default=DEFAULT_GROUP)
    ap.add_argument("--consumer", default=os.environ.get("COMPUTERNAME", "pc-bridge"))
    ap.add_argument("--count", type=int, default=32, help="单次拉取条数")
    ap.add_argument("--block-ms", type=int, default=5000, help="阻塞读超时（毫秒）")
    ap.add_argument("--stats-interval", type=float, default=30.0, help="读探针统计的间隔秒")
    ap.add_argument("--reclaim-idle", type=float, default=60.0,
                    help="回收空闲超过该秒数的遗留未确认事件（Redis 6.0 无 XAUTOCLAIM）")

    # 判定
    ap.add_argument("--threshold", type=int, default=30, help="触发 AI 的分值阈值")
    ap.add_argument("--cooldown", type=float, default=600.0, help="同一指纹报一次的间隔秒")
    ap.add_argument("--high-band", type=float, default=0.70)
    ap.add_argument("--low-band", type=float, default=0.40)
    ap.add_argument("--baseline", default=None)
    ap.add_argument("--no-baseline", action="store_true")
    ap.add_argument("--heuristics", dest="heuristics", action="store_true", default=True,
                    help="对无签名但形状可疑的 dns/tls 做低分启发式（默认开）")
    ap.add_argument("--no-heuristics", dest="heuristics", action="store_false")
    ap.add_argument("--heuristic-min", type=int, default=20,
                    help="启发式到达多少分才落盘（低于此分直接丢；默认 20）。"
                         "与 --threshold 的分工：落在 [heuristic-min, threshold) 的事件"
                         "会被记录但不会占用模型配额")

    # 关联
    ap.add_argument("--sensor-events", default=str(DEFAULT_SENSOR_EVENTS),
                    help="本机传感器事件文件（关联用）")
    ap.add_argument("--corr-window", type=float, default=120.0, help="关联时间窗（秒）")
    ap.add_argument("--correlate", dest="correlate", action="store_true", default=True)
    ap.add_argument("--no-correlate", dest="correlate", action="store_false")

    # 模型
    ap.add_argument("--llm", dest="llm", action="store_true", default=False,
                    help="对超阈值事件调用模型研判")
    ap.add_argument("--no-llm", dest="llm", action="store_false")
    ap.add_argument("--no-llm-autostart", action="store_true")
    ap.add_argument("--llm-port", type=int, default=8080)
    ap.add_argument("--ctx-size", type=int, default=4096, dest="ctx_size")
    ap.add_argument("--ngl", type=int, default=99)
    ap.add_argument("--lean", action="store_true", help="省资源档：关 RAG/工具层")
    ap.add_argument("--idle-stop", type=float, default=300.0)
    ap.add_argument("--max-llm-per-min", type=int, default=3)
    ap.add_argument("--queue-cap", type=int, default=50)

    # 通知与输出
    ap.add_argument("--notify", action="store_true", help="auto_attack 时弹 Windows 通知")
    ap.add_argument("--notify-min-score", type=int, default=40)
    ap.add_argument("--out", default=None,
                    help="记录文件。默认：实时消费写 logs/suricata_findings.jsonl，"
                         "--replay 写 logs/suricata_replay.jsonl"
                         "（分开是为了**不让回放数据污染线上证据文件**）")
    ap.add_argument("--log-file", default=str(LOG_DIR / "suricata_bridge.log"))
    ap.add_argument("--heartbeat", type=int, default=20, help="每多少次循环打一条心跳")
    ap.add_argument("--heartbeat-sec", type=float, default=120.0, help="心跳最长间隔秒")

    # 模式
    ap.add_argument("--once", action="store_true", help="只跑一轮就退出（测试用）")
    ap.add_argument("--replay", default="", help="回放一份 eve 格式文件，不连 Redis")
    ap.add_argument("--report", default="", help="生成指定日期的报告，如 2026-10-04")
    ap.add_argument("--selftest", action="store_true")
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()
    if not args.out:
        args.out = str(LOG_DIR / "suricata_replay.jsonl" if args.replay else DEFAULT_OUT)
    if args.report:
        return report(args, args.report)
    if args.replay:
        return replay(args, Path(args.replay))
    try:
        return Bridge(args).loop()
    except RedisError as exc:
        host, port = resolve_addr(args)
        print(f"连不上 Redis（{host}:{port}）：{exc}\n"
              f"检查点：树莓派上 redis-server 在跑吗？密码对吗（--password 或 "
              f"IDS_REDIS_PASSWORD）？防火墙放行 6379 了吗？", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
