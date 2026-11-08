#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/net_sensor.py — 本机进出流量的**连接级**监控 + LLM 研判 + Windows 通知。

能力边界（务必先读）
--------------------
**本工具能看到什么**：本机**全部** TCP/UDP 端点与活动连接的**五元组 + 所属进程**
（协议、本地地址端口、远端地址端口、状态、PID、进程名/路径）。
这是「所有进出流量」在**连接元数据**层面上的全覆盖。

**本工具看不到什么**：报文**载荷**。抓取载荷需要内核驱动（Npcap/WFP callout），
本项目栈里没有、也不应该悄悄装。而且即使抓到，把一个 3B 模型挂在报文流上
在工程上是荒谬的（见下面的资源账）。

**为什么不能对每条流量都调模型**（用本项目实测数据说话）：
* 单次研判约 **2.5 秒**、**约 2200 prompt + 400 completion token**；
* 240 次请求后 llama-server 工作集从 2.25GB 涨到 **9.5~10.5GB**（约 35MB/请求）；
* 常驻显存 **2.2GB**（本机 8GB，且 Ollama 已占 5.5GB）。

假设平均每秒 20 个新连接，若每条都研判：**50 倍算力不足 + 内存几分钟内打满**。
所以架构必须是「**廉价规则先筛，可疑事件才上模型**」：

    netstat 采样(15s)  ->  本地规则打分(零成本)  ->  去重/冷却/限速
                                                     |
                                    仅 score >= 阈值才入队 → LLM 研判(按需启动)
                                                     |
                                        判定 attack → Windows 通知

资源控制（默认值即「尽量省」）
----------------------------
* 传感器本身是纯 Python 轮询，无 GPU、无 LLM，常驻内存约 30MB；
* `--llm on-demand`（默认）：**没有可疑事件时 llama-server 完全不启动，显存占用 0**；
  事件到达才拉起，空闲 `--idle-stop` 秒后自动停止；
* 每分钟最多 `--max-llm-per-min` 次研判、同一事件指纹 `--cooldown` 秒内只报一次；
* 只在 `--notify-min-score` 以上才弹通知，避免刷屏。

用法::

    python tools/net_sensor.py --once                 # 采一次，打印发现，不调模型
    python tools/net_sensor.py --once --llm           # 采一次并让模型研判
    python tools/net_sensor.py --loop --notify        # 常驻 + 弹窗（开机自启用这个）
    python tools/net_sensor.py --selftest             # 规则自检
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Sequence, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security.confidence import BASELINE_MIN_HITS, BenignProfile, assess  # noqa: E402
from security.sanitize import get_logger  # noqa: E402

DEFAULT_PROFILE_PATH = PROJECT_ROOT / "logs" / "benign_profile.json"
from tools.win_notify import notify  # noqa: E402

try:
    from tools import win_net  # noqa: E402
    _HAVE_WIN_NET = win_net.available()
except Exception:  # noqa: BLE001
    win_net = None  # type: ignore[assignment]
    _HAVE_WIN_NET = False

# 屏幕不停闪黑框的根因：pythonw.exe（无控制台）spawn 控制台程序时，
# Windows 会为子进程**新建一个控制台窗口**。两条对策：
#  1. 主路径改用 ctypes 直读 API（tools/win_net.py）—— 不 spawn 任何进程；
#  2. 仍然必须 spawn 的场景（拉起 llama-server、发通知）一律加 CREATE_NO_WINDOW。
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_STARTUPINFO = None
if os.name == "nt":
    _STARTUPINFO = subprocess.STARTUPINFO()
    _STARTUPINFO.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    _STARTUPINFO.wShowWindow = 0  # SW_HIDE

# 子进程调用计数：心跳里会报出来。修好之后轮询路径应当恒为 0，
# 这就是“不会再弹终端”的可验证证据。
SPAWN_COUNT = 0


def _signature_status(path: str) -> Any:
    """凭证签名查询（仅对非常规目录新进程调用，结果带缓存）。"""
    from tools.proc_watch import signature_status  # noqa: PLC0415
    return signature_status(path)


def _hidden_kwargs() -> Dict[str, Any]:
    """给子进程加隐藏窗口标志（双保险：creationflags + STARTUPINFO）。"""
    global SPAWN_COUNT
    SPAWN_COUNT += 1
    kw: Dict[str, Any] = {"capture_output": True, "text": True,
                          "encoding": "utf-8", "errors": "replace"}
    if os.name == "nt":
        kw["creationflags"] = _NO_WINDOW
        if _STARTUPINFO is not None:
            kw["startupinfo"] = _STARTUPINFO
    return kw

LOG = get_logger("tools.net_sensor")

# 允许的常见出站端口（命中这些不带分值）
BENIGN_PORTS = {
    53, 80, 443, 123, 853, 8080, 8443, 993, 995, 587, 465, 110, 143, 25,
    67, 68, 137, 138, 139, 445, 3389, 5985, 5986, 22, 21, 990, 1723, 500, 4500,
}
# 高风险端口：单独命中就足以触发（这些端口几乎只出现在远控/矿池/匿名网络场景）
HIGH_RISK_PORTS = {4444, 1337, 31337, 45560, 6667, 9050, 9150, 14444, 10808, 10809}
# 弱可疑端口：**不能单独定调**。3333/5555/8888 这类被大量正常工具占用
# （实测：VS Code 就会连 3333，最初给 30 分直接造成误报并浪费一次模型调用）。
SOFT_PORT_HINTS = {3333, 4444, 5555, 6666, 7777, 8888, 9999, 4443, 2052, 2053,
                   2082, 2086, 31337, 33899, 6667}
# 进程路径里出现这些片段 = 可执行文件落在非常规位置（加分）
SUSPECT_PATH_HINTS = ("\\temp\\", "\\tmp\\", "\\downloads\\", "\\public\\",
                      "\\programdata\\", "\\appdata\\local\\temp",
                      "\\recycle", "\\users\\public")
# 系统/正规安装目录（命中则**衰减**分值）
TRUSTED_PATH_HINTS = ("\\windows\\system32", "\\windows\\syswow64",
                      "\\program files\\", "\\program files (x86)\\")

_RULE_BASE = {"high_risk_port": 40, "soft_port": 15, "suspect_path": 40,
              "port_fanout": 25, "periodic_beacon": 35, "intranet_lateral": 30,
              "conn_burst": 20, "rare_port": 10,
              # 由**进程创建事件**（事件驱动）触发的规则，不依赖它是否外连
              "proc_from_suspect_dir": 40}
# 命中 ≥2 条不同规则时的组合加成（单条弱信号变强信号）
_COMBO_BONUS = 15
# 进程位于正规安装目录时的衰减
_TRUSTED_DAMPEN = 20
#: 命中用户白名单后的分值上限：必须**低于默认阈值 30**（否则白名单不起作用），
#: 但不能归零 —— 记录要留着。理由：“白名单里的东西出了问题”恰恰是最需要看得见的信号，
#: 把发现直接删掉等于丢掉了一条关键线索。
_WHITELIST_CAP = 15
# **仅作标注、不算"规则命中"** 的名字。组合加成会跳过它们。
# 踩过：签名降级往 rules 里加了 `signed_valid`，组合加成把它当成第二条命中规则，
# 于是降级后的 10 分被加成到 25 分 —— 降级效果被吃掉一大半。
# 以后再加任何"解释性/注明性"的规则名，都要登记到这里。
_ANNOTATION_RULES = {"signed_valid", "benign_baseline", "whitelisted"}


@dataclass
class Conn:
    proto: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    pid: int
    proc: str = ""
    exe: str = ""

    @property
    def key(self) -> Tuple[str, str, int, str, int]:
        return (self.proto, self.local_ip, self.local_port, self.remote_ip, self.remote_port)


@dataclass
class Finding:
    score: int
    rules: List[str]
    conn: Conn
    detail: str = ""

    @property
    def fingerprint(self) -> str:
        """去重指纹。

        ⚠ 进程级规则必须**按进程聚合**：`port_fanout` / `conn_burst` / `periodic_beacon` /
        `intranet_lateral` 描述的是「这个进程干了这件事」，而一条连接一个五元组。
        实测教训：演练里 25 条爆发连接 + 15 个扫描端口，如果指纹带 `remote_port`，
        同一次行为会被拆成几十条独立事件、反复触发冷却与限速，把真正的事件淹没。
        """
        pid_level = ["port_fanout", "conn_burst", "periodic_beacon", "intranet_lateral",
                     "proc_from_suspect_dir"]
        if any(r in self.rules for r in pid_level):
            return f"{self.conn.proc or self.conn.pid}|{','.join(sorted(self.rules))}"
        return (f"{self.conn.proc}|{self.conn.remote_ip}|{self.conn.remote_port}|"
                f"{','.join(sorted(self.rules))}")


def _is_loopback(ip: str) -> bool:
    """回环 / 未指定地址 —— 本地 IPC 不是“进出流量”，必须从研判中排除。

    实测教训：不加这一步时，`rare_port` 会把 Code.exe→::1:11434、
    各家软控件的 ::1 本地端口全部报出来（一次采样 9 条全是回环），
    属于纯噪音，会把阈值调得不剩任何灵敏度。
    """
    if not ip or ip in ("*", "0.0.0.0", "::", "::1"):
        return True
    if ip.startswith("127.") or ip.startswith("::ffff:127."):
        return True
    return False


def _is_private(ip: str) -> bool:
    if ip.startswith(("10.", "127.", "169.254.", "192.168.")):
        return True
    if ip.startswith("172."):
        try:
            return 16 <= int(ip.split(".")[1]) <= 31
        except (ValueError, IndexError):
            return False
    return False


def parse_netstat(text: str) -> List[Conn]:
    """解析 `netstat -ano` 输出（TCP/UDP）。状态词为英文，不受系统语言影响。"""
    out: List[Conn] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] not in ("TCP", "UDP"):
            continue
        proto = parts[0]
        local, remote = parts[1], parts[2]
        if proto == "TCP":
            if len(parts) < 5:
                continue
            state, pid_s = parts[3], parts[4]
        else:
            if not parts[3].isdigit():
                continue
            state, pid_s = "", parts[3]
        if not pid_s.isdigit():
            continue
        lip, _, lport = local.rpartition(":")
        rip, _, rport = remote.rpartition(":")
        try:
            out.append(Conn(proto, lip.strip("[]"), int(lport), rip.strip("[]"),
                            int(rport) if rport.isdigit() else 0, state, int(pid_s)))
        except ValueError:
            continue
    return out


def _ps(cmd: str, timeout: float = 40) -> str:
    """跑一段 PowerShell 并把 stdout 取回（**统一 UTF-8 + 隐藏窗口**）。

    ⚠ 本函数只在**降级路径**上使用。主路径应当走 `tools/win_net.py`（ctypes 直读 API），
    否则 pythonw 下每次调用都会闪一个终端窗口。
    """
    prefix = "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
    try:
        p = subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                            "-Command", prefix + cmd],
                           timeout=timeout, **_hidden_kwargs())
        return p.stdout or ""
    except Exception as exc:  # noqa: BLE001
        LOG.warning("PowerShell 调用失败：%s", exc)
        return ""


def snapshot() -> List[Conn]:
    """采一次全网连接（TCP+UDP，含 PID）。

    优先 ctypes 直读（零子进程 → 不会弹终端）；仅在非 Windows/API 不可用时
    才降级到 netstat 子进程。
    """
    if _HAVE_WIN_NET and win_net is not None:
        rows = win_net.connections()
        names, paths = _fast_process_map()
        out: List[Conn] = []
        for r in rows:
            name, exe = names.get(r.pid, ""), paths.get(r.pid, "")
            out.append(Conn(r.proto, r.local_ip, r.local_port, r.remote_ip,
                            r.remote_port, r.state, r.pid, name, exe))
        if out:
            return out
    try:
        p = subprocess.run(["netstat", "-ano"], timeout=25, **_hidden_kwargs())
        txt = p.stdout or ""
    except Exception as exc:  # noqa: BLE001
        LOG.error("netstat 失败：%s", exc)
        return []
    conns = parse_netstat(txt)
    pmap = process_map()
    for c in conns:
        name, exe = pmap.get(c.pid, ("", ""))
        c.proc, c.exe = name, exe
    if conns and not pmap:
        LOG.warning("拿不到进程映射（连接 %d 条无名）—— 降级为只报端口/地址", len(conns))
    return conns


_FAST_PMAP: Tuple[Dict[int, str], Dict[int, str]] = ({}, {})
_FAST_PMAP_AT = 0.0


def _fast_process_map(max_age: float = 60.0) -> Tuple[Dict[int, str], Dict[int, str]]:
    """ctypes 进程表（带缓存）。取代原来的 PowerShell CIM 查询。"""
    global _FAST_PMAP, _FAST_PMAP_AT
    if _FAST_PMAP[0] and (time.time() - _FAST_PMAP_AT) < max_age:
        return _FAST_PMAP
    if win_net is None:
        return _FAST_PMAP
    names, paths = win_net.process_table(with_path=True)
    if names:
        _FAST_PMAP, _FAST_PMAP_AT = (names, paths), time.time()
    return _FAST_PMAP


_PMAP: Dict[int, Tuple[str, str]] = {}
_PMAP_AT = 0.0


def process_map(max_age: float = 60.0) -> Dict[int, Tuple[str, str]]:
    """pid → (进程名, 可执行文件路径)。带缓存，避免每次轮询都查一遍（省 CPU）。"""
    global _PMAP, _PMAP_AT
    if _PMAP and (time.time() - _PMAP_AT) < max_age:
        return _PMAP
    ps = ("Get-CimInstance Win32_Process | ForEach-Object "
          "{ \"$($_.ProcessId)`t$($_.Name)`t$($_.ExecutablePath)\" }")
    txt = _ps(ps, timeout=40)
    if not txt:
        return _PMAP
    m: Dict[int, Tuple[str, str]] = {}
    for line in txt.splitlines():
        bits = line.split("\t")
        if len(bits) >= 2 and bits[0].strip().isdigit():
            m[int(bits[0])] = (bits[1].strip(), (bits[2].strip() if len(bits) > 2 else ""))
    if m:
        _PMAP, _PMAP_AT = m, time.time()
    return _PMAP


# 已知会做"固定周期心跳"的合法客户端。
#
# 为什么需要：演练实测 `codex.exe → IPv6 :443` 每 20 秒一次的心跳被
# `periodic_beacon`(35 分) 判成 attack —— 合法开发者工具的云服务心跳与 C2 信标
# 在"周期"这个维度上**形状完全相同**。单靠周期无法区分，必须叠加业务归属。
#
# ⚠ 这是**启发式降级**，不是白名单豁免：
#   1) 仅对名字命中的进程降级（不豁免）；
#   2) 还必须目标端口是标准端口（BENIGN_PORTS），否则原分不变；
#   3) 降级后的分值(10) 仍会入库，只是不再触发模型与通知（可审计）。
#   恶意程序只要伪装成这些名字就能拿到降级 —— 这是本规则已知的局限，
#   所以它只能**降噪**，不能当作"已证明无害"。
_BEACON_BENIGN_OWNERS = {
    "codex.exe", "onedrive.exe", "dropbox.exe", "msteams.exe", "teams.exe",
    "slack.exe", "steam.exe", "code.exe", "msedge.exe", "chrome.exe",
    "firefox.exe", "wechat.exe", "weixin.exe", "qq.exe", "dingtalk.exe",
    "zoom.exe", "spotify.exe", "svchost.exe", "git.exe", "gh.exe",
}


class LlmQueue:
    """限速下的**优先级**待办队列。

    原实现的缺陷：配额（默认 3 次/分钟）用完就直接丢弃。演练实测 9 次命中被判
    `skipped`，**其中包含 60 分的高危事件** —— 低分噪声把高分事件挤掉了。

    现在：配额内直接研判；超出配额时按分值入队，等配额恢复后**从高分开始**处理；
    队列满（cap）时丢弃**分值最低**的，并如实计数（不静默丢）。
    """

    def __init__(self, cap: int = 50) -> None:
        self.cap = cap
        self._items: List[Tuple[int, int, Any]] = []
        self._seq = 0
        self.deferred = 0      # 曾入队的总数
        self.dropped_low = 0   # 因队列满而被丢弃（都是低分的）

    def push(self, score: int, payload: Any) -> None:
        self._seq += 1
        self._items.append((score, self._seq, payload))
        self._items.sort(key=lambda x: (-x[0], x[1]))
        while len(self._items) > self.cap:
            self._items.pop()
            self.dropped_low += 1
        self.deferred += 1

    def pop_best(self) -> Optional[Any]:
        if not self._items:
            return None
        return self._items.pop(0)[2]

    def __len__(self) -> int:
        return len(self._items)


class Baseline:
    """跨轮次的观察窗口：用于端口发散 / 周期信标 / 连接爆发等需要历史的规则。"""

    def __init__(self, fanout_window: int = 120 * 1000, fanout_threshold: int = 40):
        self.conns: Deque[Tuple[float, Conn]] = deque(maxlen=20000)
        self.fanout_window = fanout_window
        self.fanout_threshold = fanout_threshold

    def observe(self, cs: Sequence[Conn], now: Optional[float] = None) -> None:
        now = now or time.time()
        for c in cs:
            if c.remote_ip and not _is_private(c.remote_ip):
                self.conns.append((now, c))

    def _recent(self, now: float) -> List[Conn]:
        return [c for t, c in self.conns if now - t <= self.fanout_window]


_WL_CACHE: Dict[str, Any] = {"obj": None, "mtime": -1.0}


def _whitelist() -> Any:
    """取用用户白名单，并在文件变化时**自动重载**。

    为什么必须看重载：传感器是常驻进程（本机实测已连续跑了好几天），
    而 GUI 可以随时往白名单里加条目。如果不重载，界面上显示“已加入”、
    实际告警照旧 —— 那种“改了没用”的状态比没这个功能更糟，
    会让人以为系统已经按白名单工作了。
    代价只有一次 `stat()`（每轮一次，可忽略），只有 mtime 变了才真读文件。
    """
    try:
        from security.whitelist import default_whitelist  # noqa: PLC0415
        wl = default_whitelist()
    except Exception:  # noqa: BLE001  白名单不可用不能影响检测
        return None
    try:
        mt = wl.path.stat().st_mtime
    except OSError:
        mt = 0.0
    if _WL_CACHE["obj"] is None or mt != _WL_CACHE["mtime"]:
        try:
            wl.load()
        except Exception:  # noqa: BLE001
            return None
        _WL_CACHE["obj"] = wl
        _WL_CACHE["mtime"] = mt
    return wl


def analyse(cs: Sequence[Conn], base: Baseline, now: Optional[float] = None,
            profile: Optional[BenignProfile] = None,
            sig_fn: Optional[Any] = None,
            whitelist: Optional[Any] = None) -> List[Finding]:
    """本地规则打分。零 LLM 成本，是「省资源」的关键一层。

    ``profile`` 非空时，命中**已确立良性基线**的发现会被降权（对应材料里的
    「无监督正常基线」方法），降权说明会写进 ``detail`` 以便审计。

    ``sig_fn`` 非空时，对「非常规目录里的可执行文件」先查数字签名，
    **签名有效则降为 10 分**（同 `suspect_proc_finding` 的口径）。

    ⚠ 为什么必须加这个参数：签名降级最初只加在**事件驱动路径**上，
    轮询路径的 `suspect_path` 规则直接给满分 40。实测后果 ——
    本机 Visual Studio 安装器把签名的 BackgroundDownload.exe 解压到
    `%TEMP%\<随机>\` 后运行，每天一次，每次都被报成 40 分攻击、
    还进了模型研判，持续制造假告警。同一个事实（签名有效）
    不能因为走哪条采集路径而得出不同结论。
    设为参数而不是写死在里面，是为了让 `analyse()` 保持可单测（不默认起子进程）。
    """
    now = now or time.time()
    findings: List[Finding] = []
    by_pid: Dict[int, List[Conn]] = defaultdict(list)
    for c in cs:
        # 只看真正的“出入站”：有远端地址、非回环/未指定
        if _is_loopback(c.remote_ip) or not c.remote_port:
            continue
        if not _is_private(c.remote_ip):
            by_pid[c.pid].append(c)
        else:
            by_pid[c.pid].append(c)  # 内网也要看（横向移动）

    recent = base._recent(now)

    for pid, group in by_pid.items():
        proc = group[0].proc or f"pid:{pid}"
        exe = (group[0].exe or "").lower()

        # pid 0 / 无进程名 = SYSTEM 空闲或已进入 TIME_WAIT 的无属主连接。
        # 它们没有可归因的执行体，报到分析师手里只是噪音（演练里确实出现了
        # `[System Process](0) -> ...:4444 ['high_risk_port']` 这种条目）。
        if pid == 0 or not group[0].proc:
            continue

        # 规则 1/7：目标端口（风险分层，避免单一端口阈值造成误报）
        for c in group:
            if c.remote_port in HIGH_RISK_PORTS:
                findings.append(Finding(_RULE_BASE["high_risk_port"], ["high_risk_port"], c,
                                        f"目标端口 {c.remote_port} 属高危远控/矿池/匿名网络端口"))
            elif c.remote_port in SOFT_PORT_HINTS:
                findings.append(Finding(_RULE_BASE["soft_port"], ["soft_port"], c,
                                        f"目标端口 {c.remote_port} 为弱可疑端口（正常工具也用，需组合证据）"))
            elif (not _is_private(c.remote_ip)) and c.remote_port not in BENIGN_PORTS \
                    and c.remote_port > 1024:
                findings.append(Finding(_RULE_BASE["rare_port"], ["rare_port"], c,
                                        f"外连非标准端口 {c.remote_port}"))

        # 规则 2：可执行文件落在非常规位置
        if exe and any(h in exe for h in SUSPECT_PATH_HINTS) \
                and not any(t in exe for t in TRUSTED_PATH_HINTS):
            score = _RULE_BASE["suspect_path"]
            rules = ["suspect_path"]
            detail = f"可执行文件位于非常规目录：{group[0].exe}"
            # 签名校验：有效则降级（降级而非豁免 —— 签名有效≠无害，
            # 恶意软件也买证书）。口径与 suspect_proc_finding 一致。
            if sig_fn is not None:
                try:
                    status, subject = sig_fn(group[0].exe)
                except Exception:  # noqa: BLE001
                    status, subject = "UnknownError", ""
                if status == "Valid":
                    score = 10
                    rules.append("signed_valid")
                    pub = (subject or "").split(",")[0].replace("CN=", "").strip() \
                        or "未知签发者"
                    detail += f"；**数字签名有效**（{pub}），按安装器/更新器自解压降级"
                else:
                    detail += f"；数字签名状态：{status}（未降级）"
            findings.append(Finding(score, rules, group[0], detail))

        # 规则 3/7：端口发散 / 连接爆发 —— **只对 TCP 算**。
        # 实测教训：Edge 的 UDP DNS 查询每条都是一个新的本地端口，
        # 对同一台 DNS（120.196.165.24:53）瞬间就是 ≥20 条“连接”，
        # 于是 `conn_burst` 把正常域名解析报成了攻击。UDP 端点不是会话，计数无意义。
        tcp_group = [c for c in group if c.proto == "TCP"]
        ports = {c.remote_port for c in tcp_group}
        if len(ports) >= 10:
            findings.append(Finding(_RULE_BASE["port_fanout"], ["port_fanout"], tcp_group[0],
                                    f"{proc} 连接 {len(ports)} 个不同目的端口（疑扫描/横向）"))

        per_remote: Dict[str, int] = defaultdict(int)
        for c in tcp_group:
            per_remote[c.remote_ip] += 1
        for ip, n in per_remote.items():
            if n >= 20:
                findings.append(Finding(_RULE_BASE["conn_burst"], ["conn_burst"], tcp_group[0],
                                        f"到 {ip} 的活动 TCP 连接数 {n}（疑外传/连接表耗尽）"))

    # 规则 4：跨轮次周期信标（同一 进程+远端 在窗口内反复出现且间隔稳定）
    hist: Dict[Tuple[str, str, int], List[float]] = defaultdict(list)
    for t, c in base.conns:
        hist[(c.proc or str(c.pid), c.remote_ip, c.remote_port)].append(t)
    for (proc, ip, port), ts in hist.items():
        if len(ts) < 4:
            continue
        ts = sorted(ts)
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        mean = sum(gaps) / len(gaps)
        if mean < 20:
            continue
        var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
        if (var ** 0.5) / mean < 0.25:  # 变异系数 < 0.25 = 间隔高度规律
            c = next((x for t, x in base.conns if (x.proc or str(x.pid)) == proc
                      and x.remote_ip == ip and x.remote_port == port), None)
            if c and not _is_private(ip):
                owner = (proc or "").lower()
                benign = owner in _BEACON_BENIGN_OWNERS and port in BENIGN_PORTS
                note = ("；进程属已知合法客户端且目标为标准端口，按云服务心跳降级"
                        if benign else "")
                findings.append(Finding(
                    10 if benign else _RULE_BASE["periodic_beacon"],
                    ["periodic_beacon"], c,
                    f"到 {ip}:{port} 的连接间隔高度规律（均值 {mean:.0f}s，"
                    f"变异系数 {(var ** 0.5) / mean:.2f}）{note}"))

    # 规则 6：内网横向（连了多个内网主机的管理共享/远程端口）
    lateral_ports = {445, 3389, 5985, 5986, 135, 139}
    lan: Dict[str, set] = defaultdict(set)
    for c in recent:
        if _is_private(c.remote_ip) and c.remote_port in lateral_ports:
            lan[c.proc or str(c.pid)].add(c.remote_ip)
    for proc, ips in lan.items():
        if len(ips) >= 5:
            c = next((x for t, x in base.conns if (x.proc or str(x.pid)) == proc
                      and _is_private(x.remote_ip)), None)
            if c:
                findings.append(Finding(_RULE_BASE["intranet_lateral"], ["intranet_lateral"], c,
                                        f"{proc} 访问 {len(ips)} 台内网主机的管理端口"))

    # 合并同一连接的多个规则命中，避免重复研判
    merged: Dict[Tuple, Finding] = {}
    for f in findings:
        k = f.conn.key
        if k in merged:
            m = merged[k]
            m.score += f.score
            m.rules.extend(r for r in f.rules if r not in m.rules)
            m.detail += "；" + f.detail
        else:
            merged[k] = f

    # 后处理：组合加成 + 可信路径衰减
    for f in merged.values():
        # ⚠ 组合加成只能数**真实规则命中**，不能把标注规则数进去。
        # 踩过：签名降级往 rules 里加了个 `signed_valid` 标注，
        # 这里就把它当成“第二条命中规则”，10 分被加成到 25 分 ——
        # 降级效果被吃掉一大半（阈值 30 下看似无害，但叠上别的弱规则就会越线）。
        real_rules = [r for r in f.rules if r not in _ANNOTATION_RULES]
        if len(real_rules) >= 2:
            f.score += _COMBO_BONUS
            f.detail += f"；命中 {len(real_rules)} 条规则，组合加成 +{_COMBO_BONUS}"
        exe = (f.conn.exe or "").lower()
        if exe and any(t in exe for t in TRUSTED_PATH_HINTS):
            f.score -= _TRUSTED_DAMPEN
            f.detail += f"；进程位于正规安装目录，衰减 -{_TRUSTED_DAMPEN}"
        f.score = max(0, f.score)

    # 用户白名单降权（`security/whitelist.py`；与良性基线同一套纪律）。
    # 为什么放在所有规则之后：白名单的语义是“这个进程/路径我们认识”，它应该压过
    # 任何单条规则的分值；但**不删记录**，只降权+标注。
    # ⚠ 注意 `whitelisted` 已加入 `_ANNOTATION_RULES`：不加的话，这条标注会被后面的
    #   组合加成当成“第二条命中规则”而把分值加回去 —— 与当初 `signed_valid` 的
    #   问题完全同源（降级效果被自己的标注吃掉）。
    if whitelist is not None:
        for f in merged.values():
            exe = f.conn.exe or ""
            try:
                hit = whitelist.match_process(f.conn.proc, exe) or whitelist.match_path(exe)
            except Exception:  # noqa: BLE001  白名单读失败不能影响检测
                hit = None
            if hit is None:
                continue
            f.score = min(f.score, _WHITELIST_CAP)
            f.detail += (f"；命中**用户白名单**（{hit.kind}={hit.value}"
                         + (f"：{hit.note}" if getattr(hit, "note", "") else "")
                         + f"），分值压到上限 {_WHITELIST_CAP}")
            if "whitelisted" not in f.rules:
                f.rules.append("whitelisted")

    # 良性基线降权（数据驱动的白名单；只降权+不弹通知，不删记录）
    if profile is not None:
        for f in merged.values():
            ns, note = profile.dampen(f.score, f.conn.proc, f.conn.remote_port, f.conn.proto)
            if note:
                f.score = ns
                f.detail += "；" + note
                if "benign_baseline" not in f.rules:
                    f.rules.append("benign_baseline")

    # 无属主连接（pid 0 / 无进程名）统一剔除。
    # ⚠ 这一层必须放在**所有规则之后**：只在 by_pid 循环里挡是不够的，
    #   periodic_beacon / intranet_lateral 是在另外两个循环里生成的，会漏网
    #   （实测确实漏出过 `[System Process](0) -> ...:8443 ['port_fanout','conn_burst']`）。
    merged = {k: f for k, f in merged.items()
              if f.conn.pid != 0 and (f.conn.proc or "").strip()
              and "system process" not in (f.conn.proc or "").lower()}
    return sorted(merged.values(), key=lambda x: -x.score)


@dataclass
class SensorState:
    last_seen: Dict[str, float] = field(default_factory=dict)
    llm_calls: Deque[float] = field(default_factory=deque)
    stats: Dict[str, int] = field(default_factory=lambda: {
        "polls": 0, "conns": 0, "findings": 0, "queued": 0,
        "suppressed_cooldown": 0, "suppressed_ratelimit": 0, "notified": 0,
        "deferred_done": 0, "proc_events": 0, "suspect_proc": 0})

    def cooled(self, fp: str, cooldown: float, now: float) -> bool:
        return (now - self.last_seen.get(fp, 0.0)) < cooldown

    def allow_llm(self, per_min: int, now: float) -> bool:
        while self.llm_calls and now - self.llm_calls[0] > 60:
            self.llm_calls.popleft()
        return len(self.llm_calls) < per_min


class LlmController:
    """按需启停 llama-server —— 「尽量省资源」的核心：空闲时显存占用为 0。"""

    def __init__(self, port: int, ctx: int, ngl: int, idle_stop: float = 300.0,
                 autostart: bool = True, lean: bool = False) -> None:
        self.port, self.ctx, self.ngl = port, ctx, ngl
        self.idle_stop, self.autostart, self.lean = idle_stop, autostart, lean
        self.last_use = 0.0
        self.agent: Any = None

    def _deploy(self, *args: str, timeout: int = 240) -> int:
        cmd = [sys.executable, str(PROJECT_ROOT / "deployment" / "llamacpp" / "deploy_llamacpp.py"),
               *args]
        try:
            return subprocess.run(cmd, timeout=timeout, **_hidden_kwargs()).returncode
        except Exception as exc:  # noqa: BLE001
            LOG.error("deploy 调用失败 %s：%s", args, exc)
            return 1

    def _healthy(self) -> bool:
        import urllib.request
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/health", timeout=3) as r:
                return b"ok" in r.read().lower()
        except Exception:  # noqa: BLE001
            return False

    def ensure(self) -> Any:
        """确保模型可用（需要则拉起）。返回 agent 或 None。"""
        if self.agent is None:
            from tools.triage_logs import build_agent  # 复用同一套**只读**构造
            # lean 档：关掉 RAG 与工具层 —— 提示词变短、可用更小的 ctx，
            # 代价是失去知识库判据（本项目实测 RAG+接地是最大增益源）。
            extra = {"rag.enabled": False, "tools.enabled": False} if self.lean else None
            self.agent = build_agent("llamacpp", extra_pins=extra)
        if not self._healthy():
            if not self.autostart:
                return None
            LOG.info("拉起 llama-server（按需启动）…")
            self._deploy("serve", "--port", str(self.port), "--ctx", str(self.ctx),
                         "--ngl", str(self.ngl))
            self._deploy("wait", "--timeout", "200")
        self.last_use = time.time()
        return self.agent if self._healthy() else None

    def maybe_stop(self, now: Optional[float] = None) -> None:
        """空闲超过 idle_stop 就停掉，把显存/内存还回去。"""
        now = now or time.time()
        if self.autostart and self.last_use and (now - self.last_use) > self.idle_stop \
                and self._healthy():
            LOG.info("空闲 %.0fs，停止 llama-server 以释放资源", now - self.last_use)
            self._deploy("stop", timeout=60)
            self.last_use = 0.0


def build_alert_text(f: Finding, all_conns: Sequence[Conn]) -> str:
    """把流量发现转成 Agent 能吃的中文告警文本（**只给可观测事实**）。"""
    c = f.conn
    same = [x for x in all_conns if x.pid == c.pid]
    others = sorted({f"{x.remote_ip}:{x.remote_port}" for x in same})[:6]
    lines = [
        "[本机流量监控] 连接级发现（非报文级）",
        f"主机：{_hostname()}（本机）",
        f"进程：{c.proc or '?'}（pid {c.pid}）"
        + (f"，路径 {c.exe}" if c.exe else "，路径未获取"),
        f"连接：{c.proto} {c.local_ip}:{c.local_port} -> {c.remote_ip}:{c.remote_port}"
        + (f"（{c.state}）" if c.state else ""),
        f"本地规则命中（分值 {f.score}）：{'、'.join(f.rules)}",
        f"规则说明：{f.detail}",
        f"该进程同期其它外连：{'; '.join(others) if others else '无'}",
        "说明：以上只是连接元数据，**没有载荷内容**。请据此研判该行为是否构成攻击，"
        "并给出建议动作（本系统只读，不会执行）。",
    ]
    return "\n".join(lines)


def _hostname() -> str:
    import socket
    try:
        return socket.gethostname()
    except Exception:  # noqa: BLE001
        return "localhost"


def suspect_proc_finding(ev: Any, sig_fn: Any = None,
                         whitelist: Any = None) -> Optional[Finding]:
    """把「新进程从非常规目录启动」转成 Finding（事件驱动，不依赖是否外连）。

    这是事件驱动采集的核心价值：恶意程序落在 `%TEMP%` 的**那一刻**就报，
    而不是等它建连接（外连可能只持续几百毫秒，轮询根本采不到）。

    ``sig_fn`` 为签名查询回调（`(path) -> (status, subject)`）。
    **签名有效则降为 10 分**：实测 `%TEMP%` 下跑的不只是恶意程序 ——
    Visual Studio 安装器会把签名组件自解压到 `%TEMP%\\<随机>\\` 执行。
    降级而非豁免：签名有效≠无害（恶意软件也买证书）。
    """
    exe = (getattr(ev, "path", "") or "").lower()
    if not exe:
        return None
    if any(t in exe for t in TRUSTED_PATH_HINTS):
        return None
    if not any(h in exe for h in SUSPECT_PATH_HINTS):
        return None

    score = _RULE_BASE["proc_from_suspect_dir"]
    detail = f"新进程从非常规目录启动（事件驱动）：{getattr(ev, 'path', '')}"
    if sig_fn is not None:
        try:
            status, subject = sig_fn(getattr(ev, "path", ""))
        except Exception:  # noqa: BLE001
            status, subject = "UnknownError", ""
        if status == "Valid":
            score = 10
            pub = subject.split(",")[0].replace("CN=", "").strip() or "未知签发者"
            detail += f"；**数字签名有效**（{pub}），按安装器/更新器自解压降级"
        else:
            detail += f"；数字签名状态：{status}（未降级）"

    # 用户白名单：降权而不删（口径与轮询路径一致 —— 记录要留着，
    # “白名单里的东西出了问题”恰恰是最需要看得见的信号）。
    rules = ["proc_from_suspect_dir"]
    if whitelist is not None:
        try:
            hit = (whitelist.match_process(getattr(ev, "name", ""),
                                          getattr(ev, "path", ""))
                   or whitelist.match_path(getattr(ev, "path", "")))
        except Exception:  # noqa: BLE001
            hit = None
        if hit is not None:
            score = min(score, _WHITELIST_CAP)
            detail += (f"；命中**用户白名单**（{hit.kind}={hit.value}"
                       + (f"：{hit.note}" if getattr(hit, "note", "") else "")
                       + f"），分值压到上限 {_WHITELIST_CAP}")
            rules.append("whitelisted")

    return Finding(
        score, rules,
        Conn("PROC", "", 0, "", 0, "NEW", int(getattr(ev, "pid", 0)),
             getattr(ev, "name", "") or "?", getattr(ev, "path", "")),
        detail)


def _triage(agent, text: str) -> Dict[str, Any]:
    """送模型研判，并把**置信度所需的各维度**一并取回。"""
    from security.attack_judge import judge as attack_judge  # noqa: PLC0415
    from security.injection_judge import judge as injection_judge  # noqa: PLC0415
    from security.reasoning_audit import audit as reasoning_audit  # noqa: PLC0415

    t0 = time.time()
    try:
        resp = agent.ask(text)
    except Exception as exc:  # noqa: BLE001
        return {"verdict": "error", "error": str(exc), "latency_s": round(time.time() - t0, 2)}
    answer = resp.answer or ""
    aj = attack_judge(answer)
    ij = injection_judge(answer)
    ra = reasoning_audit(answer, benign_verdict=aj.benign)
    return {
        "verdict": aj.verdict, "attack_strict": aj.attack_strict, "hedged": aj.hedged,
        "contradictory": aj.contradictory, "discriminator": ra.discriminator,
        "injection_flagged": ij.injection_flagged,
        "needs_review": bool(resp.needs_review) or aj.verdict == "unclear",
        "grounded_ok": bool(resp.grounded_ok),
        "actions": [str(a.get("action") or "") for a in (resp.actions or [])],
        "latency_s": round(time.time() - t0, 2), "answer": answer,
    }


def selftest() -> int:
    ok = total = 0
    now = time.time()

    def chk(name: str, cond: bool) -> None:
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  [{'ok  ' if cond else 'FAIL'}] {name}")

    print("=== net_sensor 自检 ===")
    sample = ("  TCP    192.0.2.31:51000     203.0.113.9:4444      ESTABLISHED     4321\n"
              "  TCP    192.0.2.31:51001     203.0.113.9:80        ESTABLISHED     4321\n"
              "  UDP    192.0.2.31:5353      *:*                                    4321\n"
              "  TCP    192.0.2.31:51002     192.0.2.99:445        ESTABLISHED     4321\n")
    cs = parse_netstat(sample)
    chk("netstat 解析条数正确", len(cs) == 4)
    chk("UDP 行状态为空", next(c for c in cs if c.proto == "UDP").state == "")

    b = Baseline()
    cs[0].proc, cs[0].exe = "svchost.exe", "C:\\ProgramData\\svchost.exe"
    cs[1].proc, cs[1].exe = "svchost.exe", "C:\\ProgramData\\svchost.exe"
    for c in cs:
        c.proc = c.proc or "svchost.exe"
    b.observe(cs, now)
    fs = analyse(cs, b, now)
    rules = {r for f in fs for r in f.rules}
    chk("命中高危端口 4444", "high_risk_port" in rules)
    chk("命中非常规路径", "suspect_path" in rules)
    chk("80/443 不触发端口规则", not any(
        f.conn.remote_port in (80, 443) and ({"high_risk_port", "soft_port", "rare_port"} & set(f.rules))
        for f in fs))
    # 校准回归：单一弱端口 + 正规安装目录，不应达到默认阈值 30
    weak = Conn("TCP", "192.0.2.5", 5000, "192.220.25.249", 3333, "ESTABLISHED", 7,
                "Code.exe", "C:\\Program Files\\Microsoft VS Code\\Code.exe")
    fw = analyse([weak], Baseline(), now)
    chk("弱端口+正规目录不超阈值", bool(fw) and fw[0].score < 30)
    # 真实恶意组合：Temp 下无签名程序连高危端口，必须远超阈值
    bad = Conn("TCP", "192.0.2.5", 5001, "203.0.113.9", 4444, "ESTABLISHED", 8,
               "svchost.exe", "C:\\Users\\Public\\Temp\\svchost.exe")
    fb = analyse([bad], Baseline(), now)
    chk("恶意组合远超阈值", bool(fb) and fb[0].score >= 60)

    # 周期信标：6 次采样，间隔 60s，抖动 ±1s
    b2 = Baseline()
    beacon = Conn("TCP", "192.0.2.5", 5000, "198.51.100.7", 8443, "ESTABLISHED", 999,
                  "evil.exe", "C:\\Temp\\evil.exe")
    for i in range(6):
        b2.observe([beacon], now + i * 60 + (i % 2))
    fr = analyse([beacon], b2, now + 300)
    chk("命中周期信标", any("periodic_beacon" in f.rules for f in fr))

    st = SensorState()
    chk("冷却生效", not st.cooled("fp", 600, now))
    st.last_seen["fp"] = now
    chk("冷却期内被抑制", st.cooled("fp", 600, now + 1))
    for _ in range(3):
        st.llm_calls.append(now)
    chk("限速生效", not st.allow_llm(3, now + 1))

    chk("内网判定", _is_private("10.1.2.3") and _is_private("172.20.0.1")
        and not _is_private("172.32.0.1") and not _is_private("8.8.8.8"))
    chk("回环被排除", _is_loopback("::1") and _is_loopback("127.0.0.1")
        and _is_loopback("0.0.0.0") and not _is_loopback("203.0.113.5"))
    loop = [Conn("TCP", "192.0.2.5", 5000, "::1", 11434, "ESTABLISHED", 1, "Code.exe", ""),
            Conn("TCP", "192.0.2.5", 5001, "127.0.0.1", 9999, "ESTABLISHED", 2, "x.exe", "")]
    chk("回环连接不产生任何发现", not analyse(loop, Baseline(), now))
    # 回归：UDP DNS 不应被算成连接爆发（实测 Edge -> DNS:53 误报）
    dns = [Conn("UDP", "192.0.2.5", 50000 + i, "120.196.165.24", 53, "", 77,
                "msedge.exe", "") for i in range(30)]
    chk("UDP 同目标大量端点不算连接爆发",
        not any("conn_burst" in f.rules or "port_fanout" in f.rules
                for f in analyse(dns, Baseline(), now)))
    tcp_burst = [Conn("TCP", "192.0.2.5", 50100 + i, "203.0.113.9", 4444, "ESTABLISHED",
                      78, "x.exe", "C:\\Temp\\x.exe") for i in range(25)]
    chk("TCP 爆发仍会命中", any("conn_burst" in f.rules
                          for f in analyse(tcp_burst, Baseline(), now)))
    unnamed = [Conn("TCP", "192.0.2.5", 5002, "203.0.113.9", 4444, "TIME_WAIT", 0, "", "")]
    chk("pid 0 / 无进程名的连接被排除", not analyse(unnamed, Baseline(), now))

    # —— 轮询路径的签名降级（实测缺陷：VS 安装器解压到 %TEMP% 每天被报 40 分）——
    # 同一个事实（签名有效）不能因为走哪条采集路径而得出不同结论。
    tmp_conn = Conn("TCP", "192.0.2.5", 50000, "203.0.113.9", 443, "ESTABLISHED", 9999,
                    "BackgroundDownload.exe", r"C:\Users\x\AppData\Local\Temp\abc\BackgroundDownload.exe")
    fake_valid = lambda p: ("Valid", "CN=Microsoft Corporation")           # noqa: E731
    fake_none = lambda p: ("NotSigned", "")                                  # noqa: E731
    f_signed = analyse([tmp_conn], Baseline(), now, sig_fn=fake_valid)
    sp_signed = next((f for f in f_signed if "suspect_path" in f.rules), None)
    chk("签名有效 → 降为 10 分（含 signed_valid 标记、detail 写明签发者）",
        sp_signed is not None and sp_signed.score == 10
        and "signed_valid" in sp_signed.rules and "Microsoft" in sp_signed.detail)
    f_unsigned = analyse([tmp_conn], Baseline(), now, sig_fn=fake_none)
    sp_unsigned = next((f for f in f_unsigned if "suspect_path" in f.rules), None)
    chk("未签名 → 保持 40 分（不得连灵敏度一起降掉）",
        sp_unsigned is not None and sp_unsigned.score == 40
        and "signed_valid" not in sp_unsigned.rules)
    f_nosig = analyse([tmp_conn], Baseline(), now)
    chk("不传 sig_fn → 行为与以往一致（保持 40 分）",
        next(f for f in f_nosig if "suspect_path" in f.rules).score == 40)
    f_err = analyse([tmp_conn], Baseline(), now,
                    sig_fn=lambda p: (_ for _ in ()).throw(RuntimeError("boom")))
    chk("签名查询抛异常 → 不崩且不降级",
        next(f for f in f_err if "suspect_path" in f.rules).score == 40)
    fp_a = Finding(60, ["port_fanout", "conn_burst"],
                   Conn("TCP", "192.0.2.5", 1, "203.0.113.9", 1111, "", 7, "p.exe", ""))
    fp_b = Finding(60, ["port_fanout", "conn_burst"],
                   Conn("TCP", "192.0.2.5", 2, "203.0.113.9", 2222, "", 7, "p.exe", ""))
    chk("进程级规则按进程聚合指纹", fp_a.fingerprint == fp_b.fingerprint)

    # 限速优先级队列：配额耗尽时不能丢掉高分事件
    q = LlmQueue(cap=3)
    for sc in (40, 60, 35, 70, 50):
        q.push(sc, sc)
    chk("队列按满分优先排序", [q.pop_best() for _ in range(3)] == [70, 60, 50])
    chk("队列容量生效且丢的是最低分", q.dropped_low == 2 and len(q) == 0)
    chk("入队计数正确", q.deferred == 5)

    # 信标降级：合法客户端 + 标准端口 → 降到 10 分（低于默认阈值 30）
    b3 = Baseline()
    good = Conn("TCP", "192.0.2.5", 5003, "203.0.113.9", 443, "ESTABLISHED", 11,
                "Codex.exe", "C:\\Program Files\\codex\\codex.exe")
    for i in range(6):
        b3.observe([good], now + i * 60)
    fg = analyse([good], b3, now + 300)
    chk("合法客户端+标准端口的信标被降级", bool(fg) and max(f.score for f in fg) < 30)
    evil = Conn("TCP", "192.0.2.5", 5004, "203.0.113.9", 8443, "ESTABLISHED", 12,
                "unknown.exe", "C:\\Temp\\unknown.exe")
    b4 = Baseline()
    for i in range(6):
        b4.observe([evil], now + i * 60)
    fe = analyse([evil], b4, now + 300)
    chk("未知进程的信标仍高分", bool(fe) and any("periodic_beacon" in f.rules for f in fe)
        and max(f.score for f in fe) >= 30)

    # 事件驱动规则：新进程从非常规目录启动
    class _Ev:
        pid, name, path = 4321, "svchost.exe", "C:\\Users\\Public\\Temp\\svchost.exe"
    f1 = suspect_proc_finding(_Ev())
    chk("非常规目录新进程命中 40 分", bool(f1) and f1.score == 40
        and f1.rules == ["proc_from_suspect_dir"])
    f1s = suspect_proc_finding(_Ev(), sig_fn=lambda p: ("Valid", "CN=Microsoft Corporation"))
    chk("签名有效则降为 10 分（VS 安装器这类自解压）", bool(f1s) and f1s.score == 10)
    chk("签名无效/未签名不降级", suspect_proc_finding(_Ev(), sig_fn=lambda p: ("NotSigned", "")).score == 40)

    class _Ev2:
        pid, name, path = 4322, "Code.exe", "C:\\Program Files\\Microsoft VS Code\\Code.exe"
    chk("正规目录新进程不报", suspect_proc_finding(_Ev2()) is None)

    class _Ev3:
        pid, name, path = 4323, "x.exe", ""
    chk("拿不到路径时不报（避免全靠猜）", suspect_proc_finding(_Ev3()) is None)
    print(f"  {ok}/{total} 通过")
    return 0 if ok == total else 1


def _redirect_console(path: Path) -> None:
    """把 stdout/stderr 接到文件，并**同步重绑已存在的 logging handler**。

    ⚠ 为什么不能只写 `sys.stdout = fh; sys.stderr = fh`：
    `pythonw.exe`（无控制台）下 `sys.stdout` / `sys.stderr` 本来就是 **None**，
    而模块导入时 `get_logger()` 已经建好了 StreamHandler，
    它把 `stream` 绑成了当时的 `sys.stderr` = None。
    之后即使替换 `sys.stderr`，handler 仍指向 None →
    每次 `LOG.*` 都抛 `'NoneType' object has no attribute 'write'`；
    该异常被 logging 内部吞掉，表现为「日志文件里只有一行 Logging error，之后什么都没了」
    —— 看起来像“传感器启动即死”，实际是日志通路断了。
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fh = path.open("a", encoding="utf-8", buffering=1)
    old = (sys.stdout, sys.stderr)
    sys.stdout = sys.stderr = fh

    import logging  # noqa: PLC0415
    targets = [logging.getLogger()]
    targets += [logging.getLogger(n) for n in list(logging.root.manager.loggerDict)]
    rebound = 0
    for lg in targets:
        for h in list(getattr(lg, "handlers", [])):
            if isinstance(h, logging.StreamHandler) and (
                    getattr(h, "stream", None) is None or h.stream in old):
                h.stream = fh
                rebound += 1
    print(f"===== 会话开始 {time.strftime('%Y-%m-%d %H:%M:%S')} "
          f"（日志重定向，重绑 {rebound} 个 handler）=====", flush=True)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="本机进出流量监控（连接级）+ LLM 研判 + 通知")
    ap.add_argument("--once", action="store_true", help="采一次并退出")
    ap.add_argument("--loop", action="store_true", help="常驻轮询")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--interval", type=float, default=15.0, help="轮询间隔秒（默认 15）")
    ap.add_argument("--llm", action="store_true", help="对可疑事件调用模型研判")
    ap.add_argument("--no-llm-autostart", action="store_true",
                    help="不自动拉起 llama-server（服务已由别处启动时用）")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--ctx", type=int, default=4096,
                    help="上下文。默认 4096；⚠ 2048 会装不下系统提示词+KB 上下文，"
                         "llama-server 会直接返回 HTTP 400")
    ap.add_argument("--lean", action="store_true",
                    help="省资源档：关闭 RAG/工具层（提示词变短，可配 --ctx 2048）；"
                         "代价是失去知识库判据，识别率会下降")
    ap.add_argument("--ngl", type=int, default=99)
    ap.add_argument("--idle-stop", type=float, default=300.0, help="模型空闲多少秒后停止")
    ap.add_argument("--threshold", type=int, default=30, help="触发 LLM 的分值阈值")
    ap.add_argument("--notify", action="store_true", help="判定为攻击时弹 Windows 通知")
    ap.add_argument("--notify-min-score", type=int, default=40)
    ap.add_argument("--baseline", default=None, help="良性基线文件（默认 logs/benign_profile.json）")
    ap.add_argument("--no-baseline", action="store_true", help="关闭良性基线学习与降权")
    ap.add_argument("--high-band", type=float, default=0.70,
                    help="多维置信度的高置信阀值：低于它只记录、**不弹通知**")
    ap.add_argument("--low-band", type=float, default=0.40)
    ap.add_argument("--cooldown", type=float, default=600.0, help="同一指纹报一次的间隔秒")
    ap.add_argument("--max-llm-per-min", type=int, default=3)
    ap.add_argument("--queue-cap", type=int, default=50,
                    help="限速溢出时的待办队列容量。溢出时丢弃**分值最低**的，"
                         "不再像原先那样“配额用完就全丢”（演练里那会丢掉 60 分的高危事件）")
    ap.add_argument("--event-watch", dest="event_watch", action="store_true", default=None,
                    help="订阅进程创建事件（事件驱动，补短连接盲区；默认 Windows 上开）")
    ap.add_argument("--no-event-watch", dest="event_watch", action="store_false")
    ap.add_argument("--burst-interval", type=float, default=1.0,
                    help="检测到事件后的快采样间隔（秒）")
    ap.add_argument("--burst-window", type=float, default=20.0,
                    help="快采样窗口时长（秒）")
    ap.add_argument("--heartbeat", type=int, default=20,
                    help="每多少次轮询打一条心跳日志（默认 20；15s 间隔即约 5 分钟）。"
                         "没有心跳就无法区分“安静”与“死了”")
    ap.add_argument("--out", default="logs/net_sensor_events.jsonl")
    ap.add_argument("--log-file", default=None,
                    help="把 stdout/stderr 追加写入该文件。配合 pythonw.exe 后台运行时必填，"
                         "否则日志会被丢弃（开机自启默认这样跑）")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    # 后台运行（pythonw.exe 无控制台）时必须自己接管输出，否则报错信息全部丢失
    if args.log_file:
        _redirect_console(Path(args.log_file))

    base = Baseline()
    state = SensorState()
    queue = LlmQueue(cap=args.queue_cap)
    run_state: Dict[str, float] = {"burst_until": 0.0}
    profile = None if args.no_baseline else BenignProfile(
        Path(args.baseline) if args.baseline else DEFAULT_PROFILE_PATH)
    if profile is not None:
        LOG.info("良性基线：%s（%s）", profile.summary(), profile.path)
    llm = LlmController(args.port, args.ctx, args.ngl, args.idle_stop,
                        autostart=not args.no_llm_autostart, lean=args.lean)

    # 事件驱动源：WMI 服务侧订阅进程创建（非管理员可用，延迟约 2s）。
    # 拿不到就降级为纯轮询，并在心跳里如实标注 —— 短连接盲区会重新出现。
    watcher = None
    if args.event_watch is not False and os.name == "nt":
        try:
            from tools.proc_watch import ProcessWatcher  # noqa: PLC0415
            w = ProcessWatcher()
            if w.start():
                watcher = w
                LOG.info("进程创建事件订阅已就绪（WMI 服务侧，延迟约 2s）")
            else:
                LOG.warning("事件订阅不可用（%s）→ 退回纯轮询，短连接可能漏采", w.error)
        except Exception as exc:  # noqa: BLE001
            LOG.warning("事件订阅初始化失败（%s）→ 退回纯轮询", exc)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    def _write(rec: Dict[str, Any]) -> None:
        with out.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def _do_triage(rec: Dict[str, Any], f: Finding, conns: Sequence[Conn],
                   deferred: bool = False) -> None:
        agent = llm.ensure()
        if agent is None:
            rec["triage"] = {"verdict": "skipped", "reason": "模型不可用"}
            _write(rec)
            return
        state.llm_calls.append(time.time())
        state.stats["queued"] += 1
        rec["triage"] = _triage(agent, build_alert_text(f, conns))
        if deferred:
            rec["triage"]["deferred"] = True  # 曾因配额排队，后来补上
            state.stats["deferred_done"] += 1
        v = rec["triage"].get("verdict")
        # 多维置信度：**能不能自动定性不能只看模型自述与规则分**，
        # 还要看有无区分性证据、接地、签名、历史一致性等（见 security/confidence.py）。
        conf = assess(
            rule_score=f.score, verdict=str(v),
            attack_strict=bool(rec["triage"].get("attack_strict")),
            hedged=bool(rec["triage"].get("hedged")),
            grounded_ok=bool(rec["triage"].get("grounded_ok", True)),
            discriminator=bool(rec["triage"].get("discriminator")),
            contradictory=bool(rec["triage"].get("contradictory")),
            injection_flagged=bool(rec["triage"].get("injection_flagged")),
            baseline_hit=("benign_baseline" in f.rules),
            high_band=args.high_band, low_band=args.low_band)
        rec["confidence"] = conf.to_dict()
        rec["route"] = conf.route
        key = "route_" + conf.route
        state.stats[key] = state.stats.get(key, 0) + 1
        if profile is not None:
            profile.record_verdict(f.conn.proc, f.conn.remote_port, f.conn.proto, str(v))
        print(f"    研判={v} 置信度={conf.score} 路由={conf.route}"
              f" 耗时={rec['triage'].get('latency_s')}s"
              f"{'（排队后补）' if deferred else ''}", flush=True)

        # 只有**高置信**才弹通知（对应材料里「只在高置信区间自动处置」）。
        # 中间区间只记录 + 标需复核；低置信静默留档。
        if args.notify and conf.route == "auto_attack" and f.score >= args.notify_min_score:
            ok, _ = notify(
                f"可疑流量：{rec['triage'].get('actions') or '需人工复核'}",
                f"{f.conn.proc}(pid {f.conn.pid}) → "
                f"{f.conn.remote_ip}:{f.conn.remote_port}\n"
                f"规则：{'、'.join(f.rules)} | 判定：{v}（未执行任何动作）",
                subtitle=f"分值 {f.score}｜置信度 {conf.score}")
            rec["notified"] = ok
            state.stats["notified"] += int(ok)
        elif args.notify and v == "attack":
            state.stats["notify_suppressed"] = state.stats.get("notify_suppressed", 0) + 1
        _write(rec)

    def one_poll() -> int:
        now = time.time()
        cs = snapshot()
        base.observe(cs, now)
        state.stats["polls"] += 1
        state.stats["conns"] += len(cs)
        all_findings = analyse(cs, base, now, profile=profile, sig_fn=_signature_status,
                               whitelist=_whitelist())
        # 基线学习必须看到**全部**发现（不论是否超过阈值）：
        # 若只学超阈值的，那么被基线降权压到阈值以下的模式永远学不到，
        # 基线就永远不会自动建立起。
        if profile is not None:
            for g in all_findings:
                profile.observe(g.conn.proc, g.conn.remote_port, g.conn.proto)
            profile.save()
        findings = [f for f in all_findings if f.score >= args.threshold]
        state.stats["findings"] += len(findings)
        state.stats["suppressed_baseline"] = (
            state.stats.get("suppressed_baseline", 0)
            + sum(1 for g in all_findings if "benign_baseline" in g.rules))

        # —— 事件驱动部分：进程创建 ——
        # 这条路的价值：不依赖它”是否外连“。恶意程序落在 %TEMP% 的**那一刻**就报，
        # 而不是等它建立连接（外连可能只持续几百毫秒，轮询根本采不到）。
        if watcher is not None:
            evs = watcher.drain()
            if evs:
                state.stats["proc_events"] += len(evs)
                run_state["burst_until"] = max(run_state["burst_until"],
                                              now + args.burst_window)
                for ev in evs:
                    f2 = suspect_proc_finding(ev, sig_fn=_signature_status,
                                              whitelist=_whitelist())
                    if f2 is not None:
                        state.stats["suspect_proc"] += 1
                        findings.append(f2)

        if findings:
            run_state["burst_until"] = max(run_state["burst_until"],
                                          now + args.burst_window)

        # 先补待办队列：配额恢复后**从高分开始**处理（这是本节的核心修正）
        while args.llm and len(queue) and state.allow_llm(args.max_llm_per_min, now):
            item = queue.pop_best()
            if item:
                _do_triage(item[0], item[1], item[2], deferred=True)
        if args.heartbeat and state.stats["polls"] % args.heartbeat == 0:
            s = state.stats
            ps = profile.summary() if profile is not None else None
            LOG.info("心跳：已轮询 %d 次 / 看过 %d 条连接 / 发现 %d 条 / 上报 %d 条 / "
                     "因冷却跳过 %d / 待办队列 %d（已补 %d，队列满丢弃 %d）/ "
                     "进程事件 %d（其中非常规目录 %d）/ 事件源 %s（RSS %.0f MB）/ 快采样 %s / "
                     "良性基线 %s / 路由 告警%d 复核%d 静默%d（抑制通知 %d）/ "
                     "子进程调用 %d 次（应恒为 0，否则会弹终端）",
                     s["polls"], s["conns"], s["findings"], s["queued"],
                     s["suppressed_cooldown"], len(queue), s["deferred_done"],
                     queue.dropped_low, s["proc_events"], s["suspect_proc"],
                     "就绪" if watcher is not None else "不可用(纯轮询)",
                     watcher.rss_mb() if watcher is not None else 0.0,
                     "是" if time.time() < run_state["burst_until"] else "否",
                     f"{ps['patterns']}个(已确立{ps['established']}个)" if ps else "关闭",
                     s.get("route_auto_attack", 0), s.get("route_review", 0),
                     s.get("route_auto_benign", 0), s.get("notify_suppressed", 0),
                     SPAWN_COUNT)

        for f in findings:
            fp = f.fingerprint
            if state.cooled(fp, args.cooldown, now):
                state.stats["suppressed_cooldown"] += 1
                continue
            state.last_seen[fp] = now
            rec: Dict[str, Any] = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "score": f.score,
                                   "rules": f.rules, "pid": f.conn.pid, "proc": f.conn.proc,
                                   "remote": f"{f.conn.remote_ip}:{f.conn.remote_port}",
                                   "detail": f.detail}
            print(f"  [发现] score={f.score} {f.conn.proc}({f.conn.pid}) -> "
                  f"{f.conn.remote_ip}:{f.conn.remote_port} {f.rules}", flush=True)

            if args.llm:
                if state.allow_llm(args.max_llm_per_min, now) and not queue:
                    _do_triage(rec, f, cs)
                else:
                    # 配额已满（或已有待办）：按分值入队，等配额恢复后优先补高分
                    queue.push(f.score, (rec, f, list(cs)))
                    state.stats["suppressed_ratelimit"] += 1
                    print(f"    → 配额已满，入队等待（队列 {len(queue)}）", flush=True)
            else:
                _write(rec)

    if args.selftest or (not args.once and not args.loop):
        ap.error("需要 --once / --loop / --selftest 之一")

    if args.once:
        n = one_poll()
        print(f"\n本次发现 {n} 条（阈值 {args.threshold}）。统计：{state.stats}")
        print(f"事件记录：{out}")
        return 0
    LOG.info("流量监控启动：间隔 %.0fs 阈值 %d LLM=%s lean=%s 通知=%s",
             args.interval, args.threshold, args.llm, args.lean, args.notify)
    try:
        while True:
            one_poll()
            llm.maybe_stop()
            # 自适应采样：有事发生时快采样（补短连接盲区），平谱时保持 15s 省 CPU
            delay = args.burst_interval if time.time() < run_state["burst_until"] \
                else args.interval
            time.sleep(max(0.5, delay))
    except KeyboardInterrupt:
        LOG.info("收到中断，退出。统计：%s", state.stats)
    finally:
        if watcher is not None:
            watcher.stop()
        if llm.autostart and llm.last_use:
            llm._deploy("stop", timeout=60)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
