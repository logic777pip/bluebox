#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cyber_range/live_drill.py — 本机流量监控的**实弹演练**（只用良性流量模式）。

这是什么 / 不是什么
-------------------
* **是**：一个「流量形状生成器」。它只做普通的 socket 连接，用来复现
  `tools/net_sensor.py` 应该抓到的**可观测网络形状**（高危端口、周期信标、
  端口发散、连接爆发、非常规目录进程外连），从而在真实环境里检验检测与响应。
* **不是**：不含任何攻击载荷、漏洞利用、shellcode、反连 shell、凭据窃取。
  没有对任何**远端**主机发起连接，不写任何远端文件。

硬性安全约束（代码里强制，不是靠自觉）
--------------------------------------
1. **目标白名单**：只允许连向 (a) 本机自己的非回环 IPv4 地址，(b) RFC5737 文档网段
   （192.0.2.0/24、198.51.100.0/24、203.0.113.0/24）。任何其它目标一律拒绝。
2. **仅建立连接并立刻关闭/保持**，不发送任何有语义的载荷。
3. 如需「非常规目录执行」形状，只把**本脚本自身**复制到 `%TEMP%` 再以子进程方式运行，
   不落地任何可执行二进制。
4. 演练结束自动关闭全部监听 socket。

用法::

    python cyber_range/live_drill.py --selftest          # 目标白名单自检
    python cyber_range/live_drill.py --patterns highrisk --hold 90
    python cyber_range/live_drill.py --patterns all --duration 180
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# RFC5737 文档网段：不会路由到任何真实主机
_DOC_NETS = ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")

PATTERNS = ("highrisk", "beacon", "fanout", "burst", "path-temp")

# 端口选择：刻意包含传感器规则里的高危端口与弱可疑端口
HIGH_RISK = [4444, 9050, 31337]
FANOUT_PORTS = [21, 22, 23, 25, 110, 143, 445, 1433, 3306, 3389, 5900, 4444, 9050, 8080, 8443]


# --------------------------------------------------------------------------- #
#  安全护栏
# --------------------------------------------------------------------------- #

class TargetNotAllowed(RuntimeError):
    pass


def local_ips() -> List[str]:
    """本机可用于自连的非回环 IPv4 地址。

    排序刻意讲究：`169.254.*` 是 APIPA 链路本地地址（没有 DHCP 时的占位），
    拿它做自连基本必失败；虚拟网卡（VirtualBox/Docker/WSL）的地址也不适合当演练目标。
    所以先剔除 APIPA，再把真实局域网地址排到前面。
    """
    ips: Set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except Exception:  # noqa: BLE001
        pass
    try:  # 不产生真实流量的取本机出口地址办法（目标为文档网段，不会真的发包）
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            s.connect(("192.0.2.1", 9))
            ips.add(s.getsockname()[0])
        finally:
            s.close()
    except Exception:  # noqa: BLE001
        pass

    def rank(ip: str) -> tuple:
        if ip.startswith("169.254."):
            return (9, ip)          # APIPA 排最后
        if ip.startswith("192.168."):
            return (0, ip)          # 典型家用/办公局域网优先
        if ip.startswith("10."):
            return (1, ip)
        if ip.startswith("172."):
            return (3, ip)          # 多为 Docker/WSL 虚拟网段
        return (5, ip)

    return sorted((i for i in ips if not i.startswith("127.")), key=rank)


def guard(ip: str) -> None:
    """目标白名单校验。任何越界目标直接拒绝执行。"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise TargetNotAllowed(f"非法目标地址：{ip}") from exc
    if addr.is_loopback:
        raise TargetNotAllowed(f"回环地址被传感器有意排除，演练无意义：{ip}")
    if any(addr in ipaddress.ip_network(n) for n in _DOC_NETS):
        return
    if ip in local_ips():
        return
    raise TargetNotAllowed(
        f"拒绝连接 {ip}：只允许本机地址或 RFC5737 文档网段（本演练不触碰任何外部目标）")


def selftest() -> int:
    ok = total = 0

    def chk(name: str, cond: bool) -> None:
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  [{'ok  ' if cond else 'FAIL'}] {name}")

    print("=== live_drill 护栏自检 ===")
    chk("允许 RFC5737 文档地址", _allowed("192.0.2.11") and _allowed("203.0.113.7"))
    chk("拒绝公网地址", not _allowed("8.8.8.8") and not _allowed("1.1.1.1"))
    chk("拒绝回环", not _allowed("127.0.0.1"))
    me = local_ips()
    chk(f"能找到本机地址（{me}）", bool(me))
    chk("允许本机地址", all(_allowed(i) for i in me))
    print(f"  {ok}/{total} 通过")
    return 0 if ok == total else 1


def _allowed(ip: str) -> bool:
    try:
        guard(ip)
        return True
    except TargetNotAllowed:
        return False


# --------------------------------------------------------------------------- #
#  监听端：让连接变成 ESTABLISHED（否则只是 SYN_SENT，轮询可能采不到）
# --------------------------------------------------------------------------- #

class Listeners:
    def __init__(self, ips: Sequence[str], ports: Sequence[int]) -> None:
        self.socks: List[socket.socket] = []
        self.accepted: List[socket.socket] = []
        self.threads: List[threading.Thread] = []
        self.alive = True
        for ip in ips:
            for port in ports:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind((ip, port))
                    s.listen(64)
                    s.settimeout(1.0)
                    self.socks.append(s)
                except OSError:
                    continue  # 端口被占用/被防火墙拦，跳过

    def start(self) -> None:
        def loop(sock: socket.socket) -> None:
            while self.alive:
                try:
                    c, _ = sock.accept()
                    self.accepted.append(c)
                except socket.timeout:
                    continue
                except OSError:
                    break

        for s in self.socks:
            t = threading.Thread(target=loop, args=(s,), daemon=True)
            t.start()
            self.threads.append(t)

    def close(self) -> None:
        self.alive = False
        for s in self.socks + self.accepted:
            try:
                s.close()
            except OSError:
                pass

    def ports(self) -> List[int]:
        return sorted({s.getsockname()[1] for s in self.socks})


# --------------------------------------------------------------------------- #
#  各种流量形状
# --------------------------------------------------------------------------- #

def _connect(ip: str, port: int, timeout: float = 3.0) -> Optional[socket.socket]:
    guard(ip)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return s
    except OSError:
        s.close()
        return None


def _p_highrisk(ip: str, hold: float, stop: threading.Event) -> None:
    """高危端口长连接：应命中 high_risk_port(40)。"""
    socks = []
    for port in HIGH_RISK:
        s = _connect(ip, port)
        if s:
            socks.append(s)
            print(f"    [highrisk] 已连接 {ip}:{port}")
    stop.wait(hold)
    for s in socks:
        s.close()


def _p_beacon(ip: str, hold: float, stop: threading.Event) -> None:
    """周期信标：固定 20s 间隔短连接，应命中 periodic_beacon(35)。"""
    n = 0
    while not stop.is_set() and n < 12:
        s = _connect(ip, 8443)
        if s:
            n += 1
            print(f"    [beacon] 第 {n} 次心跳 {ip}:8443")
            time.sleep(1.5)
            s.close()
        stop.wait(18.5)  # 保持总间隔 ≈20s，间隔高度规律


def _p_fanout(ip: str, hold: float, stop: threading.Event) -> None:
    """端口发散：同一进程连 15 个不同端口，应命中 port_fanout(25)。"""
    rounds = 0
    while not stop.is_set() and rounds < 6:
        rounds += 1
        socks = []
        for port in FANOUT_PORTS:
            s = _connect(ip, port, timeout=1.5)
            if s:
                socks.append(s)
        print(f"    [fanout] 第 {rounds} 轮扫了 {len(socks)} 个端口")
        stop.wait(hold)
        for s in socks:
            s.close()
        stop.wait(4)


def _p_burst(ip: str, hold: float, stop: threading.Event) -> None:
    """连接爆发：同一远端 25 条并发连接，应命中 conn_burst(20)。"""
    rounds = 0
    while not stop.is_set() and rounds < 4:
        rounds += 1
        socks = [s for s in (_connect(ip, 4444) for _ in range(25)) if s]
        print(f"    [burst] 第 {rounds} 轮建立 {len(socks)} 条并发连接 → {ip}:4444")
        stop.wait(hold)
        for s in socks:
            s.close()
        stop.wait(5)


def _p_path_temp(ip: str, hold: float, stop: threading.Event) -> None:
    """非常规目录执行：把**本脚本自身**复制到 %TEMP% 再跑一次 highrisk。

    只复制 .py 源码，不落地任何可执行二进制、不做持久化、不写注册表。
    """
    tmp = Path(tempfile.gettempdir()) / "drill_tmp_runner.py"
    try:
        shutil.copyfile(Path(__file__).resolve(), tmp)
    except OSError as exc:
        print(f"    [path-temp] 复制失败，跳过：{exc}")
        return
    print(f"    [path-temp] 已把演练脚本复制到 {tmp} 并以子进程运行")
    try:
        subprocess.Popen([sys.executable, str(tmp), "--patterns", "highrisk",
                          "--hold", str(int(hold)), "--quiet"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as exc:  # noqa: BLE001
        print(f"    [path-temp] 子进程启动失败：{exc}")
    stop.wait(hold)


_PATTERN_FN = {"highrisk": _p_highrisk, "beacon": _p_beacon, "fanout": _p_fanout,
               "burst": _p_burst, "path-temp": _p_path_temp}


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="本机流量监控实弹演练（良性流量形状）")
    ap.add_argument("--patterns", default="all",
                    help="逗号分隔：highrisk,beacon,fanout,burst,path-temp 或 all")
    ap.add_argument("--duration", type=float, default=180.0, help="总时长（秒）")
    ap.add_argument("--hold", type=float, default=20.0, help="每轮连接保持秒数")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    names = list(PATTERNS) if args.patterns == "all" else \
        [p.strip() for p in args.patterns.split(",") if p.strip()]
    bad = [n for n in names if n not in _PATTERN_FN]
    if bad:
        ap.error(f"未知模式：{bad}；可选 {list(_PATTERN_FN)}")

    ips = local_ips()
    if not ips:
        print("找不到本机非回环 IPv4 地址，无法演练（回环已被传感器有意排除）")
        return 2
    ip = ips[0]

    print("=" * 68)
    print("实弹演练开始（良性流量形状，无载荷、无外部目标）")
    print(f"目标：本机自身 {ip}；模式：{names}；时长：{args.duration}s")
    print("说明：本演练只建立普通 TCP 连接，用来复现" 
          "「高危端口/周期信标/端口发散/连接爆发/非常规目录外连」这些网络形状。")
    print("=" * 68)

    ports = sorted(set(HIGH_RISK + FANOUT_PORTS + [8443]))
    lis = Listeners([ip], ports)
    lis.start()
    print(f"  本地监听已就绪：{ip} 上 {len(lis.ports())} 个端口")
    if not lis.ports():
        print("  ⚠ 没能绑定任何端口（可能被防火墙或权限拦下），"
              "将继续以 SYN_SENT 方式制造形状（可能被轮询漏采）")

    stop = threading.Event()
    threads = []
    for n in names:
        t = threading.Thread(target=_PATTERN_FN[n], args=(ip, args.hold, stop), daemon=True)
        t.start()
        threads.append((n, t))
        time.sleep(1.0)

    t0 = time.time()
    try:
        while time.time() - t0 < args.duration:
            time.sleep(2)
            if not args.quiet:
                left = args.duration - (time.time() - t0)
                if int(left) % 30 == 0:
                    print(f"  ... 剩余 {left:.0f}s")
    except KeyboardInterrupt:
        print("  收到中断")
    finally:
        stop.set()
        time.sleep(1)
        lis.close()
        print("演练结束，监听已关闭")

    print("\n下一步：查看检测结果")
    print("  python tools/read_log.py logs/net_sensor.log --tail 40")
    print("  事件流水：logs/net_sensor_events.jsonl")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
