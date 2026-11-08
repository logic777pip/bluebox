"""量化本机网络是否被蓝队 Agent 拖慢（只读诊断，不改动系统配置）。

测量项：
  1) DNS 解析耗时（最常见的“网变慢”症状）
  2) TCP 握手 RTT（往外网，反映网络栈延迟）
  3) 网关 ICMP RTT
  4) 本机网卡吞吐（字节增量 -> 说明是否在占带宽）
  5) Agent 进程持有的 socket 清单（直接证明有无对外连接）
  6) 本地 LLM 端口响应耗时（推理服务是否被拖慢）
  7) Agent 进程 CPU/RSS

可选 `--load-llm`：采样期间持续对本地 LLM 发请求，测**最坏情况**（推理中）的影响。

用法：
    python tools/net_impact.py --label A --seconds 20
    python tools/net_impact.py --label B --seconds 20 --json logs/net_impact_B.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import statistics
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

TCP_TARGETS = [("1.1.1.1", 443), ("223.5.5.5", 443)]
DNS_NAMES = ["www.microsoft.com", "www.qq.com", "github.com"]
LLM_URL = "http://127.0.0.1:8080"

_CREATE_NO_WINDOW = 0x08000000


def _hidden() -> Dict[str, Any]:
    kw: Dict[str, Any] = {}
    if os.name == "nt":
        kw["creationflags"] = _CREATE_NO_WINDOW
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0
        kw["startupinfo"] = si
    return kw


def _ps(cmd: str, timeout: int = 20) -> str:
    full = "[Console]::OutputEncoding=[Text.Encoding]::UTF8;" + cmd
    try:
        r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", full],
                           capture_output=True, encoding="utf-8", errors="replace",
                           timeout=timeout, **_hidden())
    except Exception:
        return ""
    return (r.stdout or "").strip()


# ---------------------------------------------------------------- 单项测量

def _stat(vals: List[float]) -> Optional[Dict[str, float]]:
    vals = [v for v in vals if v is not None]
    if not vals:
        return None
    vals_sorted = sorted(vals)
    return {
        "n": len(vals),
        "min": round(min(vals), 2),
        "avg": round(statistics.fmean(vals), 2),
        "p50": round(statistics.median(vals), 2),
        "p95": round(vals_sorted[min(len(vals_sorted) - 1, int(len(vals_sorted) * 0.95))], 2),
        "max": round(max(vals), 2),
    }


def measure_dns(rounds: int) -> Optional[Dict[str, float]]:
    out: List[float] = []
    for i in range(rounds):
        name = DNS_NAMES[i % len(DNS_NAMES)]
        t0 = time.perf_counter()
        try:
            socket.getaddrinfo(name, 443, socket.AF_INET)
            out.append((time.perf_counter() - t0) * 1000)
        except OSError:
            pass
    return _stat(out)


def measure_tcp(rounds: int) -> Dict[str, Any]:
    res: Dict[str, Any] = {}
    for host, port in TCP_TARGETS:
        vals: List[float] = []
        for _ in range(rounds):
            s = socket.socket()
            s.settimeout(2.0)
            t0 = time.perf_counter()
            try:
                s.connect((host, port))
                vals.append((time.perf_counter() - t0) * 1000)
            except OSError:
                pass
            finally:
                s.close()
        res[f"{host}:{port}"] = _stat(vals)
    return res


def gateway() -> Optional[str]:
    txt = _ps("(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
              "Sort-Object RouteMetric | Select-Object -First 1).NextHop")
    m = re.search(r"\d+\.\d+\.\d+\.\d+", txt)
    return m.group(0) if m else None


def measure_gateway(gw: str, count: int = 10) -> Optional[Dict[str, float]]:
    try:
        r = subprocess.run(["ping.exe", "-n", str(count), "-w", "1000", gw],
                           capture_output=True, encoding="utf-8", errors="replace",
                           timeout=count * 2 + 10, **_hidden())
    except Exception:
        return None
    txt = r.stdout or ""
    vals = [float(x) for x in re.findall(r"(?:time|时间)[=<]\s*(\d+(?:\.\d+)?)\s*ms", txt)]
    loss = re.search(r"(\d+)%", txt)
    st = _stat(vals)
    if st:
        st["loss_pct"] = float(loss.group(1)) if loss else None
    return st


def net_bytes() -> Optional[int]:
    txt = _ps("(Get-NetAdapterStatistics | Measure-Object -Property ReceivedBytes,SentBytes "
              "-Sum).Sum | ForEach-Object { $_ }")
    nums = re.findall(r"\d+", txt)
    return sum(int(n) for n in nums) if nums else None


def measure_llm(rounds: int) -> Optional[Dict[str, float]]:
    vals: List[float] = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(f"{LLM_URL}/health", timeout=3) as r:
                r.read(64)
            vals.append((time.perf_counter() - t0) * 1000)
        except Exception:
            pass
    return _stat(vals)


def llm_load(stop: threading.Event) -> None:
    """采样期间持续发小请求，制造最坏情况负载。"""
    body = json.dumps({
        "messages": [{"role": "user", "content": "只回答一个字：好"}],
        "max_tokens": 8, "temperature": 0.0, "stream": False,
    }).encode()
    while not stop.is_set():
        try:
            req = urllib.request.Request(f"{LLM_URL}/v1/chat/completions", data=body,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=120) as r:
                r.read(256)
        except Exception:
            pass


# ------------------------------------------------------- Agent 自身状态

def agent_procs() -> List[Dict[str, Any]]:
    try:
        import win_net
    except Exception:
        return []
    names, paths = win_net.process_table(with_path=True)
    out = []
    root = str(ROOT).lower()
    for pid, path in paths.items():
        if path and root in path.lower() and pid > 4:
            out.append({"pid": pid, "name": names.get(pid, "?"), "path": path})
    return out


def agent_sockets(pids: List[int]) -> Dict[str, Any]:
    """返回 Agent 进程持有的连接；重点看有没有非环回的对外连接。"""
    try:
        import win_net
    except Exception:
        return {}
    rows = [r for r in win_net.connections(include_ipv6=True) if r.pid in set(pids)]
    external = [r for r in rows if not win_net.is_loopback_addr(r.remote_ip) and r.remote_ip]
    by_proc: Dict[str, int] = {}
    for r in rows:
        by_proc[str(r.pid)] = by_proc.get(str(r.pid), 0) + 1
    return {
        "total": len(rows),
        "external": len(external),
        "external_detail": sorted({f"{r.pid}:{r.proto}:{r.remote_ip}:{r.remote_port}"
                                   for r in external})[:20],
        "by_pid": by_proc,
        "detail": sorted({f"{r.pid} {r.proto} {r.local_ip}:{r.local_port} -> {r.remote_ip}:{r.remote_port} {r.state}"
                          for r in rows})[:25],
    }


def proc_cost(pids: List[int]) -> List[Dict[str, Any]]:
    out = []
    for pid in pids:
        txt = _ps(f"$p=Get-Process -Id {pid} -EA SilentlyContinue; if($p){{"
                  f"'{{0}}|{{1}}|{{2}}' -f $p.CPU,$p.WorkingSet64,$p.ProcessName}}")
        if "|" in txt:
            cpu, rss, name = txt.split("|")[:3]
            try:
                out.append({"pid": pid, "name": name.strip(),
                            "cpu_sec": round(float(cpu), 2),
                            "rss_mb": round(int(rss) / 1048576, 1)})
            except ValueError:
                pass
    return out


# ---------------------------------------------------------------- 主流程

def run(args: argparse.Namespace) -> Dict[str, Any]:
    start_bytes = net_bytes()
    gw = gateway()
    procs = agent_procs()
    pids = [p["pid"] for p in procs]

    stop = threading.Event()
    th = None
    if args.load_llm:
        th = threading.Thread(target=llm_load, args=(stop,), daemon=True)
        th.start()

    t0 = time.time()
    rec: Dict[str, Any] = {"label": args.label, "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                           "seconds": args.seconds, "load_llm": bool(args.load_llm)}
    rec["dns_ms"] = measure_dns(rounds=args.rounds)
    rec["llm_health_ms"] = measure_llm(rounds=max(3, args.rounds // 3))
    rec["tcp_rtt_ms"] = measure_tcp(rounds=args.rounds)
    rec["gateway"] = gw
    rec["gateway_icmp_ms"] = measure_gateway(gw) if gw else None

    # 补齐剩余采样时间，保证两边窗口一致
    while time.time() - t0 < args.seconds:
        time.sleep(0.2)

    stop.set()
    if th:
        th.join(timeout=5)

    end_bytes = net_bytes()
    if start_bytes is not None and end_bytes is not None and end_bytes >= start_bytes:
        span = max(1.0, time.time() - t0)
        rec["net_bytes_delta"] = end_bytes - start_bytes
        rec["net_kbps"] = round((end_bytes - start_bytes) * 8 / span / 1000, 1)
        rec["window_sec"] = round(span, 1)

    rec["agent_procs"] = procs
    rec["agent_sockets"] = agent_sockets(pids)
    rec["agent_cost"] = proc_cost(pids)
    return rec


def show(rec: Dict[str, Any]) -> None:
    p = print
    p(f"=== {rec['label']} | {rec['ts']} | 窗口 {rec.get('window_sec', rec['seconds'])}s"
      f"{' | LLM 负载中' if rec['load_llm'] else ' | 静默'}")
    for key, title in (("dns_ms", "DNS 解析"), ("llm_health_ms", "本地 LLM 端口"),
                       ("gateway_icmp_ms", f"网关 ICMP ({rec.get('gateway')})")):
        v = rec.get(key)
        p(f"  {title:<22} " + (f"min {v['min']:>7} avg {v['avg']:>7} p95 {v['p95']:>7} max {v['max']:>7} ms (n={v['n']})" if v else "无数据"))
    for tgt, v in (rec.get("tcp_rtt_ms") or {}).items():
        p(f"  {'TCP 握手 ' + tgt:<22} " + (f"min {v['min']:>7} avg {v['avg']:>7} p95 {v['p95']:>7} max {v['max']:>7} ms (n={v['n']})" if v else "无数据"))
    if "net_kbps" in rec:
        p(f"  {'全网卡吞吐':<22} {rec['net_kbps']} kbps（{rec['net_bytes_delta']} 字节）")
    sock = rec.get("agent_sockets") or {}
    if sock:
        p(f"  {'Agent 连接数':<22} 共 {sock['total']}，其中对外（非环回）{sock['external']}")
        for d in (sock.get("external_detail") or [])[:10]:
            p(f"      ! 对外: {d}")
    for c in rec.get("agent_cost") or []:
        p(f"  {'进程 ' + c['name'] + ' (' + str(c['pid']) + ')':<22} CPU {c['cpu_sec']}s  RSS {c['rss_mb']} MB")


def main() -> int:
    ap = argparse.ArgumentParser(description="测量蓝队 Agent 对网络的影响")
    ap.add_argument("--label", default="A")
    ap.add_argument("--seconds", type=float, default=20.0)
    ap.add_argument("--rounds", type=int, default=12)
    ap.add_argument("--load-llm", action="store_true", help="采样期间持续请求本地 LLM（最坏情况）")
    ap.add_argument("--json", default="")
    args = ap.parse_args()

    rec = run(args)
    show(rec)
    if args.json:
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(rec, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n已写入 {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
