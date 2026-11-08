#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/resource_probe.py — 资源占用探针（CPU / 内存 / 显存 / 推理 token）。

为什么需要：评测只看「识别率」是不够的。同一个模型换更长的提示词可以刷高识别率，
但代价是显存、时延与 token 开销 —— 不量化这些，「识别率提升」是不可信的结论。

采集口径（刻意分开「被测进程」与「宿主」）：

* **CPU / 内存**  : 指定进程（默认 llama-server）的累计 CPU 秒 与 工作集 MB
                    —— Windows 用 GetProcessTimes/GetProcessMemoryInfo，Linux 读 /proc
* **显存**        : `nvidia-smi --query-gpu=memory.used`（整卡口径，需减去空载基线）
* **推理 token**  : llama-server `/metrics` 的 `llamacpp:tokens_predicted_total` 等计数器
                    （比按字符估算可靠；计数器是累计值，用前后差值）

用法::

    python tools/resource_probe.py --name llama-server
    python tools/resource_probe.py --name llama-server --port 8080 --json
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import subprocess
import sys
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# ---------------------------------------------------------------- Windows API
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


class _FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", ctypes.c_ulong), ("dwHighDateTime", ctypes.c_ulong)]


class _PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.c_ulong),
        ("PageFaultCount", ctypes.c_ulong),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


def _ft_to_seconds(ft: _FILETIME) -> float:
    return ((ft.dwHighDateTime << 32) | ft.dwLowDateTime) / 1e7


@dataclass
class Sample:
    cpu_seconds: float = 0.0
    rss_mb: float = 0.0
    peak_rss_mb: float = 0.0
    vram_mb: float = 0.0
    processes: int = 0
    tokens_prompt: int = 0
    tokens_predicted: int = 0
    metrics_ok: bool = False
    # token 计量的权威来源之一：被测后端的 usage 累加（由调用方填入）
    extra: Dict[str, Any] = field(default_factory=dict)
    # 本次采样实际纳入统计的进程镜像路径（用于暴露“同名进程混入”这类量具故障）
    image_paths: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def minus(self, other: "Sample") -> "Sample":
        """构造「本阶段」样本。

        口径区分（**重要**，报告里必须如实标注）：

        * **计数器**（CPU 秒、token）→ 相减，得到本阶段消耗
        * **仪表值**（RSS / VRAM）→ 直接取 ``self`` 的瞬时值（内存占用是「有多少」
          而不是「用了多少增量」），不是差值
        * **峰值**→ 取两者较大者
        """
        return Sample(
            cpu_seconds=round(self.cpu_seconds - other.cpu_seconds, 3),
            rss_mb=round(self.rss_mb, 1),
            peak_rss_mb=round(max(self.peak_rss_mb, other.peak_rss_mb), 1),
            vram_mb=round(self.vram_mb, 1),
            processes=self.processes,
            tokens_prompt=max(0, self.tokens_prompt - other.tokens_prompt),
            tokens_predicted=max(0, self.tokens_predicted - other.tokens_predicted),
            metrics_ok=self.metrics_ok,
            image_paths=list(self.image_paths),
        )


def _proc_image_path(pid: int) -> str:
    """取进程可执行文件的完整路径（Windows: QueryFullProcessImageNameW）。

    为什么需要：**按进程名匹配是不够的**。实测发现 Ollama 自带的
    `Ollama\lib\ollama\llama-server.exe` 与本项目的 `deployment/.../llama-server.exe`
    **同名**，如果 Ollama 在跑，按名字匹配会把它的 7.5GB 工作集算进本项目被测进程，
    整个「资源占用」指标直接失真。必须拿到路径再过滤。
    """
    if os.name != "nt":
        try:
            return os.readlink(f"/proc/{pid}/exe")
        except Exception:  # noqa: BLE001
            return ""
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.OpenProcess.restype = ctypes.c_void_p
        k32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_bool, ctypes.c_ulong]
        k32.QueryFullProcessImageNameW.argtypes = [
            ctypes.c_void_p, ctypes.c_ulong, ctypes.c_wchar_p,
            ctypes.POINTER(ctypes.c_ulong)]
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        h = k32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            return ""
        try:
            buf = ctypes.create_unicode_buffer(32768)
            size = ctypes.c_ulong(len(buf))
            if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                return buf.value
            return ""
        finally:
            k32.CloseHandle(h)
    except Exception:  # noqa: BLE001
        return ""


def _pids_by_name(name: str, path_contains: Optional[str] = None) -> tuple[List[int], List[str]]:
    """按进程名取 PID（Windows 走 tasklist，Linux 走 pgrep）。

    返回 ``(pids, 被排除的镜像路径)``。``path_contains`` 非空时只保留可执行文件路径
    包含该子串的进程；被排除的路径会被返回，便于调用方**如实记录**而不是默默丢弃。
    """
    if os.name == "nt":
        try:
            out = subprocess.run(["tasklist", "/FI", f"IMAGENAME eq {name}.exe",
                                  "/NH", "/FO", "CSV"],
                                 capture_output=True, text=True, timeout=10).stdout
        except Exception:  # noqa: BLE001
            return [], []
        pids = []
        for line in out.splitlines():
            m = re.match(r'"[^"]+","(\d+)"', line.strip())
            if m:
                pids.append(int(m.group(1)))
    else:
        try:
            out = subprocess.run(["pgrep", "-x", name], capture_output=True,
                                 text=True, timeout=5).stdout
            pids = [int(x) for x in out.split() if x.strip().isdigit()]
        except Exception:  # noqa: BLE001
            return [], []

    if not path_contains:
        return pids, []
    want = os.path.normcase(str(path_contains))
    keep: List[int] = []
    dropped: List[str] = []
    for pid in pids:
        img = _proc_image_path(pid)
        if want in os.path.normcase(img) or (not img and not path_contains):
            keep.append(pid)
        else:
            dropped.append(img or f"<pid {pid} 路径不可读>")
    return keep, dropped


def _proc_stats(pid: int) -> tuple[float, float, float]:
    """返回 (cpu_seconds, rss_mb, peak_rss_mb)。取不到返回 (0,0,0)。"""
    if os.name == "nt":
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        h = k32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            return 0.0, 0.0, 0.0
        try:
            c, e, k, u = _FILETIME(), _FILETIME(), _FILETIME(), _FILETIME()
            cpu = 0.0
            if k32.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e),
                                   ctypes.byref(k), ctypes.byref(u)):
                cpu = _ft_to_seconds(k) + _ft_to_seconds(u)
            mc = _PROCESS_MEMORY_COUNTERS()
            mc.cb = ctypes.sizeof(mc)
            rss = peak = 0.0
            if ctypes.WinDLL("psapi").GetProcessMemoryInfo(h, ctypes.byref(mc), mc.cb):
                rss = mc.WorkingSetSize / 1024 / 1024
                peak = mc.PeakWorkingSetSize / 1024 / 1024
            return cpu, rss, peak
        finally:
            k32.CloseHandle(h)
    try:
        stat = Path(f"/proc/{pid}/stat").read_text().split()
        hz = os.sysconf("SC_CLK_TCK") or 100
        cpu = (int(stat[13]) + int(stat[14])) / hz
        rss = int(stat[23]) * (os.sysconf("SC_PAGE_SIZE") or 4096) / 1024 / 1024
        st = Path(f"/proc/{pid}/status").read_text()
        peak = float(re.search(r"VmHWM:\s+(\d+)", st).group(1)) / 1024 if "VmHWM" in st else rss
        return cpu, rss, peak
    except Exception:  # noqa: BLE001
        return 0.0, 0.0, 0.0


def _vram_mb() -> float:
    try:
        out = subprocess.run(["nvidia-smi", "--query-gpu=memory.used", "--format=csv,noheader,nounits"],
                             capture_output=True, text=True, timeout=10).stdout
        vals = [float(x) for x in re.findall(r"\d+", out)]
        return max(vals) if vals else 0.0
    except Exception:  # noqa: BLE001
        return 0.0


_METRIC_KEYS = ("llamacpp:tokens_predicted_total", "llamacpp:tokens_evaluated_total",
                "llamacpp:prompt_tokens_total")


def _server_metrics(host: str, port: int) -> tuple[int, int, bool]:
    """从 llama-server /metrics 读 token 计数器，返回 (prompt, predicted, ok)。"""
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/metrics", timeout=5) as resp:
            text = resp.read().decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return 0, 0, False
    vals: Dict[str, float] = {}
    for line in text.splitlines():
        if line.startswith("#") or " " not in line:
            continue
        name, _, v = line.rpartition(" ")
        vals[name.strip()] = float(v) if v.strip().replace(".", "", 1).isdigit() else 0.0
    prompt = int(vals.get("llamacpp:tokens_evaluated_total",
                          vals.get("llamacpp:prompt_tokens_total", 0.0)))
    predicted = int(vals.get("llamacpp:tokens_predicted_total", 0.0))
    return prompt, predicted, True


def sample(name: str = "llama-server", host: str = "127.0.0.1", port: int = 8080,
           with_vram: bool = True, path_contains: Optional[str] = None) -> Sample:
    """采一次样。

    ⚠ 强烈建议传 ``path_contains``（一般传项目根目录）：不传时只按进程名匹配，
    机器上任何**同名**进程（典型：Ollama 自带的 llama-server.exe）都会被加进来。
    """
    pids, dropped = _pids_by_name(name, path_contains)
    cpu = rss = peak = 0.0
    paths: List[str] = []
    for pid in pids:
        c, r, p = _proc_stats(pid)
        cpu += c
        rss += r
        peak += p
        paths.append(_proc_image_path(pid) or f"<pid {pid}>")
    if dropped:
        print(f"[resource_probe] 已排除 {len(dropped)} 个同名但不在 {path_contains} 下的进程: "
              f"{dropped}", file=sys.stderr)
    if len({p for p in paths}) > 1:
        print(f"[resource_probe] 警告：本次采样合并了多个不同镜像路径 {paths}",
              file=sys.stderr)
    prompt, predicted, ok = _server_metrics(host, port)
    return Sample(
        cpu_seconds=round(cpu, 3), rss_mb=round(rss, 1), peak_rss_mb=round(peak, 1),
        vram_mb=round(_vram_mb(), 1) if with_vram else 0.0, processes=len(pids),
        tokens_prompt=prompt, tokens_predicted=predicted, metrics_ok=ok,
        image_paths=paths,
    )


def summarize(samples: List[Sample]) -> Dict[str, Any]:
    """把逐案采样汇总成报告用的统计量。"""
    if not samples:
        return {}
    n = len(samples)
    cpu = [s.cpu_seconds for s in samples]
    rss = [s.rss_mb for s in samples]
    vram = [s.vram_mb for s in samples]
    lat = [s.extra.get("latency_s", 0.0) for s in samples]
    pt = [s.extra.get("prompt_tokens", 0) for s in samples]
    ct = [s.extra.get("completion_tokens", 0) for s in samples]

    def stat(xs: List[float]) -> Dict[str, float]:
        xs = sorted(xs)
        return {"mean": round(sum(xs) / n, 3), "max": round(xs[-1], 3),
                "p50": round(xs[n // 2], 3), "p95": round(xs[min(n - 1, int(n * 0.95))], 3)}

    return {
        "cases": n,
        "cpu_seconds": stat(cpu),
        "rss_mb": stat(rss),
        "peak_rss_mb": round(max(s.peak_rss_mb for s in samples), 1),
        "vram_mb": stat(vram),
        "vram_peak_mb": round(max(vram), 1),
        "latency_s": stat(lat),
        "tokens_prompt": stat([float(x) for x in pt]),
        "tokens_completion": stat([float(x) for x in ct]),
        "tokens_prompt_total": sum(pt),
        "tokens_completion_total": sum(ct),
        "tokens_total": sum(pt) + sum(ct),
        "tokens_per_case_mean": round((sum(pt) + sum(ct)) / n, 1),
    }


def selftest() -> int:
    """自检：同名进程必须能被路径过滤掉。

    回归背景：机器上同时跑着 Ollama 自带的 `llama-server.exe` 与本项目的
    `llama-server.exe`，只按名字匹配会把两者工作集相加（实测多算 7495MB）。
    """
    ok = 0
    total = 0
    all_pids, _ = _pids_by_name("llama-server")
    paths = {p: _proc_image_path(p) for p in all_pids}
    total += 1
    readable = all(bool(v) for v in paths.values())
    ok += readable
    print(f"  [{'ok  ' if readable else 'FAIL'}] 能读到同名进程的镜像路径 "
          f"({len(paths)} 个)")

    total += 1
    filtered, dropped = _pids_by_name("llama-server", str(PROJECT_ROOT))
    foreign = [p for p in filtered
               if str(PROJECT_ROOT).lower() not in (paths.get(p) or "").lower()]
    good = not foreign
    ok += good
    print(f"  [{'ok  ' if good else 'FAIL'}] 按项目路径过滤后不含外来同名进程 "
          f"(保留 {len(filtered)}，排除 {len(dropped)})")
    for p, v in paths.items():
        tag = "保留" if p in filtered else "排除"
        print(f"        pid {p:<7} [{tag}] {v}")

    total += 1
    s = sample("llama-server", path_contains=str(PROJECT_ROOT), with_vram=False)
    good = s.processes == len(filtered) and set(s.image_paths) <= set(paths.values())
    ok += good
    print(f"  [{'ok  ' if good else 'FAIL'}] sample() 只统计过滤后的进程 "
          f"(processes={s.processes}, RSS={s.rss_mb}MB)")

    print(f"  {ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="资源占用探针")
    ap.add_argument("--name", default="llama-server")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--path-contains", default=None,
                    help="只统计可执行文件路径含该子串的进程（建议传项目根目录）")
    ap.add_argument("--no-vram", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        raise SystemExit(selftest())
    s = sample(args.name, args.host, args.port, with_vram=not args.no_vram,
               path_contains=args.path_contains)
    if args.json:
        print(json.dumps(s.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(f"进程 {args.name}: {s.processes} 个 | CPU {s.cpu_seconds}s | "
              f"RSS {s.rss_mb}MB (峰值 {s.peak_rss_mb}MB) | 显存 {s.vram_mb}MB")
        print(f"token 计数: prompt={s.tokens_prompt} predicted={s.tokens_predicted} "
              f"metrics={'ok' if s.metrics_ok else '不可用'}")
        for p in s.image_paths:
            print(f"  纳入统计: {p}")
