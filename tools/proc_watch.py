#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/proc_watch.py — 基于 WMI/ETW 的**进程创建**事件订阅（事件驱动采集）。

为什么需要它
------------

轮询式采集（`GetExtendedTcpTable` 每 N 秒一次）有一个**结构性盲区**：
短连接 + 长间隔 = 采不到。实弹演练里，每次只保持 1.5 秒的周期信标在 15 秒轮询下
必然漏采；即使把间隔压到 5 秒也只是缓解。

事件驱动能补上这个盲区，而且**不装内核驱动**：Windows 自带
`Win32_ProcessStartTrace`（底层就是 ETW）会在**进程创建的瞬间**投递事件。
拿到事件后立刻做一次高频网络采样，就能抓住「新进程刚建连就消失」的情况。

工程约束：**只能 spawn 一次**
------------------------------

每次轮询都去起 `powershell.exe` 会导致屏幕不停闪黑框（本项目已有教训）。
所以这里起**一个常驻隐藏子进程**，写完 `READY` 后持续把事件写进管道，
Python 侧用后台线程逐行读取。子进程带 `CREATE_NO_WINDOW`，不会闪窗。

失败即降级：拿不到事件不报错退出，而是返回 `available=False`，
调用方退回纯轮询（心跳里会体现出来）。
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Deque, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PS_SCRIPT = Path(__file__).resolve().parent / "proc_watch.ps1"


@dataclass
class ProcEvent:
    pid: int
    name: str
    parent_pid: int = 0
    path: str = ""
    ts: float = 0.0


def _hidden_kwargs() -> dict:
    kw = {}
    if os.name == "nt":
        kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0  # SW_HIDE
        kw["startupinfo"] = si
    return kw


class ProcessWatcher:
    """常驻的进程创建事件订阅器。"""

    def __init__(self, resolve_path: bool = True) -> None:
        self.resolve_path = resolve_path
        self.proc: Optional[subprocess.Popen] = None
        self.available = False
        self.error = ""
        self._events: Deque[ProcEvent] = deque(maxlen=2000)
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.ticks = 0

    # ---------------------------------------------------------------- 生命周期
    def start(self, ready_timeout: float = 25.0) -> bool:
        if os.name != "nt" or not PS_SCRIPT.exists():
            self.error = "非 Windows 或缺少 proc_watch.ps1"
            return False
        try:
            self.proc = subprocess.Popen(
                ["powershell", "-NoProfile", "-NonInteractive",
                 "-ExecutionPolicy", "Bypass", "-File", str(PS_SCRIPT)],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace", bufsize=1,
                **_hidden_kwargs())
        except Exception as exc:  # noqa: BLE001
            self.error = f"启动失败：{exc}"
            return False

        self._thread = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()

        t0 = time.time()
        while time.time() - t0 < ready_timeout:
            if self.available:
                return True
            if self.proc.poll() is not None:
                self.error = self.error or "子进程提前退出"
                return False
            time.sleep(0.2)
        self.error = self.error or "等待 READY 超时"
        self.stop()
        return False

    def _reader(self) -> None:
        assert self.proc and self.proc.stdout
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            if line == "READY":
                self.available = True
                continue
            if line == "TICK":
                self.ticks += 1
                continue
            if line.startswith("ERR"):
                self.error = line
                break
            bits = line.split("\t")
            if len(bits) < 2 or not bits[0].strip().isdigit():
                continue
            pid = int(bits[0])
            path = ""
            if self.resolve_path:
                try:
                    from tools.win_net import process_image_path  # noqa: PLC0415
                    path = process_image_path(pid)
                except Exception:  # noqa: BLE001
                    path = ""
            self._events.append(ProcEvent(pid=pid, name=bits[1].strip(),
                                          parent_pid=int(bits[2]) if len(bits) > 2
                                          and bits[2].strip().isdigit() else 0,
                                          path=path, ts=time.time()))
        self.available = False

    def stop(self) -> None:
        self._stop.set()
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
            except Exception:  # noqa: BLE001
                pass

    # ---------------------------------------------------------------- 读取
    def drain(self) -> List[ProcEvent]:
        out: List[ProcEvent] = []
        while self._events:
            try:
                out.append(self._events.popleft())
            except IndexError:
                break
        return out

    def alive(self) -> bool:
        return bool(self.proc and self.proc.poll() is None)

    def rss_mb(self) -> float:
        """事件源子进程的工作集（MB）。

        ⚠ 这个数很重要：PowerShell 运行时基线约 **80MB**，是传感器本体（6MB）的十几倍。
        不把它算进去就会把总占用报低一个数量级（本项目早期就报过“总共 6.1MB”）。
        """
        if not self.alive() or self.proc is None:
            return 0.0
        return _rss_mb(self.proc.pid)


_SIG_CACHE: Dict[Tuple[str, float], Tuple[str, str]] = {}


def signature_status(path: str) -> Tuple[str, str]:
    """返回 ``(状态, 签发者)``。状态取值同 `Get-AuthenticodeSignature`：
    ``Valid`` / ``NotSigned`` / ``HashMismatch`` / ``NotTrusted`` / ``UnknownError``。

    为什么要校验签名：实测 `%TEMP%` 下启动的**不只是恶意程序** ——
    Visual Studio 安装器会把签名组件自解压到 `%TEMP%\<随机>\` 再运行
    （实测 `BackgroundDownload.exe`，外连 Microsoft/Akamai）。
    单看“从 Temp 启动”无法区分，必须叠加签名这个可验证信号。

    ⚠ 局限：**签名有效不等于无害**（恶意软件也会买证书）。所以只用于**降级**
    （降到阈值以下作信息项留档），不当作“已证明无害”。
    """
    import os as _os  # noqa: PLC0415
    if _os.name != "nt" or not path:
        return "UnknownError", ""
    try:
        mtime = _os.path.getmtime(path)
    except OSError:
        return "UnknownError", ""
    key = (path.lower(), mtime)
    if key in _SIG_CACHE:
        return _SIG_CACHE[key]

    ps = ("$s=Get-AuthenticodeSignature -LiteralPath '" + path.replace("'", "''") + "';"
          "$sub=''; if($s.SignerCertificate){$sub=$s.SignerCertificate.Subject};"
          "Write-Output ($s.Status.ToString() + [char]9 + $sub)")
    try:
        p = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=25, **_hidden_kwargs())
        out = (p.stdout or "").strip()
        bits = out.split("\t")
        res = (bits[0].strip() if bits else "UnknownError",
               bits[1].strip() if len(bits) > 1 else "")
    except Exception:  # noqa: BLE001
        res = ("UnknownError", "")
    _SIG_CACHE[key] = res
    return res


def _rss_mb(pid: int) -> float:
    if os.name != "nt" or pid <= 0:
        return 0.0
    try:
        import ctypes  # noqa: PLC0415
        from ctypes import wintypes  # noqa: PLC0415

        class _PMC(ctypes.Structure):
            _fields_ = [("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong),
                        ("PeakWorkingSetSize", ctypes.c_size_t),
                        ("WorkingSetSize", ctypes.c_size_t),
                        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                        ("PagefileUsage", ctypes.c_size_t),
                        ("PeakPagefileUsage", ctypes.c_size_t)]

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.OpenProcess.restype = ctypes.c_void_p
        k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        h = k32.OpenProcess(0x1000, False, pid)
        if not h:
            return 0.0
        try:
            mc = _PMC()
            mc.cb = ctypes.sizeof(mc)
            if ctypes.WinDLL("psapi").GetProcessMemoryInfo(h, ctypes.byref(mc), mc.cb):
                return round(mc.WorkingSetSize / 1024 / 1024, 1)
            return 0.0
        finally:
            k32.CloseHandle(h)
    except Exception:  # noqa: BLE001
        return 0.0


# --------------------------------------------------------------------------- #
#  自检
# --------------------------------------------------------------------------- #

def selftest() -> int:
    ok = total = 0

    def chk(name: str, cond: bool) -> None:
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  [{'ok  ' if cond else 'FAIL'}] {name}")

    print("=== proc_watch 自检 ===")
    chk("脚本存在", PS_SCRIPT.exists())
    if os.name != "nt":
        print("  非 Windows，跳过运行时部分")
        print(f"  {ok}/{total} 通过")
        return 0 if ok == total else 1

    w = ProcessWatcher()
    total += 1
    started = w.start()
    ok += started
    print(f"  [{'ok  ' if started else 'FAIL'}] 订阅成功 {'' if started else w.error}")
    if not started:
        print(f"  {ok}/{total} 通过（拿不到事件时应降级为纯轮询，不阻断）")
        return 0 if ok == total else 1

    # 起一个子进程，应当在事件流里看到它
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(6)"],
                             **_hidden_kwargs())
    seen: List[ProcEvent] = []
    t0 = time.time()
    while time.time() - t0 < 15 and not any(e.pid == child.pid for e in seen):
        seen += w.drain()
        time.sleep(0.3)
    hit = any(e.pid == child.pid for e in seen)
    total += 1
    ok += hit
    print(f"  [{'ok  ' if hit else 'FAIL'}] 捕获到新建子进程 pid={child.pid}"
          f"（共收到 {len(seen)} 个事件）")
    total += 1
    ok += bool(seen and seen[0].name)
    print(f"  [{'ok  ' if seen and seen[0].name else 'FAIL'}] 事件含进程名"
          f"（样例：{seen[0].name if seen else '-'}）")

    try:
        child.terminate()
    except Exception:  # noqa: BLE001
        pass
    w.stop()
    print(f"  {ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
