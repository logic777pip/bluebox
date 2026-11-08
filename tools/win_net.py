#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/win_net.py — 用 ctypes 直读 Windows 网络表与进程表（**零子进程**）。

为什么必须有这个模块
--------------------

后台服务用 `pythonw.exe` 跑（无控制台）。此时如果再 `subprocess` 去调
`netstat.exe` / `powershell.exe` 这类**控制台程序**，Windows 会为子进程
**新建一个控制台窗口** —— 于是屏幕上不停弹出又消失一个黑框。
实测症状：传感器每轮询一次闪一下（`netstat`），每 60 秒再闪一下（进程表 CIM 查询）。

把 `creationflags=CREATE_NO_WINDOW` 加上能压住窗口，但更好的做法是
**根本不要在热路径上 spawn 进程**：直接调 `iphlpapi` / `kernel32` 的 API。

* 连接表：`GetExtendedTcpTable` / `GetExtendedUdpTable`（含 IPv4 与 IPv6、含 PID）
* 进程表：`CreateToolhelp32Snapshot` + `Process32FirstW/NextW`
* 进程路径：`QueryFullProcessImageNameW`

全部只读，不加载驱动，不改系统设置。
"""

from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from typing import Dict, List, NamedTuple, Optional, Tuple

# ---------------------------------------------------------------- 常量
AF_INET = 2
AF_INET6 = 23
TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID = 1
ERROR_INSUFFICIENT_BUFFER = 122
TH32CS_SNAPPROCESS = 0x00000002
MAX_PATH = 260

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

_TCP_STATES = {
    1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD", 5: "ESTABLISHED",
    6: "FIN_WAIT1", 7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING",
    10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB",
}


class NetRow(NamedTuple):
    proto: str          # TCP / UDP
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    pid: int


# ---------------------------------------------------------------- 结构体
class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [("dwState", wintypes.DWORD),
                ("dwLocalAddr", wintypes.DWORD),
                ("dwLocalPort", wintypes.DWORD),
                ("dwRemoteAddr", wintypes.DWORD),
                ("dwRemotePort", wintypes.DWORD),
                ("dwOwningPid", wintypes.DWORD)]


class MIB_UDPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [("dwLocalAddr", wintypes.DWORD),
                ("dwLocalPort", wintypes.DWORD),
                ("dwOwningPid", wintypes.DWORD)]


class MIB_TCP6ROW_OWNER_PID(ctypes.Structure):
    _fields_ = [("ucLocalAddr", ctypes.c_ubyte * 16),
                ("dwLocalScopeId", wintypes.DWORD),
                ("dwLocalPort", wintypes.DWORD),
                ("ucRemoteAddr", ctypes.c_ubyte * 16),
                ("dwRemoteScopeId", wintypes.DWORD),
                ("dwRemotePort", wintypes.DWORD),
                ("dwState", wintypes.DWORD),
                ("dwOwningPid", wintypes.DWORD)]


class MIB_UDP6ROW_OWNER_PID(ctypes.Structure):
    _fields_ = [("ucLocalAddr", ctypes.c_ubyte * 16),
                ("dwLocalScopeId", wintypes.DWORD),
                ("dwLocalPort", wintypes.DWORD),
                ("dwOwningPid", wintypes.DWORD)]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", ctypes.c_wchar * MAX_PATH)]


_AVAILABLE: Optional[bool] = None


def available() -> bool:
    """Windows 且 API 可用。"""
    global _AVAILABLE
    if _AVAILABLE is None:
        if os.name != "nt":
            _AVAILABLE = False
        else:
            try:
                _iphlpapi().GetExtendedTcpTable
                _AVAILABLE = True
            except Exception:  # noqa: BLE001
                _AVAILABLE = False
    return bool(_AVAILABLE)


def _iphlpapi():
    return ctypes.WinDLL("iphlpapi", use_last_error=True)


def _k32():
    return ctypes.WinDLL("kernel32", use_last_error=True)


# ---------------------------------------------------------------- 地址解析
def _ipv4(dw: int) -> str:
    b = dw.to_bytes(4, "little")
    return ".".join(str(x) for x in b)


def _ipv6(buf) -> str:
    raw = bytes(bytearray(buf))
    parts = [int.from_bytes(raw[i:i + 2], "big") for i in range(0, 16, 2)]
    # 压掉最长的一段 0（RFC 5952 简写）
    best_s = best_len = -1
    s = 0
    for i, p in enumerate(parts + [1]):
        if p == 0:
            if s < 0:
                s = i
        elif s >= 0:
            if i - s > best_len:
                best_s, best_len = s, i - s
            s = -1
    if best_len > 1:
        head = ":".join(f"{x:x}" for x in parts[:best_s])
        tail = ":".join(f"{x:x}" for x in parts[best_s + best_len:])
        return f"{head}::{tail}" if tail else f"{head}::"
    return ":".join(f"{x:x}" for x in parts)


def _port(dw: int) -> int:
    return ((dw & 0xFF) << 8) | ((dw >> 8) & 0xFF)


def _table(func, cls, row_size: int, af: int, table_class: int, proto: str,
           ipv6: bool):
    """调用一个 GetExtended*Table 并解析成 NetRow 列表（两段式：先问大小再读）。"""
    fn = getattr(_iphlpapi(), func)
    fn.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
                   wintypes.ULONG, ctypes.c_int, wintypes.ULONG]
    fn.restype = wintypes.DWORD

    size = wintypes.DWORD(0)
    rc = fn(None, ctypes.byref(size), False, af, table_class, 0)
    if rc not in (0, ERROR_INSUFFICIENT_BUFFER) or size.value == 0:
        return []
    buf = ctypes.create_string_buffer(size.value)
    rc = fn(buf, ctypes.byref(size), False, af, table_class, 0)
    if rc != 0:
        return []

    out: List[NetRow] = []
    count = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD)).contents.value
    base = ctypes.addressof(buf) + ctypes.sizeof(wintypes.DWORD)
    for i in range(count):
        row = cls.from_address(base + i * row_size)
        lip = _ipv6(row.ucLocalAddr) if ipv6 else _ipv4(row.dwLocalAddr)
        lport = _port(row.dwLocalPort)
        if proto == "UDP":
            out.append(NetRow("UDP", lip, lport, "", 0, "", int(row.dwOwningPid)))
            continue
        rip = _ipv6(row.ucRemoteAddr) if ipv6 else _ipv4(row.dwRemoteAddr)
        out.append(NetRow("TCP", lip, lport, rip, _port(row.dwRemotePort),
                          _TCP_STATES.get(int(row.dwState), "UNKNOWN"),
                          int(row.dwOwningPid)))
    return out


def connections(include_ipv6: bool = True) -> List[NetRow]:
    """取全部 TCP/UDP 端点（IPv4 + 可选 IPv6）。零子进程。"""
    if not available():
        return []
    rows: List[NetRow] = []
    rows += _table("GetExtendedTcpTable", MIB_TCPROW_OWNER_PID,
                   ctypes.sizeof(MIB_TCPROW_OWNER_PID), AF_INET,
                   TCP_TABLE_OWNER_PID_ALL, "TCP", False)
    rows += _table("GetExtendedUdpTable", MIB_UDPROW_OWNER_PID,
                   ctypes.sizeof(MIB_UDPROW_OWNER_PID), AF_INET,
                   UDP_TABLE_OWNER_PID, "UDP", False)
    if include_ipv6:
        rows += _table("GetExtendedTcpTable", MIB_TCP6ROW_OWNER_PID,
                       ctypes.sizeof(MIB_TCP6ROW_OWNER_PID), AF_INET6,
                       TCP_TABLE_OWNER_PID_ALL, "TCP", True)
        rows += _table("GetExtendedUdpTable", MIB_UDP6ROW_OWNER_PID,
                       ctypes.sizeof(MIB_UDP6ROW_OWNER_PID), AF_INET6,
                       UDP_TABLE_OWNER_PID, "UDP", True)
    return rows


def is_loopback_addr(ip: str) -> bool:
    """判断地址是否为环回/本机通配（这类连接不等于真实网络活动）。"""
    if not ip:
        return True
    ip = ip.strip().lower()
    return (ip.startswith("127.") or ip in ("::1", "0.0.0.0", "::", "*", "(*)", "0.0.0.0/0")
            or ip.startswith("fe80::1") or ip.startswith("::ffff:127."))


def process_image_path(pid: int) -> str:
    """`QueryFullProcessImageNameW`：取进程可执行文件完整路径。"""
    if os.name != "nt" or pid <= 0:
        return ""
    try:
        k32 = _k32()
        k32.OpenProcess.restype = ctypes.c_void_p
        k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k32.QueryFullProcessImageNameW.argtypes = [
            ctypes.c_void_p, wintypes.DWORD, wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD)]
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            return ""
        try:
            buf = ctypes.create_unicode_buffer(32768)
            size = wintypes.DWORD(len(buf))
            if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                return buf.value
            return ""
        finally:
            k32.CloseHandle(h)
    except Exception:  # noqa: BLE001
        return ""


def process_table(with_path: bool = True) -> Tuple[Dict[int, str], Dict[int, str]]:
    """返回 ``(pid -> 进程名, pid -> 可执行文件路径)``。零子进程。

    用 `CreateToolhelp32Snapshot` 一次拿到全部进程名；路径按需再用
    `QueryFullProcessImageNameW` 逐个取（只对调用方关心的 pid 取更省，但这里
    一次采全表，便于后续按 pid 直接查）。
    """
    names: Dict[int, str] = {}
    paths: Dict[int, str] = {}
    if os.name != "nt":
        return names, paths
    try:
        k32 = _k32()
        k32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
        k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        k32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)]
        k32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)]
        k32.CloseHandle.argtypes = [ctypes.c_void_p]

        snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if not snap or snap == ctypes.c_void_p(-1).value:
            return names, paths
        try:
            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            if not k32.Process32FirstW(snap, ctypes.byref(entry)):
                return names, paths
            while True:
                pid = int(entry.th32ProcessID)
                names[pid] = entry.szExeFile
                if with_path:
                    p = process_image_path(pid)
                    if p:
                        paths[pid] = p
                if not k32.Process32NextW(snap, ctypes.byref(entry)):
                    break
        finally:
            k32.CloseHandle(snap)
    except Exception:  # noqa: BLE001
        pass
    return names, paths


def selftest() -> int:
    ok = total = 0

    def chk(name: str, cond: bool) -> None:
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  [{'ok  ' if cond else 'FAIL'}] {name}")

    print("=== win_net 自检 ===")
    chk("API 可用", available())
    rows = connections()
    chk(f"能读到连接表（{len(rows)} 条）", len(rows) > 0)
    tcp = [r for r in rows if r.proto == "TCP"]
    chk(f"含 TCP 记录（{len(tcp)} 条）", len(tcp) > 0)
    chk("端口解析在 1..65535", all(0 <= r.local_port <= 65535 for r in rows))
    # 注意：不能写 r.state.isalpha() —— "SYN_SENT"/"TIME_WAIT" 含下划线，isalpha() 为 False
    chk("状态词可读", all(r.state == "" or r.state.replace("_", "").isalpha()
                      for r in rows))
    names, paths = process_table()
    chk(f"能读到进程表（{len(names)} 个）", len(names) > 0)
    me = os.getpid()
    chk(f"进程表含自身 pid {me}", me in names)
    chk("能读到自身可执行路径", bool(paths.get(me)))
    print(f"  {ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
