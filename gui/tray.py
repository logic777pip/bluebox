#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gui/tray.py — 纯 ctypes 实现的 Windows 托盘图标（通知区域）。

为什么不用 pystray / PyQt
-------------------------

本项目的依赖纪律是"能用标准库就不装包"（见 gui/__init__.py）。托盘功能
Win32 原生就有（`Shell_NotifyIconW`），ctypes 直接调即可，~200 行换掉一个
第三方依赖 + 一个 GUI 框架。

它解决的具体问题
----------------

GUI 以**无窗口**方式开机自启（`pythonw.exe`，见 `tools/install_gui_autostart.ps1`）。
无窗口意味着用户没有任何可见入口 —— 托盘图标就是这个入口：
左键单击打开控制台，右键出菜单。没有它，"后台静默自启"等于"用户再也找不到它"。

实现要点（都是踩过的坑）
------------------------

1. **必须有一个真窗口**（不能是 message-only 窗口）：Explorer 重启后会广播
   `TaskbarCreated`，收不到就该重新 `Shell_NotifyIconW(NIM_ADD)`；message-only
   窗口收不到广播，图标会就此消失直到进程重启。
2. **弹菜单前要 `SetForegroundWindow`**：否则菜单点了别处不消失（光标"粘住"菜单）。
3. **退出前一定要 `NIM_DELETE`**：否则任务栏留一个"僵尸图标"，鼠标划过才消失。
4. **`NOTIFYICONDATAW.cbSize` 必须填对**：结构体随版本变长，填错 → 调用静默失败
   （返回 False 但不告诉你为什么）。所以回读并断言返回值。
"""

from __future__ import annotations

import ctypes
import os
import struct
import sys
import threading
import webbrowser
from ctypes import wintypes
from pathlib import Path
from typing import Any, Callable, Optional

IS_WINDOWS = os.name == "nt"

# --------------------------------------------------------------------------- #
# Win32 常量
# --------------------------------------------------------------------------- #
WM_DESTROY = 0x0002
WM_CLOSE = 0x0010
WM_COMMAND = 0x0111
WM_NULL = 0x0000
WM_APP = 0x8000
WM_TRAYICON = WM_APP + 1          # 托盘回调消息
WM_LBUTTONUP = 0x0202
WM_RBUTTONUP = 0x0205
WM_LBUTTONDBLCLK = 0x0203

NIM_ADD = 0x00000000
NIM_MODIFY = 0x00000001
NIM_DELETE = 0x00000002
NIF_MESSAGE = 0x00000001
NIF_ICON = 0x00000002
NIF_TIP = 0x00000004
NIF_INFO = 0x00000010

MF_STRING = 0x00000000
MF_SEPARATOR = 0x00000800
MF_GRAYED = 0x00000001

TPM_RIGHTALIGN = 0x0008
TPM_BOTTOMALIGN = 0x0020
TPM_RETURNCMD = 0x0100

IDI_APPLICATION = 32512
IMAGE_ICON = 1
LR_LOADFROMFILE = 0x0010
LR_DEFAULTSIZE = 0x0040

CS_HREDRAW = 0x0002
CS_VREDRAW = 0x0001

# 菜单项 ID
IDM_OPEN = 1001
IDM_COPY = 1002
IDM_STATUS = 1003
IDM_LOGS = 1004
IDM_EXIT = 1099


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]


class NOTIFYICONDATAW(ctypes.Structure):
    """完整版结构（Shell v5+）。字段顺序与 SDK 头文件一致。"""
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("hWnd", wintypes.HWND),
        ("uID", wintypes.UINT),
        ("uFlags", wintypes.UINT),
        ("uCallbackMessage", wintypes.UINT),
        ("hIcon", wintypes.HICON),
        ("szTip", wintypes.WCHAR * 128),
        ("dwState", wintypes.DWORD),
        ("dwStateMask", wintypes.DWORD),
        ("szInfo", wintypes.WCHAR * 256),
        ("uVersion", wintypes.UINT),
        ("szInfoTitle", wintypes.WCHAR * 64),
        ("dwInfoFlags", wintypes.DWORD),
        ("guidItem", GUID),
        ("hBalloonIcon", wintypes.HICON),
    ]


WNDPROCTYPE = ctypes.WINFUNCTYPE(
    ctypes.c_longlong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_long,
    wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)


class WNDCLASSEXW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.UINT),
        ("style", wintypes.UINT),
        ("lpfnWndProc", WNDPROCTYPE),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wintypes.HINSTANCE),
        ("hIcon", wintypes.HICON),
        ("hCursor", wintypes.HANDLE),
        ("hbrBackground", wintypes.HBRUSH),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
        ("hIconSm", wintypes.HICON),
    ]


# --------------------------------------------------------------------------- #
# 生成一个自有图标（免得用通用问号图标）
# --------------------------------------------------------------------------- #

def make_icon(path: Path, size: int = 32) -> bool:
    """画一个"监控眼"图标并存成 .ico（纯 Python 写 ICO，不依赖 Pillow）。

    32bpp BGRA + 全零 AND 掩码：现代 Windows 用 alpha 通道，AND 掩码填 0 即可。
    图形是蓝环 + 白底 + 蓝色瞳孔 —— 在深色/浅色任务栏上都看得清。
    """
    try:
        cx = cy = (size - 1) / 2.0
        r_outer, r_inner, r_pupil = size * 0.47, size * 0.36, size * 0.17
        px = bytearray()
        for y in range(size):
            row = bytearray()
            for x in range(size):
                d = ((x - cx) ** 2 + (y - cy) ** 2) ** 0.5
                if d > r_outer:
                    row += bytes((0, 0, 0, 0))              # 透明
                elif d > r_inner:
                    row += bytes((235, 111, 31, 255))       # 蓝环（BGRA）
                elif d <= r_pupil:
                    row += bytes((235, 111, 31, 255))       # 蓝瞳
                else:
                    row += bytes((255, 255, 255, 255))      # 白底
            px += row
        # DIB 行序自下而上
        rows = [bytes(px[i * size * 4:(i + 1) * size * 4]) for i in range(size)]
        xor = b"".join(reversed(rows))
        and_mask = b"\x00" * (((size + 31) // 32) * 4) * size
        dib = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0,
                          len(xor) + len(and_mask), 0, 0, 0, 0) + xor + and_mask
        hdr = struct.pack("<HHH", 0, 1, 1)
        ent = struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32,
                          len(dib), 6 + 16)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(hdr + ent + dib)
        return True
    except Exception:  # noqa: BLE001
        return False


# --------------------------------------------------------------------------- #
# 托盘
# --------------------------------------------------------------------------- #

class TrayIcon:
    """通知区域图标 + 菜单。在**主线程**跑消息循环。"""

    WNDPROC_REF: Any = None      # 必须保活：回调被 GC 掉 → 进程崩
    #: 日志钩子。server 会把写 logs/gui.log 的函数塞进实例；用类属性兜底是为了
    #: 让"忘了传 logger"也不会崩（托盘是用户唯一入口，不能因为日志没配好就挂掉）。
    logger: Optional[Callable[[str], None]] = None

    def __init__(self, *, url: str = "", title: str = "蓝队 Agent 控制台",
                 tooltip: str = "", on_exit: Optional[Callable[[], None]] = None,
                 status_text: Optional[Callable[[], str]] = None,
                 icon_path: Optional[Path] = None,
                 logger: Optional[Callable[[str], None]] = None) -> None:
        if not IS_WINDOWS:
            raise RuntimeError("托盘图标仅支持 Windows")
        self.url = url
        self.title = title
        self.tooltip = (tooltip or title)[:127]
        self.on_exit = on_exit
        self.status_text = status_text
        self.logger = logger
        self.icon_path = icon_path or (Path(__file__).resolve().parent / "static" / "agent.ico")
        self.hwnd: Optional[int] = None
        self.hicon = None
        self._nid: Optional[NOTIFYICONDATAW] = None
        self._cls = "BlueTeamAgentTrayWnd"
        self._uid = 1
        self._icon_added = False
        self._stop = threading.Event()
        self._ready = threading.Event()
        self.error: Optional[str] = None

        self.user32 = ctypes.windll.user32
        self.shell32 = ctypes.windll.shell32
        self.kernel32 = ctypes.windll.kernel32
        self._declare()

    # -- 原型声明：不声明的话 64 位下句柄会被截成 32 位 --
    def _declare(self) -> None:
        u, s, k = self.user32, self.shell32, self.kernel32
        k.GetModuleHandleW.restype = wintypes.HMODULE
        k.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        u.CreateWindowExW.restype = wintypes.HWND
        u.CreateWindowExW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                      wintypes.DWORD, ctypes.c_int, ctypes.c_int,
                                      ctypes.c_int, ctypes.c_int, wintypes.HWND,
                                      wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID]
        u.DefWindowProcW.restype = ctypes.c_longlong
        u.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT,
                                     wintypes.WPARAM, wintypes.LPARAM]
        u.LoadIconW.restype = wintypes.HICON
        u.LoadImageW.restype = wintypes.HANDLE
        u.LoadImageW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR, wintypes.UINT,
                                 ctypes.c_int, ctypes.c_int, wintypes.UINT]
        u.CreatePopupMenu.restype = wintypes.HMENU
        u.TrackPopupMenu.restype = wintypes.BOOL
        u.RegisterWindowMessageW.restype = wintypes.UINT
        s.Shell_NotifyIconW.restype = wintypes.BOOL

    # -- 图标 --
    def _say(self, msg: str) -> None:
        """写一行日志。托盘是"用户唯一的入口"，它到底挂上没挂上必须留痕 ——
        否则出问题时只能靠外部探测窗口类，而那个方法不可靠（见 install 脚本的自检）。"""
        lg = TrayIcon.logger or self.logger
        if lg:
            try:
                lg(msg)
            except Exception:  # noqa: BLE001
                pass

    def _load_icon(self):
        if self.icon_path.is_file():
            h = self.user32.LoadImageW(None, str(self.icon_path), IMAGE_ICON,
                                       16, 16, LR_LOADFROMFILE)
            if h:
                return h
        else:
            if make_icon(self.icon_path):
                h = self.user32.LoadImageW(None, str(self.icon_path), IMAGE_ICON,
                                           16, 16, LR_LOADFROMFILE)
                if h:
                    return h
        return self.user32.LoadIconW(None, wintypes.LPCWSTR(IDI_APPLICATION))

    def _on_message(self, hwnd, msg, wparam, lparam):
        try:
            if msg == WM_TRAYICON:
                ev = lparam & 0xFFFF
                if ev in (WM_LBUTTONUP, WM_LBUTTONDBLCLK):
                    self.open_console()
                elif ev == WM_RBUTTONUP:
                    self._menu()
                return 0
            if msg == self._wm_taskbar_created and self._wm_taskbar_created:
                self._icon_added = False
                self._add_icon()          # Explorer 重启后重新挂上
                return 0
            if msg == WM_COMMAND:
                cmd = wparam & 0xFFFF
                if cmd == IDM_OPEN:
                    self.open_console()
                elif cmd == IDM_COPY:
                    self._copy_url()
                elif cmd == IDM_STATUS:
                    self._show_status()
                elif cmd == IDM_LOGS:
                    self._open_logs()
                elif cmd == IDM_EXIT:
                    self.quit()
                return 0
            if msg == WM_DESTROY:
                self.user32.PostQuitMessage(0)
                return 0
        except Exception as exc:  # noqa: BLE001
            self.error = f"{type(exc).__name__}: {exc}"
        return self.user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def _menu(self) -> None:
        u = self.user32
        m = u.CreatePopupMenu()
        u.AppendMenuW(m, MF_STRING, IDM_OPEN, "打开控制台(&O)")
        u.AppendMenuW(m, MF_STRING, IDM_COPY, "复制访问地址(&C)")
        u.AppendMenuW(m, MF_SEPARATOR, 0, None)
        u.AppendMenuW(m, MF_STRING, IDM_STATUS, "查看运行状态(&S)")
        u.AppendMenuW(m, MF_STRING, IDM_LOGS, "打开输出目录(&L)")
        u.AppendMenuW(m, MF_SEPARATOR, 0, None)
        u.AppendMenuW(m, MF_STRING, IDM_EXIT, "退出(&X)")
        pt = wintypes.POINT()
        u.GetCursorPos(ctypes.byref(pt))
        # 不先 SetForegroundWindow 的话，菜单点别处不消失
        u.SetForegroundWindow(self.hwnd)
        cmd = u.TrackPopupMenu(m, TPM_RIGHTALIGN | TPM_BOTTOMALIGN | TPM_RETURNCMD,
                               pt.x, pt.y, 0, self.hwnd, None)
        u.DestroyMenu(m)
        if cmd:
            u.PostMessageW(self.hwnd, WM_COMMAND, cmd, 0)

    # -- 对外动作 --
    def open_console(self, *_a) -> bool:
        if not self.url:
            return False
        try:
            webbrowser.open(self.url)
            return True
        except Exception:  # noqa: BLE001
            # 备用：直接掀起默认浏览器
            try:
                os.startfile(self.url)  # noqa: S606
                return True
            except Exception:  # noqa: BLE001
                return False

    def _copy_url(self) -> None:
        """把地址放剪贴板（令牌太长，手抄不现实）。"""
        try:
            u = self.user32
            k = self.kernel32
            if not u.OpenClipboard(self.hwnd):
                return
            try:
                u.EmptyClipboard()
                data = self.url.encode("utf-16-le") + b"\x00\x00"
                GMEM_MOVEABLE = 0x0002
                h = k.GlobalAlloc(GMEM_MOVEABLE, len(data))
                p = k.GlobalLock(h)
                ctypes.memmove(p, data, len(data))
                k.GlobalUnlock(h)
                u.SetClipboardData(13, h)      # CF_UNICODETEXT
            finally:
                u.CloseClipboard()
            self._balloon("地址已复制", "粘贴到浏览器即可打开控制台。")
        except Exception:  # noqa: BLE001
            pass

    def _show_status(self) -> None:
        txt = "（无状态信息）"
        if self.status_text:
            try:
                txt = str(self.status_text())[:250]
            except Exception as exc:  # noqa: BLE001
                txt = f"取状态失败：{type(exc).__name__}"
        self._balloon("运行状态", txt)

    def _open_logs(self) -> None:
        try:
            from gui import core
            core.open_in_explorer("logs")
        except Exception:  # noqa: BLE001
            pass

    def _balloon(self, title: str, text: str) -> None:
        if not self._nid:
            return
        n = self._nid
        n.uFlags = NIF_INFO
        n.szInfoTitle = title[:63]
        n.szInfo = text[:255]
        n.dwInfoFlags = 0x00000001           # NIIF_INFO
        self.shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(n))

    # -- 生命周期 --
    def _add_icon(self) -> None:
        n = NOTIFYICONDATAW()
        n.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        n.hWnd = self.hwnd
        n.uID = self._uid
        n.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        n.uCallbackMessage = WM_TRAYICON
        n.hIcon = self.hicon
        n.szTip = self.tooltip
        self._nid = n
        ok = bool(self.shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(n)))
        self._icon_added = ok
        if ok:
            self._say(f"托盘图标已挂上（窗口类 {self._cls}，hwnd={self.hwnd}）")
        else:
            self.error = ("Shell_NotifyIconW(NIM_ADD) 失败 —— "
                          "托盘图标未能加入通知区域（可能 Explorer 未运行或结构体被拒）")
            self._say("错误：" + self.error)

    def quit(self, *_a) -> None:
        self._stop.set()
        if self._nid and self._icon_added:
            try:
                self.shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(self._nid))
            except Exception:  # noqa: BLE001
                pass
            self._icon_added = False
        if self.hwnd:
            try:
                self.user32.PostMessageW(self.hwnd, WM_DESTROY, 0, 0)
            except Exception:  # noqa: BLE001
                pass
        if self.on_exit:
            try:
                self.on_exit()
            except Exception:  # noqa: BLE001
                pass

    def shutdown(self, *_a) -> None:
        """线程安全地请求退出（供 HTTP 线程调用）。"""
        self._stop.set()
        if self.hwnd:
            self.user32.PostMessageW(self.hwnd, WM_DESTROY, 0, 0)

    def run(self, *, notify_url: bool = True) -> None:
        """创建窗口 + 挂图标 + 跑消息循环（阻塞直到退出）。"""
        k, u = self.kernel32, self.user32
        hinst = k.GetModuleHandleW(None)
        self._wm_taskbar_created = u.RegisterWindowMessageW("TaskbarCreated")

        def _proc(hwnd, msg, wparam, lparam):
            return self._on_message(hwnd, msg, wparam, lparam)

        TrayIcon.WNDPROC_REF = WNDPROCTYPE(_proc)     # 保活
        wc = WNDCLASSEXW()
        wc.cbSize = ctypes.sizeof(WNDCLASSEXW)
        wc.style = CS_HREDRAW | CS_VREDRAW
        wc.lpfnWndProc = TrayIcon.WNDPROC_REF
        wc.hInstance = hinst
        wc.lpszClassName = self._cls
        if not u.RegisterClassExW(ctypes.byref(wc)):
            err = ctypes.get_last_error() or k.GetLastError()
            # 类已存在（重复启动）也继续
            if not self.error:
                self.error = f"RegisterClassExW 失败（GetLastError={err}）"

        # 真窗口（不可见）：消息-only 窗口收不到 TaskbarCreated 广播
        self.hwnd = u.CreateWindowExW(0, self._cls, self.title, 0, 0, 0, 0, 0,
                                      None, None, hinst, None)
        if not self.hwnd:
            self.error = "CreateWindowExW 失败"
            raise RuntimeError(self.error)

        self.hicon = self._load_icon()
        self._add_icon()
        self._ready.set()
        self._say(f"托盘就绪：左键单击打开 {self.url}")

        if notify_url and self.url:
            self._balloon("控制台已启动",
                          f"{self.tooltip}\n{self.url}\n（左键单击图标打开）")

        msg = wintypes.MSG()
        while not self._stop.is_set():
            r = u.GetMessageW(ctypes.byref(msg), None, 0, 0)
            if r in (0, -1):
                break
            u.TranslateMessage(ctypes.byref(msg))
            u.DispatchMessageW(ctypes.byref(msg))

        if self._icon_added:
            try:
                self.shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(self._nid))
            except Exception:  # noqa: BLE001
                pass
            self._icon_added = False

    def run_in_thread(self, **kw) -> threading.Thread:
        """把托盘跑在后台线程（服务器反过来跑主线程时用）。"""
        t = threading.Thread(target=self.run, kwargs=kw, daemon=True,
                             name="gui-tray")
        t.start()
        self._ready.wait(timeout=10)
        return t


def selftest() -> int:
    """只做**离线**检查：图标能画出来、结构体能对上 Win32 的预期尺寸。"""
    import tempfile

    try:
        sys.stdout.reconfigure(errors="replace")  # type: ignore[union-attr]
    except Exception:  # noqa: BLE001
        pass

    ok = fail = 0

    def chk(name: str, cond: bool, detail: str = "") -> None:
        nonlocal ok, fail
        if cond:
            ok += 1
            print(f"  [OK]   {name}")
        else:
            fail += 1
            print(f"  [FAIL] {name}  {str(detail)[:200]}")

    print("=== gui.tray 自检 ===")
    chk("运行在 Windows 上", IS_WINDOWS, os.name)

    with tempfile.TemporaryDirectory() as td:
        ico = Path(td) / "agent.ico"
        chk("能生成自有图标", make_icon(ico), str(ico))
        if ico.is_file():
            raw = ico.read_bytes()
            chk("ICO 头正确（type=1 count=1）", raw[:6] == b"\x00\x00\x01\x00\x01\x00",
                raw[:6].hex())
            w, h = raw[6], raw[7]
            chk("图标尺寸为 32x32", (w, h) == (32, 32), f"{w}x{h}")
            chk("文件大小合理（约 4KB）", 3000 < len(raw) < 6000, str(len(raw)))

    if IS_WINDOWS:
        # 完整版 NOTIFYICONDATAW 在 x64 下就是 976 字节（4+pad+8+4+4+4+pad+8+256
        # +8+512+4+128+4+16+8）。填错 cbSize → Shell 调用静默失败，所以这里钉死。
        size = ctypes.sizeof(NOTIFYICONDATAW)
        chk("NOTIFYICONDATAW 尺寸为 976 字节（x64 完整版）", size == 976, str(size))
        n = NOTIFYICONDATAW()
        n.cbSize = size
        chk("cbSize 可写入且等于 sizeof", n.cbSize == size)
        # 注意：`c_wchar * N` 字段读出来会被 ctypes 自动转成 str，所以既不能
        # len() 量容量、也不能 sizeof(type(...))；只能查 _fields_ 里声明的类型。
        ft = {name: typ for name, typ in NOTIFYICONDATAW._fields_}
        chk("szTip 容量 128 宽字符（256 字节）",
            ctypes.sizeof(ft["szTip"]) == 256, str(ctypes.sizeof(ft["szTip"])))
        chk("szInfo 容量 256 宽字符（512 字节）",
            ctypes.sizeof(ft["szInfo"]) == 512, str(ctypes.sizeof(ft["szInfo"])))
        chk("szInfoTitle 容量 64 宽字符（128 字节）",
            ctypes.sizeof(ft["szInfoTitle"]) == 128,
            str(ctypes.sizeof(ft["szInfoTitle"])))
        n.szTip = "T" * 127
        n.szInfo = "I" * 255
        n.szInfoTitle = "H" * 63
        chk("能写入 127 字符提示并读回（TrayIcon 实际会传这么长）", len(n.szTip) == 127)
        chk("能写入 255 字符气泡正文并读回", len(n.szInfo) == 255)
        chk("能写入 63 字符气泡标题并读回", len(n.szInfoTitle) == 63)
        chk("宽字符按 2 字节计（确认是 W 版而非 A 版）",
            ctypes.sizeof(wintypes.WCHAR) == 2, str(ctypes.sizeof(wintypes.WCHAR)))
        chk("WNDPROC 函数指针可用", WNDPROCTYPE is not None)
        chk("托盘回调消息在 WM_APP 之后（不撞系统消息）", WM_TRAYICON > WM_APP,
            hex(WM_TRAYICON))
        chk("TrayIcon.logger 类属性存在（缺了会让 _say 抛 AttributeError）",
            hasattr(TrayIcon, "logger"), "no attr")

        # 日志钩子：构造实例不建窗口，所以可以离线测
        seen: list = []
        t1 = TrayIcon(url="http://127.0.0.1:1/?token=x", tooltip="t",
                      logger=seen.append)
        t1._say("hello")                       # noqa: SLF001
        chk("_say 会把消息交给 logger 钩子", seen == ["hello"], str(seen))
        t2 = TrayIcon(tooltip="t")             # 不传 logger
        try:
            t2._say("no-logger")               # noqa: SLF001
            chk("未配 logger 时 _say 静默不抛", True)
        except Exception as exc:  # noqa: BLE001
            chk("未配 logger 时 _say 静默不抛", False, f"{type(exc).__name__}: {exc}")
        TrayIcon.logger = None

        # tooltip 会被塞进 128 宽字符的 TIP 字段，超长必须自己截断
        long_tip = TrayIcon(tooltip="x" * 500).tooltip
        chk("超长 tooltip 被截到 127 字符内", len(long_tip) <= 127, str(len(long_tip)))
    else:
        print("  [SKIP] 非 Windows：跳过 Win32 结构检查")

    print(f"\ngui.tray 自检：{ok} 通过 / {fail} 失败")
    return 1 if fail else 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        raise SystemExit(selftest())
    print(__doc__)
