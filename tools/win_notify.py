#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/win_notify.py — 跨进程可用的 Windows 通知（无第三方依赖）。

为什么不用 pip 包：本机不便再装依赖，且 `win10toast` 这类包大多已停止维护。
这里用系统自带能力：Python 生成 Toast XML（UTF-8）→ ASCII 的 PowerShell 脚本投递。

降级链（逐个尝试，任一成功即返回）：
1. Windows Toast（Win10/11 原生通知中心）
2. 托盘气泡（System.Windows.Forms.NotifyIcon，老系统兜底）
3. 控制台输出（永远可用，用于 CI/无桌面会话）

用法::

    python tools/win_notify.py --title "安全告警" --body "发现可疑外连" --test
    python tools/win_notify.py --title "x" --body "y" --json
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PS_SCRIPT = Path(__file__).resolve().parent / "win_notify.ps1"

# 用 PowerShell 自己的 AppId：任意自造 AppId 在没有对应快捷方式时无法投递通知
DEFAULT_APP_ID = ("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}"
                  "\\WindowsPowerShell\\v1.0\\powershell.exe")


def _xml_escape(s: str, limit: int = 400) -> str:
    s = (s or "").strip()
    if len(s) > limit:
        s = s[:limit - 1] + "…"
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;").replace("'", "&apos;"))


def build_toast_xml(title: str, body: str, subtitle: str = "") -> str:
    """构造 Toast 模板（ToastGeneric：粗体标题 + 正文 + 可选副标题）。"""
    parts = [f"<text>{_xml_escape(title, 120)}</text>"]
    if subtitle:
        parts.append(f"<text>{_xml_escape(subtitle, 200)}</text>")
    parts.append(f"<text>{_xml_escape(body)}</text>")
    return (
        '<toast scenario="urgent">'
        '<visual><binding template="ToastGeneric">'
        + "".join(parts) +
        '</binding></visual>'
        '<audio src="ms-winsoundevent:Notification.Looping.Alarm2" loop="false"/>'
        '</toast>'
    )


def _hidden_kwargs(timeout: int) -> Dict[str, Any]:
    """隐藏子进程控制台。

    没有这一步：pythonw.exe 后台服务发通知时会 spawn `powershell.exe`，
    Windows 为它**新建控制台窗口** → 屏幕闪一下黑框。
    """
    kw: Dict[str, Any] = {"capture_output": True, "text": True,
                          "encoding": "utf-8", "errors": "replace",
                          "timeout": timeout}
    if os.name == "nt":
        kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0  # SW_HIDE
        kw["startupinfo"] = si
    return kw


def notify(title: str, body: str, subtitle: str = "",
           app_id: str = DEFAULT_APP_ID, timeout: int = 20) -> Tuple[bool, str]:
    """发送通知，返回 (是否成功, 通道或错误)。"""
    if os.name != "nt":
        return False, "non-windows"

    xml = build_toast_xml(title, body, subtitle)
    fd, tmp = tempfile.mkstemp(suffix=".xml", prefix="notify_")
    os.close(fd)
    tmp_path = Path(tmp)
    try:
        tmp_path.write_text(xml, encoding="utf-8")
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-File", str(PS_SCRIPT), "-XmlFile", str(tmp_path), "-AppId", app_id],
            **_hidden_kwargs(timeout))
        out = ((proc.stdout or "") + (proc.stderr or "")).strip()
        if out.startswith("OK"):
            return True, "toast"
        # 降级 1：托盘气泡
        if _balloon(title, body):
            return True, f"balloon（toast 失败：{out[:80]}）"
        return False, f"全部通道失败：{out[:120]}"
    except Exception as exc:  # noqa: BLE001
        return False, f"异常：{exc}"
    finally:
        tmp_path.unlink(missing_ok=True)


def _balloon(title: str, body: str) -> bool:
    """降级：托盘气泡（老系统/Toast 被策略禁用时）。"""
    if os.name != "nt":
        return False
    ps = (
        "Add-Type -AssemblyName System.Windows.Forms;"
        "$n=New-Object System.Windows.Forms.NotifyIcon;"
        "$n.Icon=[System.Drawing.SystemIcons]::Warning;"
        "$n.Visible=$true;"
        f"$n.ShowBalloonTip(10000,'{title.replace(chr(39), chr(39) * 2)[:60]}',"
        f"'{body.replace(chr(39), chr(39) * 2)[:200]}',"
        "[System.Windows.Forms.ToolTipIcon]::Warning);"
        "Start-Sleep -Seconds 6;$n.Dispose();'OK'"
    )
    try:
        proc = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                              **_hidden_kwargs(25))
        return "OK" in (proc.stdout or "")
    except Exception:  # noqa: BLE001
        return False


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description="Windows 通知")
    ap.add_argument("--title", default="蓝队研判副驾")
    ap.add_argument("--body", default="")
    ap.add_argument("--subtitle", default="")
    ap.add_argument("--test", action="store_true", help="发一条测试通知")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    title = "蓝队研判副驾 · 通道测试" if args.test else args.title
    body = args.body or ("这是一条测试通知。看到它就说明通知通道可用。" if args.test
                         else "（空内容）")
    ok, channel = notify(title, body, args.subtitle)
    result: Dict[str, Any] = {"ok": ok, "channel": channel, "title": title}
    print(json.dumps(result, ensure_ascii=False) if args.json
          else f"{'成功' if ok else '失败'}：{channel}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
