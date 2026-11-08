#!/usr/bin/env python3
"""远控软件审计（**只读**）—— 查清这台机器上谁能远程操作它。

为什么单独做这个工具：
    「鼠标自己动」这类现象，最常见的解释不是木马，而是**本机装了远程控制软件
    且被人连上了**。这类软件为了穿透 NAT，全部走**主动外连到厂商中转云**，
    所以在防火墙日志里长得和"正常出站 HTTPS"一样，本机传感器也只会看到
    「某进程外连某 IP:443」——看不出"这台机器正被人控屏"。
    必须专门去查：进程 / 服务 / 自启项 / **它们自己的连接日志**。

本工具的定位是**证据收集与风险提示**，不做任何处置：
    * 不卸载、不停服务、不改注册表、不断开连接（只读）
    * 处置命令只**打印**出来，由你确认后自己执行

查什么：
    1. 已知远控产品：进程 / Windows 服务 / 自启项（Run、启动文件夹、计划任务）/ 安装记录
    2. 每个在跑的产品：完整路径 + **数字签名状态**（区分正版软件与被篡改的同名程序）
    3. **被控证据**：扫它们自己的日志目录，找"被远程连接/会话"的痕迹与时间
    4. 远程访问通道状态：RDP 是否开启、Windows 远程协助/快速助手是否可用
    5. 风险定性：哪些是"能控屏且已联网"，哪些只是装了没运行

用法：
    python tools/remote_access_audit.py                 # 控制台摘要
    python tools/remote_access_audit.py --report        # 同时写 reports/remote_access_audit_<日期>.md
    python tools/remote_access_audit.py --json logs/remote_access.json
    python tools/remote_access_audit.py --selftest
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORT_DIR = PROJECT_ROOT / "reports"

_CREATE_NO_WINDOW = 0x08000000

# ---------------------------------------------------------------------------
# 已知远控产品表。只登记**公开的远程控制/远程桌面**类产品：
# 它们共同特征是"能注入鼠标键盘"，也就是"鼠标自己动"的候选原因。
#
# 匹配策略：进程名 / 服务名用**小写子串**；路径用子串；日志用文件名正则。
# 刻意用子串而非精确匹配：这类软件版本间可执行文件名会改
# （向日葵从 SunLoginClient 改成 AweSun 就是一个例子，只看精确名会漏）。
# ---------------------------------------------------------------------------
PRODUCTS: Tuple[Dict[str, Any], ...] = (
    {"name": "向日葵 / AweSun (Oray)", "vendor": "Oray",
     "proc": ("awesun", "sunlogin", "oray"),
     "svc": ("sunloginservice", "oray", "awesun"),
     "path": ("oray\\awesun", "oray\\sunlogin", "sunlogin"),
     "runkey": ("awesun", "sunlogin"),
     "logdirs": ("%APPDATA%\\Oray", "%ProgramData%\\Oray", "Program Files\\Oray"),
     "controlled_re": r"(shell|session|connect|controlled|被控|远控)"},
    {"name": "远辰 GameViewer", "vendor": "yuanchen",
     "proc": ("gameviewer",),
     "svc": ("gameviewerservice",),
     "path": ("yuanchen\\gameviewer",),
     "runkey": ("gameviewer",),
     "logdirs": ("D:\\yuanchen\\GameViewer\\log",),
     "controlled_re": r"controlled|streamer|connection"},
    {"name": "TeamViewer", "vendor": "TeamViewer",
     "proc": ("teamviewer",), "svc": ("teamviewer",), "path": ("teamviewer",),
     "runkey": ("teamviewer",), "logdirs": ("%APPDATA%\\TeamViewer", "%ProgramData%\\TeamViewer"),
     "controlled_re": r"connection|session|incoming"},
    {"name": "AnyDesk", "vendor": "AnyDesk",
     "proc": ("anydesk",), "svc": ("anydesk",), "path": ("anydesk",),
     "runkey": ("anydesk",), "logdirs": ("%APPDATA%\\AnyDesk", "%ProgramData%\\AnyDesk"),
     "controlled_re": r"session|incoming|connection"},
    {"name": "RustDesk", "vendor": "RustDesk",
     "proc": ("rustdesk",), "svc": ("rustdesk",), "path": ("rustdesk",),
     "runkey": ("rustdesk",), "logdirs": ("%APPDATA%\\RustDesk",),
     "controlled_re": r"session|connect"},
    {"name": "ToDesk", "vendor": "ToDesk",
     "proc": ("todesk",), "svc": ("todesk",), "path": ("todesk",),
     "runkey": ("todesk",), "logdirs": ("%APPDATA%\\ToDesk", "%ProgramData%\\ToDesk"),
     "controlled_re": r"session|connect|被控"},
    {"name": "UU远程", "vendor": "NetEase",
     "proc": ("uuremote", "uu_remote", "uuacc"), "svc": ("uuremote", "uu_"),
     "path": ("uu远程", "uuremote"), "runkey": ("uu远程", "uuremote"),
     "logdirs": ("%APPDATA%\\UU", "%LOCALAPPDATA%\\UU"),
     "controlled_re": r"session|connect"},
    {"name": "VNC 类", "vendor": "various",
     "proc": ("winvnc", "vncserver", "tvnserver", "uvnc"),
     "svc": ("vnc", "tvnserver"), "path": ("ultravnc", "tightvnc", "realvnc"),
     "runkey": ("vnc",), "logdirs": ("%APPDATA%\\UltraVNC", "%ProgramData%\\RealVNC"),
     "controlled_re": r"client|connection"},
    {"name": "Chrome Remote Desktop", "vendor": "Google",
     "proc": ("remoting_host", "remote_assistance_host"), "svc": ("chromoting",),
     "path": ("chrome remote desktop",), "runkey": (),
     "logdirs": ("%LOCALAPPDATA%\\Google\\Chrome Remote Desktop",),
     "controlled_re": r"session|client"},
    {"name": "Quick Assist / 远程协助", "vendor": "Microsoft",
     "proc": ("quickassist", "msra"), "svc": ("",),
     "path": ("quickassist",), "runkey": (),
     "logdirs": ("%LOCALAPPDATA%\\Packages\\MicrosoftCorporationII.QuickAssist*",),
     "controlled_re": r"session"},
    {"name": "Splashtop / LogMeIn / Radmin / ScreenConnect 等",
     "vendor": "various",
     "proc": ("splashtop", "logmein", "radmin", "screenconnect", "connectwise",
              "ammyy", "dwagent", "aeroadmin", "supremo", "netsupport", "parsec",
              "sunshine", "moonlight"),
     "svc": ("splashtop", "logmein", "r_server", "screenconnect", "dwagent"),
     "path": ("splashtop", "logmein", "radmin", "screenconnect", "dwagent"),
     "runkey": ("splashtop", "logmein", "radmin", "dwagent"),
     "logdirs": (), "controlled_re": r"session|connect"},
)

# 日志里出现这些词 = 该产品记录的"有人连进来了"
CONTROLLED_HINTS = re.compile(
    r"controlled|被控|远控|remote[_\- ]?session|incoming[_\- ]?connection|"
    r"client[_\- ]?connected|session[_\- ]?start", re.I)


def _hidden() -> Dict[str, Any]:
    kw: Dict[str, Any] = {}
    if os.name == "nt":
        kw["creationflags"] = _CREATE_NO_WINDOW
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0
        kw["startupinfo"] = si
    return kw


def _ps(cmd: str, timeout: int = 60) -> str:
    """跑一段 PowerShell 只读查询。拿不到就返回空串（不编造结果）。"""
    try:
        r = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
             "[Console]::OutputEncoding=[Text.Encoding]::UTF8;" + cmd],
            capture_output=True, encoding="utf-8", errors="replace",
            timeout=timeout, **_hidden())
    except (OSError, subprocess.SubprocessError):
        return ""
    return (r.stdout or "").strip()


def _ps_json(cmd: str, timeout: int = 60) -> List[Dict[str, Any]]:
    txt = _ps(f"$ErrorActionPreference='SilentlyContinue'; ConvertTo-Json -Compress -Depth 4 "
              f"@({cmd})", timeout=timeout)
    if not txt or txt in ("null", "[]"):
        return []
    try:
        data = json.loads(txt)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        return [data]
    return data if isinstance(data, list) else []


def _expand(p: str) -> str:
    return os.path.expandvars(p)


# ------------------------------------------------------------------ 采集

def collect() -> Dict[str, Any]:
    """采集本机远控相关事实。全部只读。"""
    out: Dict[str, Any] = {"ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                          "products": [], "rdp": {}, "notes": []}

    procs = _ps_json("Get-Process | Where-Object { $_.Path } | "
                     "Select-Object Id,Name,Path,StartTime", timeout=90)
    svcs = _ps_json("Get-CimInstance Win32_Service | "
                    "Select-Object Name,DisplayName,State,StartMode,PathName", timeout=90)
    runkeys = _ps_json(
        "$ErrorActionPreference='SilentlyContinue';"
        "foreach ($h in @('HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',"
        "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',"
        "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run')) {"
        "  $k = Get-ItemProperty $h -ErrorAction SilentlyContinue;"
        "  if ($k) { foreach ($p in $k.PSObject.Properties) {"
        "    if ($p.Name -notlike 'PS*') {"
        "      [PSCustomObject]@{ Hive=$h; Name=$p.Name; Value=[string]$p.Value } } } } }",
        timeout=90)
    installed = _ps_json(
        "$ErrorActionPreference='SilentlyContinue';"
        "foreach ($h in @('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*')) {"
        "  Get-ItemProperty $h -ErrorAction SilentlyContinue | "
        "  Select-Object DisplayName,InstallLocation,DisplayVersion }", timeout=120)
    tasks = _ps_json(
        "$ErrorActionPreference='SilentlyContinue';"
        "Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\\Microsoft\\*' } | "
        "Select-Object TaskName,TaskPath,State", timeout=120)

    # 只对"命中的产品"查签名，避免对系统里上百个进程逐个验签（慢）
    def match_any(hay: str, needles: Tuple[str, ...]) -> bool:
        h = (hay or "").lower()
        return any(n and n in h for n in needles)

    for spec in PRODUCTS:
        hits: Dict[str, Any] = {"name": spec["name"], "vendor": spec["vendor"],
                                "processes": [], "services": [], "autostart": [],
                                "installed": [], "logs": [], "signatures": {}}
        for p in procs:
            nm, path = str(p.get("Name") or ""), str(p.get("Path") or "")
            if match_any(nm, spec["proc"]) or match_any(path, spec["path"]):
                hits["processes"].append({"pid": p.get("Id"), "name": nm, "path": path,
                                          "start": str(p.get("StartTime") or "")})
        for s in svcs:
            if match_any(str(s.get("Name") or ""), spec["svc"]) or \
                    match_any(str(s.get("PathName") or ""), spec["path"]):
                hits["services"].append({"name": s.get("Name"), "state": s.get("State"),
                                         "start": s.get("StartMode"),
                                         "path": s.get("PathName")})
        for r in runkeys:
            if match_any(str(r.get("Name") or ""), spec["runkey"]) or \
                    match_any(str(r.get("Value") or ""), spec["path"] + spec["runkey"]):
                hits["autostart"].append({"hive": str(r.get("Hive") or "").split("\\")[0],
                                          "name": r.get("Name"), "value": r.get("Value")})
        for inst in installed:
            dn = str(inst.get("DisplayName") or "")
            if dn and (match_any(dn, spec["runkey"]) or match_any(dn, spec["path"])):
                hits["installed"].append({"name": dn, "version": inst.get("DisplayVersion"),
                                          "location": inst.get("InstallLocation")})
        for t in tasks:
            if match_any(str(t.get("TaskName") or ""), spec["runkey"] or spec["proc"]):
                hits["autostart"].append({"hive": "Task", "name": t.get("TaskName"),
                                          "value": str(t.get("TaskPath") or "") + " " +
                                                   str(t.get("State") or "")})

        # 签名：只看进程真实路径（可执行文件在哪比注册表写什么更可信）
        for p in hits["processes"][:6]:
            path = str(p.get("path") or "")
            if not path or path in hits["signatures"]:
                continue
            sig = _ps(f"(Get-AuthenticodeSignature -LiteralPath '{path.replace(chr(39), chr(39)*2)}')"
                      f" | Select-Object -ExpandProperty Status")
            hits["signatures"][path] = sig or "Unknown"

        # 被控证据：扫日志目录
        for d in spec["logdirs"]:
            real = Path(_expand(d))
            if not real.parent.exists() and not real.exists():
                continue
            files = []
            try:
                files = list(real.rglob("*")) if real.exists() else \
                    list(real.parent.glob(real.name))
            except OSError:
                files = []
            for f in files:
                try:
                    if not f.is_file():
                        continue
                except OSError:
                    continue
                name = f.name
                if CONTROLLED_HINTS.search(name) or \
                        any(pat in str(f).lower() for pat in
                            ("controlled", "session", "connection", "shell")):
                    try:
                        st = f.stat()
                    except OSError:
                        continue
                    files_entry = {"path": str(f), "mb": round(st.st_size / 1048576, 2),
                                   "mtime": time.strftime("%Y-%m-%d %H:%M",
                                                          time.localtime(st.st_mtime))}
                    hits["logs"].append(files_entry)

        hits["logs"].sort(key=lambda x: x["mtime"], reverse=True)
        hits["logs"] = hits["logs"][:60]
        if hits["processes"] or hits["services"] or hits["autostart"] or hits["installed"]:
            out["products"].append(hits)

    # 远程访问通道
    out["rdp"] = {
        "fDenyTSConnections": _ps(
            "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' "
            "-Name fDenyTSConnections).fDenyTSConnections"),
        "sessions": _ps("query session"),
        "remote_assistance": _ps(
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\RemoteAssistance' "
            "-Name fAllowToGetHelp -EA SilentlyContinue).fAllowToGetHelp"),
    }
    return out


# ------------------------------------------------------------------ 定性

def assess(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """给每个产品定风险等级。**只给结论与依据，不给"已确认入侵"这种断言。**"""
    verdicts = []
    for p in data.get("products", []):
        running = bool(p["processes"])
        controlled = [x for x in p["logs"] if "controlled" in x["path"].lower()]
        bad_sig = [k for k, v in p["signatures"].items() if v not in ("Valid",)]
        risk, why = "低", []
        if running:
            risk, why = "中", why + ["进程正在运行"]
        if p["autostart"]:
            risk, why = ("高" if running else "中"), why + ["配置了开机自启"]
        if p["services"] and any(s.get("state") == "Running" for s in p["services"]):
            risk = "高"
            why.append("有正在运行的服务（可在无人值守时接受连接）")
        if controlled:
            risk = "高"
            why.append(f"日志中存在 **{len(controlled)}** 个被远程连接/会话的记录文件"
                       f"（最近 {controlled[0]['mtime']}）")
        if bad_sig:
            risk = "高"
            why.append(f"签名异常：{bad_sig}")
        verdicts.append({"name": p["name"], "risk": risk, "reasons": why,
                         "running": running, "controlled_logs": len(controlled),
                         "newest_controlled": controlled[0]["mtime"] if controlled else ""})
    order = {"高": 0, "中": 1, "低": 2}
    verdicts.sort(key=lambda v: (order.get(v["risk"], 3), -(v["controlled_logs"] or 0)))
    return verdicts


def render(data: Dict[str, Any], verdicts: List[Dict[str, Any]]) -> List[str]:
    L: List[str] = []
    L.append("# 远控软件审计报告")
    L.append("")
    L.append(f"> 采集时间：{data['ts']}　工具：`tools/remote_access_audit.py`（**只读**）")
    L.append("")
    if not verdicts:
        L.append("未发现已知远程控制软件。")
    else:
        L.append("## 风险排序")
        L.append("")
        L.append("| 产品 | 风险 | 正在运行 | 被控记录 | 依据 |")
        L.append("|---|---|---|---|---|")
        for v in verdicts:
            L.append(f"| {v['name']} | **{v['risk']}** | {'是' if v['running'] else '否'} | "
                     f"{v['controlled_logs']} 条"
                     f"{'（最近 ' + v['newest_controlled'] + '）' if v['newest_controlled'] else ''} | "
                     f"{'；'.join(v['reasons']) or '—'} |")
        L.append("")
        for p in data["products"]:
            L.append(f"## {p['name']}")
            L.append("")
            for key, label in (("installed", "安装记录"), ("processes", "进程"),
                               ("services", "服务"), ("autostart", "自启项")):
                if p.get(key):
                    L.append(f"- **{label}**")
                    for x in p[key][:8]:
                        L.append(f"  - `{json.dumps(x, ensure_ascii=False)}`")
            if p.get("signatures"):
                L.append("- **签名状态**")
                for k, v in p["signatures"].items():
                    L.append(f"  - `{v}`　{k}")
            if p.get("logs"):
                L.append(f"- **被控/会话相关日志（{len(p['logs'])} 个）**")
                for x in p["logs"][:12]:
                    L.append(f"  - {x['mtime']}　{x['mb']} MB　`{x['path']}`")
            L.append("")
    rdp = data.get("rdp") or {}
    L.append("## 远程访问通道")
    L.append("")
    deny = rdp.get("fDenyTSConnections")
    L.append(f"- RDP `fDenyTSConnections = {deny}`"
             f"（**1 = 已禁用**，0 = 允许）")
    L.append(f"- 远程协助 `fAllowToGetHelp = {rdp.get('remote_assistance') or '(未读到)'}`")
    if rdp.get("sessions"):
        L.append("- 当前会话：")
        L.append("```")
        L.append(rdp["sessions"][:1200])
        L.append("```")
    L.append("")

    L.append("## 处置建议（需要你自己执行；本工具不代替你操作）")
    L.append("")
    hi = [v for v in verdicts if v["risk"] == "高"]
    if hi:
        L.append("**有高风险项。先确认这些是不是你自己装的、自己用的。**")
        L.append("")
        L.append("1. **先看连接记录再卸载** —— 卸载后日志就没了，而日志是判定"
                 "「谁连过」的唯一证据：")
        L.append("   - 向日葵：登录 Oray 账号后台看「连接记录/登录日志」（来源、时间、时长）")
        L.append("   - GameViewer：看 `D:\\yuanchen\\GameViewer\\log\\` 下 "
                 "`*_controlled_*.slog` 的时间分布")
        L.append("2. **不是你用的就卸载干净**，并逐项确认删除：")
        for v in hi:
            L.append(f"   - {v['name']}")
        L.append("   卸载后复查：服务是否消失、Run 项是否删除（本工具再跑一次即可）")
        L.append("3. **改密码 + 开两步验证**：远控账号、邮箱、以及这台机器上所有用过的账号")
        L.append("4. **如果确认是被他人远控**：备份数据后**重装系统**是最稳妥的处理"
                 "（管理员权限下无法穷举所有后门）")
        L.append("5. 用当前杀软做一次全盘扫描（注意：若 Defender 已被其它杀软接管，"
                 "它自己不会扫描）")
    else:
        L.append("未发现高风险远控项。")
    L.append("")
    L.append("### 本次审计**没有**覆盖的范围（别把它当成「已排除入侵」）")
    L.append("")
    L.append("- 非管理员运行时读不到安全事件日志（登录 4624 / 进程创建 4688 / 服务安装 7045）")
    L.append("- 不做全盘病毒扫描，也不替代杀软")
    L.append("- 只查已知远控产品；自研/改名的远控工具不会被这张表命中")
    L.append("- 「不能控屏但能读写文件」的窃密类恶意软件不在本工具范围内")
    return L


# ------------------------------------------------------------------ 自检

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

    chk("产品表非空且每个都有 name/proc/path",
        len(PRODUCTS) >= 8 and all(p.get("name") and p.get("proc") and p.get("path")
                                  for p in PRODUCTS))
    chk("产品表里包含向日葵与 GameViewer（本次实机发现）",
        any("AweSun" in p["name"] for p in PRODUCTS)
        and any("GameViewer" in p["name"] for p in PRODUCTS))

    # 被控日志名识别
    for name in ("connection_log_controlled_20260831091148243_816.slog",
                 "streamer_log_controlled_20260926193444068_7468.slog",
                 "被控-20260926.log", "remote_session_2026.log"):
        chk(f"识别被控日志名：{name[:36]}", bool(CONTROLLED_HINTS.search(name)), name)
    chk("普通日志名不误判为被控",
        not CONTROLLED_HINTS.search("checkupdate.20261004-053451.log"))

    # 定性：造三档数据
    data = {"products": [
        {"name": "A", "processes": [{"pid": 1}], "services": [], "autostart": [],
         "installed": [], "signatures": {}, "logs": []},
        {"name": "B", "processes": [{"pid": 2}],
         "services": [{"state": "Running", "name": "svc"}],
         "autostart": [{"name": "x"}], "installed": [],
         "signatures": {"C:\\x.exe": "Valid"},
         "logs": [{"path": "D:\\x\\connection_log_controlled_1.slog", "mtime": "2026-09-26 19:35",
                   "mb": 1.0}]},
        {"name": "C", "processes": [], "services": [], "autostart": [],
         "installed": [{"name": "c"}], "signatures": {}, "logs": []},
    ]}
    v = assess(data)
    by = {x["name"]: x for x in v}
    chk("只装了没运行 → 低风险", by["C"]["risk"] == "低", str(by["C"]))
    chk("在运行但无自启 → 中风险", by["A"]["risk"] == "中", str(by["A"]))
    chk("运行中服务 + 被控日志 → 高风险", by["B"]["risk"] == "高", str(by["B"]))
    chk("高风险排在前面", v[0]["name"] == "B")
    chk("被控日志计数正确", by["B"]["controlled_logs"] == 1)
    chk("签名异常会升级为高风险",
        assess({"products": [dict(data["products"][0], name="D",
                                  signatures={"C:\\y.exe": "HashMismatch"})]})[0]["risk"] == "高")

    lines = render({"ts": "t", "products": [], "rdp": {}}, [])
    text = "\n".join(lines)
    chk("无远程控制软件时报告不空且有说明", "未发现已知远程控制软件" in text)
    chk("报告里始终写明'没覆盖的范围'", "没有**覆盖的范围" in text)

    hi_lines = render({"ts": "t", "products": [
        {"name": "B", "processes": [{"pid": 2, "name": "b", "path": "C:\\b.exe"}],
         "services": [], "autostart": [], "installed": [],
         "signatures": {}, "logs": []}], "rdp": {}}, assess({"products": [
        {"name": "B", "processes": [{"pid": 2}], "services": [], "autostart": [{"name": "x"}],
         "installed": [], "signatures": {}, "logs": []}]}))
    hi_text = "\n".join(hi_lines)
    chk("有高风险时给出卸载与改密建议", "卸载" in hi_text and "两步验证" in hi_text)
    chk("建议里强调先看连接记录再卸载（卸载后日志就没了）",
        "先看连接记录再卸载" in hi_text)
    chk("建议里提醒重装系统这一选项", "重装系统" in hi_text)

    print(f"\nremote_access_audit 自检：{ok} 通过 / {fail} 失败")
    return 1 if fail else 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="远控软件审计（只读）")
    ap.add_argument("--report", action="store_true", help="写出 reports/remote_access_audit_<日期>.md")
    ap.add_argument("--json", default="", help="把原始结果写成 JSON")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    if os.name != "nt":
        print("本工具依赖 Windows 的 PowerShell/WMI，当前系统不支持", file=sys.stderr)
        return 2

    print("采集本机远控相关事实（只读）…")
    data = collect()
    verdicts = assess(data)

    print("\n=== 风险排序 ===")
    if not verdicts:
        print("  未发现已知远程控制软件。")
    for v in verdicts:
        mark = {"高": "!!", "中": " !", "低": "  "}.get(v["risk"], "  ")
        ctl = f"，被控记录 {v['controlled_logs']} 条（最近 {v['newest_controlled']}）" \
            if v["controlled_logs"] else ""
        print(f"  {mark} [{v['risk']}] {v['name']}：{'运行中' if v['running'] else '未运行'}{ctl}")
        for r in v["reasons"]:
            print(f"        - {r}")
    rdp = data.get("rdp") or {}
    print(f"\n  RDP fDenyTSConnections = {rdp.get('fDenyTSConnections')}（1 = 已禁用）")

    lines = render(data, verdicts)
    if args.report:
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        out = REPORT_DIR / f"remote_access_audit_{datetime.now():%Y-%m-%d}.md"
        out.write_text("\n".join(lines), encoding="utf-8")
        print(f"\n已写出 {out}")
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(
            {"data": data, "verdicts": verdicts}, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"已写出 {args.json}")

    print("\n提示：本工具只读，不会卸载/停服务。处置命令与『没覆盖的范围』见 "
          "docs/REMOTE_ACCESS_HARDENING.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
