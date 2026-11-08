#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""security/whitelist.py — 进程 / 文件 / 文件夹白名单（减少打扰，**不放行处置**）。

白名单在这套系统里的作用，必须说清楚，否则很容易被误解成"免检通道"
--------------------------------------------------------------------------

本模块的白名单**只做一件事：降低告警优先级 / 不去打扰人**。
它**不会**让某个动作变得可执行，也**不会**跳过任何闸门（schema / 两阶段确认 /
保护资产 / 适配器策略）。原因很直接：如果白名单能放行处置动作，那么"把恶意文件
加进白名单"就成了一次授权，攻击者只要能改这个 json 就等于拿到了执行权。
所以设计上把它定位成**降噪**，而不是**放行**。

它接在哪里
----------

* `tools/net_sensor.py` —— 命中白名单的发现会被**降级并标注**（不消耗模型配额、
  不弹通知），机制与既有的 `signed_valid` 注解完全一致（同样是注解、同样不计入
  组合加成）。
* `actions/executor.py` —— 白名单里的文件/文件夹会被当作**受保护对象**，
  破坏性动作打到它们直接拒绝（与 `protected_hosts` 同一套逻辑）。
  注意方向：这是"**别动它**"，不是"**可以动它**"。

为什么必须拒绝一些白名单值
--------------------------

白名单天然是"降低警惕"的工具，所以它最大的风险是**把真正该警惕的范围也罩进去**。
因此这里的校验不是走过场，而是有硬拒绝条件（全部可自检）：

1. **不许把"按位置就可疑"的目录加进白名单**：`%TEMP%`、`Downloads`、
   `C:\\Users\\Public`、`ProgramData`、`AppData` 这些正是样本最爱落地的位置。
   把它们罩住等于把"落地即告警"这条最有效的规则关掉了 —— 那白名单就成了绕过通道。
   实测依据：本机一次真实采集里，`%TEMP%` 与 `Downloads` 是用户目录下体积和
   可疑度最高的两个位置。
2. **系统关键进程名不许按裸名加入**（`svchost.exe` / `lsass.exe` / `explorer.exe` /
   `rundll32.exe` / `powershell.exe` / `cmd.exe` / `mshta.exe` / `wscript.exe` / `cscript.exe` /
   `regsvr32.exe` / `certutil.exe` / `bitsadmin.exe` …）。恶意软件最常用的手法之一就是
   取一个跟系统进程一样的名字。按裸名白名单 = 给这种伪装发免检牌。
   要用就必须给**绝对路径**（路径是更难伪装的证据）。
3. **不许通配符 / 不许空值 / 不许盘根**：`*`、`C:\\`、`%SystemRoot%`（未展开）这类一律拒绝，
   因为无法审计它到底罩住了什么。

每条都要写清"谁加的、什么时候、为什么" —— 白名单是安全策略资产，必须可追溯。
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

__all__ = [
    "WhitelistEntry", "Whitelist", "KINDS", "RefusedError",
    "STAGING_HINTS", "CRITICAL_PROCESS_NAMES", "default_whitelist",
]

KINDS = ("process", "file", "folder")

DEFAULT_PATH = "logs/whitelist.json"

#: 「按位置就可疑」的目录片段。白名单不许覆盖它们 —— 见模块 docstring 第 1 条。
#: 这些值与 `tools/net_sensor.py` 的 SUSPECT_PATH_HINTS 保持一致：
#: 那边负责"这些位置要加分"，这边负责"不许把这些位置罩起来"，两处必须同源，
#: 否则会出现"一边因为位于 Temp 而告警、一边因为白名单而不告警"的自相矛盾。
STAGING_HINTS: Tuple[str, ...] = (
    r"\temp", r"\tmp", r"\downloads", r"\users\public", r"\programdata",
    r"\appdata\local\temp", r"\recycle", r"\windows\temp",
)

#: 系统关键进程名：按裸名加入白名单会被拒绝（要求绝对路径）。见 docstring 第 2 条。
CRITICAL_PROCESS_NAMES: Tuple[str, ...] = (
    "svchost.exe", "lsass.exe", "services.exe", "wininit.exe", "winlogon.exe",
    "csrss.exe", "smss.exe", "explorer.exe", "taskhostw.exe", "spoolsv.exe",
    "rundll32.exe", "regsvr32.exe", "powershell.exe", "pwsh.exe", "cmd.exe",
    "mshta.exe", "wscript.exe", "cscript.exe", "certutil.exe", "bitsadmin.exe",
    "wmic.exe", "msiexec.exe", "conhost.exe", "dllhost.exe", "runtimebroker.exe",
)

_RE_WILDCARD = re.compile(r"[*?\[\]]")


class RefusedError(ValueError):
    """白名单值被硬拒绝（不是"警告"，是拒绝写入）。"""


@dataclass
class WhitelistEntry:
    kind: str                     # process | file | folder
    value: str
    note: str = ""
    added_at: str = ""
    added_by: str = ""
    expires_at: str = ""          # 空 = 永不过期

    def expired(self, now: Optional[float] = None) -> bool:
        if not self.expires_at:
            return False
        try:
            t = time.mktime(time.strptime(self.expires_at, "%Y-%m-%d %H:%M:%S"))
        except ValueError:
            return False
        return (now or time.time()) > t

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _norm_path(p: str) -> str:
    """规范化路径用于比较：去尾部分隔符 + 环境变量展开 + 小写。"""
    s = os.path.expandvars(str(p or "").strip().strip('"').strip("'"))
    s = s.replace("/", "\\")
    while len(s) > 3 and s.endswith("\\"):
        s = s[:-1]
    return s.lower()


class Whitelist:
    """JSON 落盘的白名单。线程内使用；GUI 侧加锁串行化。"""

    def __init__(self, path: Optional[str | Path] = None) -> None:
        p = Path(path) if path else Path(DEFAULT_PATH)
        self.path = p if p.is_absolute() else (PROJECT_ROOT / p)
        self._entries: List[WhitelistEntry] = []
        self.load()

    # ---------------------------------------------------------------- 读写
    def load(self) -> None:
        self._entries = []
        if not self.path.is_file():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return                     # 坏文件不让整个系统起不来；下面 save 会覆盖成合法内容
        for item in (data.get("entries") or []):
            try:
                e = WhitelistEntry(**{k: item.get(k, "") for k in
                                      ("kind", "value", "note", "added_at",
                                       "added_by", "expires_at")})
            except TypeError:
                continue
            if e.kind in KINDS and e.value:
                self._entries.append(e)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "note": ("白名单只用于降低告警优先级 / 保护对象，不用于放行处置动作。"
                     "见 security/whitelist.py 模块说明。"),
            "entries": [e.to_dict() for e in self._entries],
        }
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.path)         # 原子替换：避免半个文件导致下次读失败

    # ---------------------------------------------------------------- 校验
    @staticmethod
    def validate(kind: str, value: str) -> Tuple[bool, str]:
        """硬拒绝条件（可自检）。返回 (是否允许, 原因或空)。"""
        v = str(value or "").strip().strip('"').strip("'")
        if not v:
            return False, "空值"
        if kind not in KINDS:
            return False, f"未知类型 {kind!r}（只支持 {', '.join(KINDS)}）"
        if _RE_WILDCARD.search(v):
            return False, ("不允许通配符 —— 无法审计它到底罩住了什么。"
                           "请填具体名字或具体路径")
        if "%" in v:
            return False, ("不允许未展开的环境变量（如 %TEMP%）—— 无法审计它罩住了什么。"
                           "请填展开后的绝对路径")
        if kind == "process":
            base = os.path.basename(v).lower()
            if "\\" not in v:
                if base in CRITICAL_PROCESS_NAMES:
                    return False, (
                        f"不许按裸名白名单系统关键进程 `{base}` —— 恶意软件最常用的手法"
                        f"之一就是取同名。必须给**绝对路径**（路径更难伪装）"
                    )
                if not base.endswith((".exe", ".com", ".bat", ".cmd", ".ps1", ".dll", ".sys")):
                    return False, f"进程名 `{base}` 看起来不是可执行文件名"
                return True, ""
            # 绝对路径形式：检查它是否落在"按位置就可疑"的目录里
            if _in_staging(v):
                return False, (
                    f"`{v}` 位于按位置就可疑的目录（临时/下载/公共等）。"
                    f"白名单不许覆盖这些位置 —— 那会把\"落地即告警\"这条最有效的规则关掉"
                )
            return True, ""
        # file / folder
        if not re.match(r"^[a-zA-Z]:\\", v) and not v.startswith("\\\\"):
            return False, f"`{v}` 不是绝对路径（白名单只接受绝对路径，便于审计）"
        if _in_staging(v):
            return False, (
                f"`{v}` 位于按位置就可疑的目录（临时/下载/公共/ProgramData/AppData 等）。"
                f"白名单不许覆盖这些位置 —— 样本最爱落地的地方不能被罩住"
            )
        if kind == "folder" and _norm_path(v).rstrip("\\") in (
                "c:", "d:", "e:", "c:\\windows", "c:\\users"):
            return False, f"`{v}` 范围过大（盘根或整个 Windows/用户目录），无法审计"
        return True, ""

    # ---------------------------------------------------------------- 增删
    def add(self, kind: str, value: str, *, note: str = "", added_by: str = "",
            ttl_days: int = 0, force: bool = False) -> WhitelistEntry:
        """加入白名单。校验不通过抛 `RefusedError`（`force` 不能绕过硬拒绝）。"""
        ok, why = self.validate(kind, value)
        if not ok:
            if force:
                raise RefusedError(
                    f"{why}　（`force` 也不能绕过这条：它是硬拒绝条件。"
                    f"确需例外请直接在白名单文件里改，并说明理由。）")
            raise RefusedError(why)

        v = str(value).strip().strip('"').strip("'")
        for e in self._entries:
            if e.kind == kind and _norm_path(e.value) == _norm_path(v):
                return e                # 幂等
        exp = ""
        if ttl_days > 0:
            exp = time.strftime("%Y-%m-%d %H:%M:%S",
                                time.localtime(time.time() + ttl_days * 86400))
        e = WhitelistEntry(kind=kind, value=v, note=note,
                           added_at=time.strftime("%Y-%m-%d %H:%M:%S"),
                           added_by=added_by or os.environ.get("USERNAME", ""),
                           expires_at=exp)
        self._entries.append(e)
        self.save()
        return e

    def remove(self, kind: str, value: str) -> bool:
        v = _norm_path(value)
        before = len(self._entries)
        self._entries = [e for e in self._entries
                         if not (e.kind == kind and _norm_path(e.value) == v)]
        if len(self._entries) != before:
            self.save()
            return True
        return False

    def entries(self, *, prune_expired: bool = True) -> List[WhitelistEntry]:
        if prune_expired:
            alive = [e for e in self._entries if not e.expired()]
            if len(alive) != len(self._entries):
                self._entries = alive
                self.save()
        return list(self._entries)

    # ---------------------------------------------------------------- 匹配
    def match_process(self, proc: str, path: str = "") -> Optional[WhitelistEntry]:
        """进程名或镜像路径命中。**路径优先**：路径比名字更可信。"""
        pn = os.path.basename(str(proc or "")).lower()
        pp = _norm_path(path) if path else ""
        for e in self.entries():
            if e.kind != "process":
                continue
            ev = _norm_path(e.value)
            if "\\" in ev:
                if pp and pp == ev:
                    return e
            elif pn and pn == os.path.basename(ev):
                return e
        return None

    def match_path(self, path: str) -> Optional[WhitelistEntry]:
        """文件/文件夹命中。文件夹用前缀匹配（含子目录）。"""
        if not path:
            return None
        pp = _norm_path(path)
        for e in self.entries():
            if e.kind == "file" and _norm_path(e.value) == pp:
                return e
            if e.kind == "folder":
                fv = _norm_path(e.value)
                if pp == fv or pp.startswith(fv + "\\"):
                    return e
        return None

    def stats(self) -> Dict[str, Any]:
        es = self.entries()
        by: Dict[str, int] = {k: 0 for k in KINDS}
        for e in es:
            by[e.kind] = by.get(e.kind, 0) + 1
        return {"total": len(es), "by_kind": by, "path": str(self.path)}


def _in_staging(v: str) -> bool:
    n = _norm_path(v)
    return any(h in n for h in STAGING_HINTS)


_DEFAULT: Optional[Whitelist] = None


def default_whitelist() -> Whitelist:
    """进程内共享实例（避免 GUI/传感器各自读到不同副本）。"""
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = Whitelist()
    return _DEFAULT


# --------------------------------------------------------------------------- #
# 自检
# --------------------------------------------------------------------------- #

def selftest() -> int:
    import tempfile

    try:
        sys.stdout.reconfigure(errors="replace")  # type: ignore[union-attr]
    except Exception:  # noqa: BLE001
        pass

    ok = 0
    fail = 0

    def chk(name: str, cond: bool, detail: str = "") -> None:
        nonlocal ok, fail
        if cond:
            ok += 1
            print(f"  [OK]   {name}")
        else:
            fail += 1
            print(f"  [FAIL] {name}  {detail}")

    print("=== security.whitelist 自检 ===")

    with tempfile.TemporaryDirectory() as td:
        wl = Whitelist(Path(td) / "wl.json")

        # -- 校验：硬拒绝条件 --
        bad_cases = [
            ("folder", r"C:\Users\user\AppData\Local\Temp", "临时目录"),
            ("folder", r"D:\work\downloads", "下载目录"),
            ("folder", r"C:\Users\Public\Documents", "公共目录"),
            ("folder", r"C:\ProgramData\vendor", "ProgramData"),
            ("folder", r"C:\Windows\Temp\x", "Windows 临时目录"),
            ("file", r"C:\Users\user\Downloads\a.exe", "下载目录里的文件"),
            ("process", r"C:\Users\user\AppData\Local\Temp\x.exe", "临时目录里的进程"),
            ("process", "svchost.exe", "系统关键进程裸名"),
            ("process", "powershell.exe", "powershell 裸名"),
            ("folder", r"C:\Windows", "范围过大"),
            ("folder", "not/a/path", "非绝对路径"),
            ("folder", r"C:\Tools\*", "通配符"),
            ("folder", r"C:\Tools\%TEMP%", "未展开变量"),
            ("", r"C:\Tools", "空类型"),
            ("folder", "", "空值"),
        ]
        for kind, val, why in bad_cases:
            allowed, reason = Whitelist.validate(kind, val)
            chk(f"拒绝：{why}（{val[:38]}）", not allowed, reason)

        # -- 校验：应当允许的 --
        good_cases = [
            ("folder", r"D:\tools\trusted"),
            ("file", r"D:\tools\trusted\agent.exe"),
            ("process", r"D:\tools\trusted\agent.exe"),
            ("process", "notepad.exe"),
        ]
        for kind, val in good_cases:
            allowed, reason = Whitelist.validate(kind, val)
            chk(f"允许：{kind} {val}", allowed, reason)

        # -- force 不能绕过硬拒绝 --
        try:
            wl.add("folder", r"C:\Users\user\AppData\Local\Temp", force=True)
            chk("force 不能绕过硬拒绝", False, "竟然加进去了")
        except RefusedError as exc:
            chk("force 不能绕过硬拒绝", "硬拒绝" in str(exc), str(exc))

        # -- 增删与持久化 --
        e = wl.add("folder", r"D:\tools\trusted", note="自研工具目录", added_by="selftest")
        chk("加入成功且记录来源", e.added_by == "selftest" and bool(e.added_at))
        e2 = wl.add("folder", r"D:\tools\trusted")     # 幂等
        chk("重复加入是幂等的", len(wl.entries()) == 1, str(len(wl.entries())))
        wl.add("process", "notepad.exe", note="记事本")
        wl.add("file", r"D:\tools\trusted\agent.exe")
        # 按绝对路径的进程条目。踩过的坑：最初漏了这一条，而下面又有"进程按绝对路径匹配"
        # 的断言 —— 于是测的是一个**白名单里不存在的条目**，失败看起来像匹配逻辑坏了。
        # 给匹配逻辑写用例时，先确认被测数据真的加进去了。
        wl.add("process", r"D:\tools\trusted\agent.exe", note="自研工具（按路径）")
        chk("三种类型都在", wl.stats()["by_kind"] == {"process": 2, "file": 1, "folder": 1},
            str(wl.stats()))

        wl2 = Whitelist(Path(td) / "wl.json")          # 重新加载
        chk("落盘后能重新载入", wl2.stats()["total"] == 4, str(wl2.stats()))

        # -- 匹配 --
        chk("文件夹前缀匹配（含子目录）",
            wl2.match_path(r"D:\tools\trusted\sub\x.dll") is not None)
        chk("文件夹前缀匹配不越界",
            wl2.match_path(r"D:\tools\trusted2\x.dll") is None)
        chk("文件精确匹配",
            wl2.match_path(r"D:\tools\trusted\agent.exe") is not None)
        chk("进程按裸名匹配", wl2.match_process("notepad.exe") is not None)
        chk("进程按绝对路径匹配",
            wl2.match_process("agent.exe", r"D:\tools\trusted\agent.exe") is not None)
        chk("路径不符时不匹配（防同名伪装）",
            wl2.match_process("agent.exe", r"C:\Users\user\AppData\Local\Temp\agent.exe")
            is None)
        chk("未在白名单的进程不匹配", wl2.match_process("random.exe") is None)

        # -- 删除 --
        chk("删除成功", wl2.remove("process", "notepad.exe") is True)
        chk("删除后不再匹配", wl2.match_process("notepad.exe") is None)
        chk("删除不存在的返回 False", wl2.remove("process", "nothing.exe") is False)

        # -- TTL --
        wl3 = Whitelist(Path(td) / "wl3.json")
        wl3.add("process", "temp.exe", ttl_days=1)
        chk("TTL 条目未过期", len(wl3.entries()) == 1)
        wl3._entries[0].expires_at = "2000-01-01 00:00:00"
        chk("过期条目会被清理", len(wl3.entries()) == 0)

        # -- 坏文件不影响启动 --
        bad = Path(td) / "bad.json"
        bad.write_text("{ not json", encoding="utf-8")
        wl4 = Whitelist(bad)
        chk("白名单文件损坏时不抛异常（降级为空）", wl4.stats()["total"] == 0)

    print(f"\nsecurity.whitelist 自检：{ok} 通过 / {fail} 失败")
    return 1 if fail else 0


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="进程/文件/文件夹白名单（只降噪，不放行处置）")
    ap.add_argument("--add", nargs=2, metavar=("KIND", "VALUE"), action="append",
                    help="加入白名单，例如 --add process notepad.exe")
    ap.add_argument("--remove", nargs=2, metavar=("KIND", "VALUE"), action="append")
    ap.add_argument("--note", default="")
    ap.add_argument("--ttl-days", type=int, default=0)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    try:
        sys.stdout.reconfigure(errors="replace")  # type: ignore[union-attr]
    except Exception:  # noqa: BLE001
        pass

    wl = default_whitelist()
    if args.add:
        for kind, val in args.add:
            try:
                e = wl.add(kind, val, note=args.note, ttl_days=args.ttl_days)
                print(f"已加入：{e.kind} {e.value}")
            except RefusedError as exc:
                print(f"已拒绝：{kind} {val} —— {exc}")
                return 1
    if args.remove:
        for kind, val in args.remove:
            print(("已移除：" if wl.remove(kind, val) else "未找到：") + f"{kind} {val}")
    if args.list or not (args.add or args.remove):
        s = wl.stats()
        print(f"白名单（{s['total']} 条）：{s['path']}")
        for e in wl.entries():
            exp = f"  过期 {e.expires_at}" if e.expires_at else ""
            print(f"  [{e.kind:7s}] {e.value}{exp}   {e.note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
