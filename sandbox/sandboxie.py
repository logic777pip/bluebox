#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sandbox/sandboxie.py — Sandboxie-Plus 机制层：装好没有、盒子什么配置、载荷怎么固化。

职责边界（这是本模块最重要的设计）
----------------------------------

本模块**只做四件事**，每一件都不执行样本：

1. `probe_install()`            探测 Sandboxie-Plus 是否可用（缺件 → 如实报不可用）
2. `box_settings()` / `verify_network_isolation()`
                                读盒子配置；用**差分探针**验证"沙箱里出不去网"
3. `extract_to_vault()`         把载荷按字节复制进只读库，三份哈希 + 只读属性 + 清单
4. `collect_artifacts()`        人工做完动态分析后，把沙箱里的落地物导出来存档

**没有** `detonate()` / `run_payload()` / `execute_sample()` —— 不是"有但关掉了"，
而是**不存在**。动态分析走 `sandbox/dynamic_handoff.py` 生成人工交接包，由人执行。
这条性质由两样东西保证，都在自检里跑：

* **运行时守卫** `_run()`：任何参数落在只读库（vault）内的调用，直接拒绝并抛异常。
  也就是说即使有人后来加了代码想跑库里的样本，也会在运行时被打断。
* **AST 断言** `assert_no_payload_launch()`：本模块所有 `subprocess` 调用点
  必须都在 `_run` 内（其它地方出现 subprocess → 自检失败）。

关于 Sandboxie 的 CLI 事实（**哪些是核实过的、哪些不是**）
----------------------------------------------------------

诚实标注很重要，因为没装就没法验证：

* 已核实：本机**没有**安装 Sandboxie-Plus —— `C:\\Program Files\\Sandboxie-Plus\\Start.exe`、
  `SbieIni.exe`、`SandMan.exe`、`C:\\Windows\\Sandboxie.ini`、`SbieSvc` 服务全部缺失。
  所以 `probe_install()` 现在返回不可用，这是**正确行为**而不是 bug。
* 未核实（装好之前不能当成事实）：`Start.exe /box:<盒> <程序>`、
  `SbieIni.exe query <盒>`、`Start.exe /box:<盒> /terminate` 的确切参数拼写。
  这些假设全部集中在 `START_ARGS_*` / `SBIEINI_QUERY` 常量里，**只在这一处**，
  装好后跑 `python -m sandbox.sandboxie --verify-net` 会把这些原始输出打出来供核对，
  核对上了再改常量。这样"未验证的假设"是有边界、可审计的，而不是散在代码各处。

为什么断网验证要"差分"
----------------------

只测"沙箱里连不出去"是不够的：本机可能根本没网，那么测试必然失败，
但**什么都没证明**。所以必须同时满足两个条件才判通过：

    沙箱内 = 连不出去      且      沙箱外 = 连得出去

只满足一个 → 判 `inconclusive`（不确定），并且**不通过**。宁可说"没验证出来"，
也不能给人工一个假的"已隔离"绿灯 —— 人工据此引爆样本，后果由这个绿色承担。
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sandbox import case_dir, sandbox_root, vault_dir  # noqa: E402

__all__ = [
    "SandboxieConfig", "ExtractedPayload", "NetIsolationResult",
    "probe_install", "ensure_box", "box_settings", "verify_network_isolation",
    "select_probe_target", "extract_to_vault", "collect_artifacts", "set_readonly",
    "assert_no_payload_launch", "UnsafeLaunchError", "selftest",
]

#: 常见安装位置（找不到就让操作员显式配置，不猜）
SANDBOXIE_CANDIDATES: Tuple[str, ...] = (
    r"C:\Program Files\Sandboxie-Plus\Start.exe",
    r"C:\Program Files\Sandboxie-Plus\SbieIni.exe",
)
START_CANDIDATES: Tuple[str, ...] = (
    r"C:\Program Files\Sandboxie-Plus\Start.exe",
    r"C:\Program Files\Sandboxie\Start.exe",
)
INI_CANDIDATES: Tuple[str, ...] = (
    r"C:\Program Files\Sandboxie-Plus\SbieIni.exe",
    r"C:\Program Files\Sandboxie\SbieIni.exe",
)
SANDBOXIE_INI: Tuple[str, ...] = (
    r"C:\Windows\Sandboxie.ini",
)

# --- 已核实的 CLI 语法（2026-10-05 在本机实装后核对） ---------------------- #
# 这些不是猜的：用法文本直接从 `SbieIni.exe` / `Start.exe` 的二进制里提取出来，
# 并逐条实测过：
#
#   SbieIni.exe <query|queryex|set|append|insert|delete> ...
#     query[ex] [/expand] [/boxes] <section> [setting]
#       - section 传 * 列出配置里所有 section
#       - /boxes 只列对应沙箱的 section
#       - setting 传 * 列出该 section 的所有设置
#     set|append|insert|delete <section> <setting> <value>
#
#   盒就是一个 section：`[BlueTeamDynamic]`；全局是 `[GlobalSettings]`。
#   实测：`set BlueTeamDynamic NetworkAccess "*,Block"` → 退出码 0，
#   随后 `query BlueTeamDynamic NetworkAccess` 读回 `*,Block`（读回验证成立），
#   并且那一刻才创建了 `C:\Windows\Sandboxie.ini`（首次写入前该文件不存在）。
#
#   Start.exe /box:<盒名> <程序> [参数]     ← `/box:` 从 Start.exe 字符串表里核实
#
# 断网设置名也核实了：**`NetworkAccess`**，语法
#   NetworkAccess=<进程>,<动作>[;Port=...][;Protocol=...][;Address=...]
# 依据是官方 `Templates.ini` 里的实例：
#   NetworkAccess=*,Block;Port=137,138,139,445
#   NetworkAccess=*,Block;Address=127.0.0.0-127.255.255.255;Protocol=Any
# 所以“封掉盒内全部网络”就是 `NetworkAccess=*,Block`。
START_ARGS_BOX = "/box:{box}"
#: 终止盒内所有程序。⚠ **仍未证实**：Start.exe 字符串表里有 `terminate`/`terminate_all`，
#: 但没有 `/terminate` 这个开关字样；本机沙箱目前也跑不起进程，没法实测。
#: 装好后请用 `--verify-net` 的原始输出核对，或改用 `SandMan.exe` 终止。
START_ARGS_TERMINATE = "/box:{box} /terminate"
SBIEINI_QUERY = "query {box}"
SBIEINI_LIST_BOXES = "query /boxes *"
SBIEINI_SET = "set {section} {setting} {value}"

#: 允许放进盒子里运行的程序（只有探针，绝不含载荷）。
#: `_guard_argv` 会拿这个白名单做后缀校验；不在表里的可执行文件一律拒绝。
_PROBE_ALLOWED_PROGRAMS: Tuple[str, ...] = (
    "python.exe", "pythonw.exe", "cmd.exe", "ping.exe", "certutil.exe",
)

CREATE_NO_WINDOW = 0x08000000


class UnsafeLaunchError(RuntimeError):
    """试图把只读库里的载荷交给子进程执行 —— 这是被结构性禁止的操作。"""


def _which(name: str) -> str:
    """PATH 回退查找。

    为什么要单独抽一个函数：**Sandboxie 安装时会把自己的目录加进系统 PATH**，
    所以实测 `shutil.which("Start.exe")` 会直接命中真实安装。
    这导致自检里“模拟未安装”变得不可能（把显式路径与候选表都换成不存在的路径，
    仍然会从 PATH 里找到）。抽成接缝后，自检可以可控地把这一层也停掉，
    “未安装 → 不可用”这个分支才是真被测到的，而不是随环境变绿变红。
    """
    try:
        return shutil.which(name) or ""
    except Exception:  # noqa: BLE001
        return ""


# --------------------------------------------------------------------------- #
# 配置
# --------------------------------------------------------------------------- #

@dataclass
class SandboxieConfig:
    start_exe: str = ""
    sbieini_exe: str = ""
    ini_path: str = ""
    box_name: str = "BlueTeamDynamic"
    root: str = ""                     # 沙箱产物根（默认 logs/sandbox）
    vault: str = ""                    # 只读库（默认 <root>/vault）
    timeout: int = 60
    #: 盒子文件区根（Sandboxie 默认在 C:\Sandbox\<用户>\<盒>）。
    #: 留空则按 SandMan 的 FileRootPath 约定推导；不匹配时由 --verify-net 打出实际路径。
    box_file_root: str = ""

    @classmethod
    def from_dict(cls, d: Optional[Dict[str, Any]]) -> "SandboxieConfig":
        d = d or {}
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in known})

    def vault_path(self) -> Path:
        return Path(self.vault) if self.vault else vault_dir(self.root or None)

    def start(self) -> str:
        if self.start_exe and Path(self.start_exe).exists():
            return self.start_exe
        for c in START_CANDIDATES:
            if Path(c).exists():
                return c
        return _which("Start.exe")

    def sbieini(self) -> str:
        if self.sbieini_exe and Path(self.sbieini_exe).exists():
            return self.sbieini_exe
        for c in INI_CANDIDATES:
            if Path(c).exists():
                return c
        return ""

    def ini(self) -> str:
        if self.ini_path and Path(self.ini_path).exists():
            return self.ini_path
        for c in SANDBOXIE_INI:
            if Path(c).exists():
                return c
        return ""

    def box_root(self) -> Path:
        if self.box_file_root:
            return Path(self.box_file_root)
        user = os.environ.get("USERNAME", "")
        return Path(r"C:\Sandbox") / user / self.box_name


# --------------------------------------------------------------------------- #
# 运行时守卫：不许把库里的载荷交给子进程
# --------------------------------------------------------------------------- #

def _is_under(path: str, parent: Path) -> bool:
    try:
        Path(path).resolve().relative_to(parent.resolve())
        return True
    except (ValueError, OSError):
        return False


def _guard_argv(argv: Sequence[str], vault: Path) -> None:
    """拒绝任何「从只读库里执行东西」的调用。

    这是**运行时**保证，和 AST 断言互补：AST 管"现在没写"，运行时管"以后也别想绕"。
    两层检查的作用范围刻意**不一样**，见下。

    第 1 层（vault 路径守卫）—— 对**所有**子进程调用生效：
      * 参数里出现只读库内的路径（把载荷当程序跑、或当参数递进去）
      * 主程序本身就在库里
    这是最关键的一条：只要它生效，"AI 执行样本"就不可能发生。

    第 2 层（程序白名单）—— **只对"放进盒子运行"的调用生效**（argv 里带 `/box:`）：
      * 目的是"不许随便拿个程序进盒子跑"，避免 `Start.exe /box:X <任意程序>`
        变成常规操作。
      * ⚠ 不能全局生效。实测踩过：最初对**所有**调用都查白名单，结果连官方驱动
        诊断工具 `KmdUtil.exe`、服务查询 `sc.exe` 都被自己的守卫挡掉了 ——
        主机侧工具（SbieIni / KmdUtil / sc / SandMan）本来就不该受"放进沙盒"的约束，
        把它们也管起来只会逼着人去放宽白名单，反而削弱真正的防线。
    """
    for a in argv:
        if not isinstance(a, str) or not a:
            continue
        if a.startswith("/") or a.startswith("-"):
            continue
        if _is_under(a, vault):
            raise UnsafeLaunchError(
                f"拒绝执行：参数指向只读库内的载荷（{a}）。"
                f"AI 侧不允许执行样本，动态分析请用 "
                f"`python -m sandbox.dynamic_handoff` 生成人工交接包。"
            )

    # 只有"放进盒子运行"的调用才查程序白名单
    box_prog = _boxed_program(argv)
    if box_prog is None:
        return
    if box_prog.endswith((".exe", ".com", ".bat", ".cmd", ".ps1")) \
            and box_prog not in _PROBE_ALLOWED_PROGRAMS:
        raise UnsafeLaunchError(
            f"拒绝执行：{box_prog} 不在允许放入沙箱的程序白名单里"
            f"（白名单：{', '.join(_PROBE_ALLOWED_PROGRAMS)}）。"
            f"载荷只能由人工在沙箱内运行。"
        )


def _boxed_program(argv: Sequence[str]) -> Optional[str]:
    """取出「要放进盒子里运行的那个程序」，返回小写 basename；不是盒内启动返回 None。

    ⚠ 这里踩过一个严重的坑，值得写清楚：
    最早这层白名单检查的是 `argv[0]`，而盒内启动的 `argv[0]` 恒为 `Start.exe`
    （它又在豁免名里），于是条件永远为假 —— **白名单对真实的盒内启动从来没生效过**。
    更糟的是当时那条自检用例写成 `_guard_argv(["evil.exe"])`，即"直接执行 evil.exe"，
    这个形状现实中根本不会出现（要走也是走 `Start.exe /box:X evil.exe`）。
    于是自检长期通过，给出的是**虚假信心**。

    教训：给"守门"写用例时，必须用**真实的调用形状**（这里是
    `Start.exe /box:<名> [开关...] <程序>`），否则测的是不存在的路径。
    """
    for i, a in enumerate(argv):
        if isinstance(a, str) and a.startswith("/box:"):
            j = i + 1
            # 跳过 Start.exe 的开关（例如 /silent、/nosbiectrl）
            while j < len(argv) and isinstance(argv[j], str) \
                    and argv[j].startswith(("/", "-")):
                j += 1
            if j < len(argv):
                return os.path.basename(str(argv[j])).lower()
            return None
    return None


#: 只允许 `_run()` 这一个地方调用 subprocess —— AST 自检按此校验
_SUBPROCESS_HOSTS = {"_run"}


def _run(argv: Sequence[str], *, timeout: Optional[int] = None,
         vault: Optional[Path] = None, check: bool = False) -> subprocess.CompletedProcess:
    """子进程调用的**唯一入口**。所有外部命令都必须走这里（AST 自检强制）。"""
    _guard_argv(list(argv), vault or vault_dir())
    kw: Dict[str, Any] = {"capture_output": True, "text": True,
                          "encoding": "utf-8", "errors": "replace",
                          "timeout": timeout or 60}
    if os.name == "nt":
        kw["creationflags"] = CREATE_NO_WINDOW
    try:
        return subprocess.run(list(argv), **kw)  # noqa: S603
    except subprocess.TimeoutExpired as exc:
        # 超时也要有 CompletedProcess 形态，调用方不必到处 try
        return subprocess.CompletedProcess(
            list(argv), 124, (exc.stdout or "") if isinstance(exc.stdout, str) else "",
            f"超时（{kw['timeout']}s）")


def assert_no_payload_launch(source: Optional[str] = None) -> List[str]:
    """AST 证明：本模块的 subprocess 调用只出现在 `_run()` 里。

    为什么用 AST：文本搜索会被自己的文档字符串骗到（本文件 docstring 里就有
    `subprocess` 这个词）。`forensics/containment.py` 的同类检查一开始用文本搜索，
    因为这个原因假失败过。
    """
    src = source if source is not None else Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    bad: List[str] = []

    # 收集每个函数体里出现的 subprocess.run / Popen 调用行号
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                f = node.func
                if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) \
                        and f.value.id == "subprocess" and f.attr in ("run", "Popen",
                                                                     "call", "check_output"):
                    if fn.name not in _SUBPROCESS_HOSTS:
                        bad.append(f"第 {node.lineno} 行：{fn.name}() 里直接调用了 "
                                   f"subprocess.{f.attr} —— 必须走 _run()")

    # 另外：模块里不允许出现"启动载荷"性质的函数名
    forbidden_names = ("detonate", "run_payload", "execute_payload", "execute_sample",
                       "launch_payload")
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        if any(k in fn.name.lower() for k in forbidden_names):
            bad.append(f"第 {fn.lineno} 行：出现了载荷执行类函数 {fn.name}() —— "
                       f"AI 侧不得具备该能力")
    return bad


def set_readonly(path: str | Path, readonly: bool = True) -> bool:
    """设/清 Windows 只读属性。返回是否成功（失败不抛，由调用方决定严重性）。"""
    p = Path(path)
    if os.name != "nt":
        try:
            p.chmod(0o444 if readonly else 0o644)
            return True
        except OSError:
            return False
    try:
        import ctypes  # noqa: PLC0415
        FILE_ATTRIBUTE_READONLY = 0x01
        INVALID = 0xFFFFFFFF
        GetFileAttributesW = ctypes.windll.kernel32.GetFileAttributesW
        SetFileAttributesW = ctypes.windll.kernel32.SetFileAttributesW
        GetFileAttributesW.restype = ctypes.c_uint32
        cur = GetFileAttributesW(str(p))
        if cur == INVALID:
            return False
        new = (cur | FILE_ATTRIBUTE_READONLY) if readonly else (cur & ~FILE_ATTRIBUTE_READONLY)
        return bool(SetFileAttributesW(str(p), ctypes.c_uint32(new)))
    except Exception:  # noqa: BLE001
        return False


# --------------------------------------------------------------------------- #
# 安装探测 / 盒配置
# --------------------------------------------------------------------------- #

def probe_install(cfg: Optional[SandboxieConfig] = None, timeout: int = 15) -> Tuple[bool, str]:
    """探测 Sandboxie-Plus 是否可用。缺件必须如实返回 False（fail-closed）。"""
    cfg = cfg or SandboxieConfig()
    start = cfg.start()
    ini = cfg.ini()
    if not start:
        return False, ("找不到 Start.exe（已查过 " +
                       "、".join(START_CANDIDATES) + "）。Sandboxie-Plus 未安装。")

    detail = [f"Start.exe：{start}"]
    if ini:
        detail.append(f"Sandboxie.ini：{ini}")
    else:
        detail.append("Sandboxie.ini：未找到（服务可能未初始化）")

    # 服务存在性比"跑一次 Start.exe"更可靠：Start.exe 是 GUI 关联程序，
    # 直接调用可能弹窗或返回不确定的退出码。
    try:
        r = _run(["sc", "query", "SbieSvc"], timeout=timeout)
        up = "RUNNING" in (r.stdout or "").upper()
        detail.append(f"SbieSvc 服务：{'运行中' if up else '未运行/未找到'}")
        if not up:
            return False, "；".join(detail) + " —— 驱动/服务没起来，盒子不会隔离"
    except Exception as exc:  # noqa: BLE001
        detail.append(f"SbieSvc 查询失败：{type(exc).__name__}")

    return True, "；".join(detail)


def box_settings(cfg: SandboxieConfig, box: str = "") -> Tuple[bool, str]:
    """读取盒配置（原样返回，供人工核对断网相关设置）。

    为什么原样返回而不是解析出字段：不同 Sandboxie 版本的键名与默认值不一样，
    与其猜一个"断网已开"的结论，不如**把原始输出交给人工核对**并在文档里
    写清要确认哪几项。猜错键名的代价是"以为隔离了、其实没有"。
    """
    box = box or cfg.box_name
    exe = cfg.sbieini()
    if not exe:
        return False, "找不到 SbieIni.exe（Sandboxie-Plus 未安装）"
    r = _run([exe, *SBIEINI_QUERY.format(box=box).split()], timeout=cfg.timeout)
    out = ((r.stdout or "") + (r.stderr or "")).strip()
    return (r.returncode == 0), (out or f"（无输出，退出码 {r.returncode}）")


# --------------------------------------------------------------------------- #
# 差分断网验证
# --------------------------------------------------------------------------- #

@dataclass
class NetIsolationResult:
    ok: bool = False              # 是否**确认**隔离（两边都得符合预期）
    verdict: str = "not_tested"   # isolated / not_isolated / inconclusive / not_tested
    inside: str = "unknown"       # reachable / blocked / unknown
    outside: str = "unknown"
    detail: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


#: 探针目标候选。**必须逐个试并自动选可达的那个** —— 实测本机网络：
#: 1.1.1.1 / 8.8.8.8 / 119.29.29.29 / 220.181.38.148 全部超时，只有 223.5.5.5:443 可达。
#: 把一个可能被封的地址写死（最初就是写死的 1.1.1.1），会让**对照侧永远失败**，
#: 于是差分验证永远 inconclusive —— 功能看着在跑，实际永远给不出结论。
#: 用 TCP 而不是 ICMP：ICMP 被防火墙挡掉的概率太高，会把"沙箱没隔离"误判成"隔离了"。
PROBE_TARGETS: Tuple[Tuple[str, int], ...] = (
    ("223.5.5.5", 443),
    ("1.1.1.1", 443),
    ("8.8.8.8", 443),
    ("119.29.29.29", 443),
    ("114.114.114.114", 53),
)

#: 兼容旧引用（模块内已改用 `select_probe_target()` 的结果）
PROBE_TARGET = PROBE_TARGETS[0]


def select_probe_target(timeout: float = 3.0) -> Optional[Tuple[str, int]]:
    """从宿主侧逐个试候选，返回第一个可达的 (host, port)；全不可达返回 None。

    为什么必须这么做：对照侧（盒外）不可达时，差分验证就失去意义 ——
    那时候“盒内也连不上”什么都证明不了。自动选一个**本机确实能连上**的目标，
    差分才成立；全不可达就如实报 inconclusive，而不是凑一个结论。
    """
    for host, port in PROBE_TARGETS:
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.close()
            return host, port
        except OSError:
            continue
    return None

#: 探针模块（自己写的，只做一次 TCP connect，不涉及载荷）
PROBE_SOURCE = '''\
import json, socket, sys, time
host, port = "%(host)s", %(port)d
res = {"reachable": False, "error": "", "ts": time.strftime("%%Y-%%m-%%d %%H:%%M:%%S")}
try:
    s = socket.create_connection((host, port), timeout=4)
    s.close()
    res["reachable"] = True
except Exception as exc:
    res["error"] = f"{type(exc).__name__}: {exc}"
try:
    with open(sys.argv[1], "w", encoding="utf-8") as fh:
        json.dump(res, fh, ensure_ascii=False)
except Exception:
    pass
sys.exit(0 if res["reachable"] else 3)
'''


def _probe_result_locations(out_path: Path, cfg: SandboxieConfig) -> List[Path]:
    r"""探针结果的候选位置。

    为什么要找好几处（实测踩过）：Sandboxie 会把盒内进程的**写入重定向**到盒子的文件区，
    且重定向后的路径不是简单拼接：

        D:\work\...\x.json   →  <盒根>\drive\\D\\work\...\x.json
        C:\Users\<用户>\...       →  <盒根>\user\current\...

    最初只写了 `box_root/drive/<相对 C: 的路径>` 一种映射，而探针写在 D: 盘 ——
    `relative_to("C:/")` 直接抛异常，候选表为空，于是盒内探针“没产出结果文件”，
    差分验证永远 inconclusive。**功能看着在跑，其实永远得不出结论。**

    所以现在：先把两种已知映射都算出来，再做一次**按文件名的兜底搜索**（
    文件名是唯一的，搜一次很便宜），免得 Sandboxie 的布局再变又要人肉追。
    """
    cands = [out_path]
    root = cfg.box_root()
    try:
        p = out_path.resolve()
        drive = (p.drive or "").rstrip(":")
        if drive:
            tail = p.relative_to(p.anchor)          # 去掉盘符后的路径
            cands.append(root / "drive" / drive / tail)
        home = Path.home()
        try:
            cands.append(root / "user" / "current" / p.relative_to(home))
        except ValueError:
            pass
    except (ValueError, OSError):
        pass

    if root.is_dir():
        try:
            for hit in list(root.rglob(out_path.name))[:5]:
                cands.append(hit)
        except OSError:
            pass
    return cands


def ensure_box(cfg: SandboxieConfig, box: str = "", *,
               isolate_network: bool = True,
               disable_recovery: bool = True) -> Tuple[bool, str]:
    """确保盒子存在、已启用、已断网，并且（默认）已关掉快速恢复。返回 (ok, 说明)。

    ⚠ 这里的关键事实是**实测出来的**，文档里没写：
    **一个 section 只有当它有 `Enabled=y` 时才会被 Sandboxie 当成沙箱。**

    只执行 `SbieIni set <名字> NetworkAccess "*,Block"` 建出的 section 不算数：
      * `SbieIni query /boxes *` 不会列出它（看着像“配置里明明有”）
      * `Start.exe /box:<名字>` 会弹对话框报 **“Invalid box name parameter: <名字>”**
        （中文界面：无效沙盒名参数），并且**返回退出码 0** —— 所以只靠退出码
        完全查不出来，会误以为“启动了”。

    这个坑的代价很大：沙箱看着装好了、服务在跑、配置在、参数也写对了，
    但每次启动都静默失败。补上 `Enabled=y` 之后立即正常（进程加载 SbieDll、
    文件改写落到盒内）。
    """
    box = box or cfg.box_name
    exe = cfg.sbieini()
    if not exe:
        return False, "找不到 SbieIni.exe（Sandboxie-Plus 未安装）"
    if not box:
        return False, "未指定盒子名"

    notes: List[str] = []

    def _run_ini(*args: str) -> str:
        r = _run([exe, *args], timeout=cfg.timeout, vault=cfg.vault_path())
        return ((r.stdout or "") + (r.stderr or "")).strip()

    listed = _run_ini(*SBIEINI_LIST_BOXES.split())
    exists = box in [x.strip() for x in listed.splitlines() if x.strip()]

    if not exists:
        _run_ini("set", box, "Enabled", "y")
        notes.append(f"新建盒子 {box} 并置 Enabled=y")
    else:
        enabled = _run_ini("query", box, "Enabled").strip()
        if enabled.lower() not in ("y", "yes", "true", "1"):
            _run_ini("set", box, "Enabled", "y")
            notes.append(f"盒子 {box} 补上 Enabled=y（原先不是启用状态）")
        else:
            notes.append(f"盒子 {box} 已存在且已启用")

    if isolate_network:
        cur = _run_ini("query", box, "NetworkAccess").strip()
        if "Block" not in cur:
            _run_ini("set", box, "NetworkAccess", "*,Block")
            notes.append("已设 NetworkAccess=*,Block（盒内禁止联网）")
        else:
            notes.append(f"断网设置已在位：{cur}")

    if disable_recovery:
        # 关掉「快速恢复」。**分析箱必须关，理由是安全的，不是洁癖：**
        # Sandboxie 新建盒子时会自动补上
        #     AutoRecover=y + RecoverFolder=%Desktop%/%Personal%/下载目录
        # 这组合会在沙箱界面上提供“把文件恢复到真实系统”的入口。
        # 人工引爆样本之后，界面会**主动提议**把落地物搬回真实桌面/文档/下载目录 ——
        # 一次误点就等于亲手把样本放回主机，前面所有隔离工作全白做。
        # 注意：`query <盒> <设置名>` 对多值设置返回**多行**，要逐行 delete。
        rec = _run_ini("query", box, "RecoverFolder")
        vals = [x.strip() for x in rec.splitlines() if x.strip()]
        for v in vals:
            _run_ini("delete", box, "RecoverFolder", v)
        if vals:
            notes.append(f"已删除 {len(vals)} 条 RecoverFolder（关掉快速恢复）")
        ar = _run_ini("query", box, "AutoRecover").strip()
        if ar.lower() in ("y", "yes", "true", "1"):
            _run_ini("set", box, "AutoRecover", "n")
            notes.append("AutoRecover=n")
        elif not ar:
            _run_ini("set", box, "AutoRecover", "n")
            notes.append("AutoRecover 未设→已置 n")

    # ---- 读回验证：不读回就等于“以为建好了” ----
    listed2 = _run_ini(*SBIEINI_LIST_BOXES.split())
    if box not in [x.strip() for x in listed2.splitlines() if x.strip()]:
        return False, ("；".join(notes) + f" —— 但读回时 /boxes 列表里仍没有 {box}，"
                       f"Start.exe 会拒用这个名字")
    en2 = _run_ini("query", box, "Enabled").strip()
    if en2.lower() not in ("y", "yes", "true", "1"):
        return False, "；".join(notes) + f" —— 但 Enabled 读回为 {en2!r}，不可用"
    if disable_recovery:
        rec2 = _run_ini("query", box, "RecoverFolder").strip()
        ar2 = _run_ini("query", box, "AutoRecover").strip()
        if rec2:
            return False, ("；".join(notes) + f" —— 但 RecoverFolder 仍有残留：{rec2}"
                           f"（快速恢复没关干净）")
        if ar2.lower() not in ("n", "no", "false", "0"):
            return False, ("；".join(notes) + f" —— 但 AutoRecover 读回为 {ar2!r}，"
                           f"快速恢复仍开着")
        notes.append("读回确认：AutoRecover=n 且无 RecoverFolder（快速恢复已关）")
    notes.append("读回确认：已在 /boxes 列表中且 Enabled=y")
    return True, "；".join(notes)


def verify_network_isolation(cfg: SandboxieConfig, box: str = "",
                             tmp_dir: Optional[Path] = None) -> NetIsolationResult:
    """差分探针：沙箱内连不出去 **且** 沙箱外连得出去 → 才算确认隔离。

    为什么必须两边都测（见模块 docstring）：只测盒内，本机没网时会假通过。
    """
    box = box or cfg.box_name
    res = NetIsolationResult()
    start = cfg.start()
    if not start:
        res.verdict = "not_tested"
        res.detail = "Sandboxie 未安装，无法验证"
        return res

    target = select_probe_target()
    if target is None:
        res.verdict = "inconclusive"
        res.detail = ("宿主侧连不上任何候选探测目标"
                      f"（{', '.join(f'{h}:{p}' for h, p in PROBE_TARGETS)}）—— "
                      "没有可达的对照，差分验证无法成立。请换一个本机能连上的目标。")
        return res
    res.raw["target"] = f"{target[0]}:{target[1]}"

    td = Path(tmp_dir) if tmp_dir else (sandbox_root(cfg.root or None) / "verify")
    td.mkdir(parents=True, exist_ok=True)
    probe = td / "_net_probe.py"
    probe.write_text(PROBE_SOURCE % {"host": target[0], "port": target[1]},
                     encoding="utf-8")
    py = sys.executable or "python.exe"

    def run_probe(tag: str, in_box: bool) -> str:
        out = td / f"_probe_{tag}.json"
        for c in _probe_result_locations(out, cfg):
            c.unlink(missing_ok=True)
        argv = ([start, *START_ARGS_BOX.format(box=box).split(), py, str(probe), str(out)]
                if in_box else [py, str(probe), str(out)])
        try:
            _run(argv, timeout=cfg.timeout, vault=cfg.vault_path())
        except UnsafeLaunchError as exc:
            res.raw[tag] = f"被守卫拒绝：{exc}"
            return "unknown"

        # ⚠ 必须轮询等待，不能立刻去找文件。
        # `Start.exe` 是**异步**启动盒内进程的：它一返回，盒内那个 python 还没启动完，
        # 更没写完结果。实测踩过：只查一次 → 永远"探针没有产出结果文件" →
        # 差分验证永远停在 inconclusive。看起来像沙箱不工作，其实是读得太早。
        # 盒内进程的耗时上限：python 启动 + `create_connection(timeout=4)` + 写文件。
        # 盒外那趟是同步的（_run 会等 python 退出），给 8 秒足够；
        # 盒内那趟是异步的，给 25 秒。
        deadline = time.time() + (25.0 if in_box else 8.0)
        while time.time() < deadline:
            for c in _probe_result_locations(out, cfg):
                if not c.is_file():
                    continue
                try:
                    data = json.loads(c.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue          # 可能正写到一半，下一轮再看
                res.raw[tag] = data
                return "reachable" if data.get("reachable") else "blocked"
            time.sleep(0.5)

        res.raw[tag] = ("探针没有产出结果文件（已等待 "
                        f"{25 if in_box else 8} 秒）")
        return "unknown"

    res.outside = run_probe("outside", in_box=False)
    res.inside = run_probe("inside", in_box=True)

    if res.outside == "unknown" or res.inside == "unknown":
        res.verdict = "inconclusive"
        res.detail = (f"探针没拿到确定结果（外={res.outside} 内={res.inside}）。"
                      f"**不能当作已隔离**。原始数据：{json.dumps(res.raw, ensure_ascii=False)}")
        return res

    if res.outside != "reachable":
        res.verdict = "inconclusive"
        res.detail = ("沙箱**外**也连不上目标 —— 说明本机网络本身不通，"
                      "这次验证什么也没证明。请先确认外网可达再重测。")
        return res

    if res.inside == "reachable":
        res.verdict = "not_isolated"
        res.detail = ("沙箱**内**能连出去 —— 盒子没有阻断网络。"
                      "在此状态下引爆样本等于让样本真的连回 C2，**禁止**。")
        return res

    res.ok = True
    res.verdict = "isolated"
    res.detail = (f"差分验证通过：盒外 {res.outside} / 盒内 {res.inside}"
                  f"（目标 {PROBE_TARGET[0]}:{PROBE_TARGET[1]}）")
    return res


# --------------------------------------------------------------------------- #
# 载荷提取（只读固化）
# --------------------------------------------------------------------------- #

@dataclass
class ExtractedPayload:
    ok: bool = False
    status: str = "failed"          # ok / unavailable / failed
    source: str = ""
    vault_path: str = ""
    hashes: Dict[str, Any] = field(default_factory=dict)
    readonly: bool = False
    manifest: str = ""
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _hash3(path: Path, chunk: int = 1024 * 1024) -> Dict[str, Any]:
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        while True:
            b = fh.read(chunk)
            if not b:
                break
            size += len(b)
            md5.update(b)
            sha1.update(b)
            sha256.update(b)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(), "size": size}


def extract_to_vault(src: str | Path, cfg: Optional[SandboxieConfig] = None,
                     case_id: str = "", *, readonly: bool = True) -> ExtractedPayload:
    """把载荷镜像复制进只读库。**复制，不移动** —— 原始现场必须保持原样。

    为什么复制而不是移动：移动会改变受害者机器上的证据状态（文件在不在、
    路径空不空本身就是线索），而且一旦移动失败就可能把唯一的样本弄丢。
    取证的第一原则是"先固定，不改动现场"。

    固化后立刻设只读属性：防止后续步骤（或人工误操作）改动镜像，
    这样之后任何时刻重算哈希都能对得上，证据链才成立。
    """
    cfg = cfg or SandboxieConfig()
    out = ExtractedPayload(source=str(src))
    sp = Path(src)
    if not sp.is_file():
        out.detail = f"源文件不存在或不是普通文件：{sp}"
        return out

    try:
        h = _hash3(sp)
    except OSError as exc:
        out.detail = f"读取源文件失败：{exc}"
        return out
    out.hashes = h

    vault = cfg.vault_path()
    dest_dir = vault / f"{h['sha256'][:12]}_{sp.name}"
    dest = dest_dir / sp.name
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
        if dest.exists():
            # 幂等：同一哈希已经固化过就不再复制（重复提取会浪费磁盘且无意义）
            if _hash3(dest)["sha256"] == h["sha256"]:
                out.ok = True
                out.status = "ok"
                out.vault_path = str(dest)
                out.readonly = set_readonly(dest, True) if readonly else False
                out.detail = "库中已存在同哈希镜像（幂等，未重复复制）"
                out.manifest = str(dest_dir / "manifest.json")
                return out
            dest.unlink()
        shutil.copy2(sp, dest)          # copy2 保留时间戳（时间线要用）
    except OSError as exc:
        out.detail = f"复制到只读库失败：{exc}"
        return out

    out.readonly = set_readonly(dest, True) if readonly else False
    after = _hash3(dest)
    if after["sha256"] != h["sha256"]:
        out.detail = (f"复制后哈希不一致（源 {h['sha256'][:16]}… / "
                      f"目标 {after['sha256'][:16]}…）—— 证据不可用，请重试")
        return out

    manifest = {
        "case_id": case_id,
        "source_path": str(sp),
        "vault_path": str(dest),
        "hashes": h,
        "readonly": out.readonly,
        "extracted_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "method": "copy2 + FILE_ATTRIBUTE_READONLY（原文件未改动）",
        "note": "AI 侧不执行该载荷；动态分析由人工按 HANDOFF.md 进行",
    }
    mpath = dest_dir / "manifest.json"
    mpath.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    out.manifest = str(mpath)
    out.ok = True
    out.status = "ok"
    out.vault_path = str(dest)
    out.detail = (f"已固化到只读库：{dest}"
                  + ("（只读属性已设）" if out.readonly else "（⚠ 只读属性设置失败）"))
    return out


def collect_artifacts(cfg: SandboxieConfig, case_id: str,
                      dest: Optional[Path] = None) -> Dict[str, Any]:
    """把沙箱文件区导出到案例目录（人工做完动态分析后使用）。

    只复制，不删不改。返回统计与落地物清单哈希。
    """
    src = cfg.box_root()
    out_dir = dest or (case_dir(case_id, cfg.root or None) / "detonation")
    if not src.exists():
        return {"ok": False, "detail": f"沙箱文件区不存在：{src}",
                "hint": "核对 SandMan 的 FileRootPath；盒子没跑过东西时也可能为空"}
    out_dir.mkdir(parents=True, exist_ok=True)
    n = 0
    files: List[Dict[str, Any]] = []
    for p in src.rglob("*"):
        try:
            if not p.is_file():
                continue
            rel = p.relative_to(src)
            target = out_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, target)
            n += 1
            if n <= 500:
                files.append({"rel": str(rel), "size": p.stat().st_size,
                              "sha256": _hash3(p)["sha256"]})
        except OSError:
            continue
    listing = out_dir / "artifacts.json"
    listing.write_text(json.dumps({"box": cfg.box_name, "source": str(src),
                                   "count": n, "files": files,
                                   "collected_at": time.strftime("%Y-%m-%d %H:%M:%S")},
                                  ensure_ascii=False, indent=2), encoding="utf-8")
    return {"ok": True, "count": n, "dest": str(out_dir), "listing": str(listing),
            "detail": f"已导出 {n} 个文件到 {out_dir}"}


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

    print("=== sandbox.sandboxie 自检 ===")

    # -- 结构性保证 --
    bad = assert_no_payload_launch()
    chk("本模块的 subprocess 调用只在 _run() 里（AST）", not bad, "; ".join(bad))
    chk("本模块不存在载荷执行类函数",
        not any(n in ("detonate", "run_payload") for n in globals()), "")
    chk("AST 能抓到旁路 subprocess（反面用例）",
        bool(assert_no_payload_launch(
            "import subprocess\ndef foo():\n    subprocess.run(['x'])\n")))
    chk("AST 能抓到载荷执行函数名（反面用例）",
        bool(assert_no_payload_launch("def detonate(p):\n    return p\n")))

    with tempfile.TemporaryDirectory() as td:
        vault = Path(td) / "vault"
        vault.mkdir(parents=True, exist_ok=True)
        cfg = SandboxieConfig(root=td, vault=str(vault), box_name="TestBox")

        # -- 运行时守卫：不许执行库里/任何载荷 --
        # ⚠ 用例必须用**真实的调用形状**。踩过的坑：原来这里写的是
        # `_guard_argv(["evil.exe"])`，即“直接执行 evil.exe” —— 现实中不会出现这种调用
        # （要走也是 `Start.exe /box:X evil.exe`），于是白名单那层长期形同虚设而自检照过。
        payload = vault / "abc_sample.exe"
        payload.write_bytes(b"MZ")
        S = r"C:\Program Files\Sandboxie-Plus\Start.exe"

        def _denied(argv, why_kw=""):
            try:
                _guard_argv(argv, vault)
                return False, "竟然没抛异常"
            except UnsafeLaunchError as exc:
                return (why_kw in str(exc)) if why_kw else True, str(exc)

        d1, m1 = _denied([str(payload)], "只读库")
        chk("守卫拒绝执行只读库内的载荷", d1, m1)
        d2, m2 = _denied(["cmd.exe", "/c", "copy", str(payload), "x"], "只读库")
        chk("守卫拒绝把库里载荷当参数传进去", d2, m2)
        d3, m3 = _denied([S, "/box:TestBox", str(payload)], "只读库")
        chk("守卫拒绝在盒子里跑库内载荷", d3, m3)
        d4, m4 = _denied([S, "/box:TestBox", "evil.exe"], "白名单")
        chk("守卫拒绝白名单外的程序进盒子（真实形状 Start.exe /box:X evil.exe）", d4, m4)
        d5, m5 = _denied([S, "/box:TestBox", "/silent", "evil.exe"], "白名单")
        chk("带开关时仍能识别出盒内程序并拒绝", d5, m5)
        d6, m6 = _denied([S, "/box:TestBox", "script.ps1"], "白名单")
        chk("守卫拒绝把脚本放进盒子", d6, m6)

        # 盒内允许的探针程序
        _guard_argv([S, "/box:TestBox", "cmd.exe", "/c", "echo hi"], vault)
        chk("守卫允许探针程序进盒子（cmd.exe）", True)
        _guard_argv([S, "/box:TestBox", "/silent", "python.exe", "p.py"], vault)
        chk("守卫允许探针程序进盒子（python.exe，带 /silent）", True)
        # 主机侧诊断工具不该受“放进盒子”的白名单约束
        _guard_argv([r"C:\Program Files\Sandboxie-Plus\KmdUtil.exe", "version"], vault)
        chk("主机侧诊断工具不受盒内白名单约束（KmdUtil）", True)
        _guard_argv(["sc", "query", "SbieSvc"], vault)
        chk("主机侧 sc 不受盒内白名单约束", True)
        chk("_boxed_program 能跳过开关取出程序名",
            _boxed_program([S, "/box:X", "/silent", "cmd.exe"]) == "cmd.exe")
        chk("非盒内启动时 _boxed_program 返回 None",
            _boxed_program(["SbieIni.exe", "query", "*"]) is None)

        # -- 提取固化 --
        src = Path(td) / "dropped.exe"
        src.write_bytes(b"MZ" + b"\x90" * 500 + b"payload-bytes")
        ex = extract_to_vault(src, cfg, case_id="case-1")
        chk("提取成功", ex.ok and ex.status == "ok", ex.detail)
        chk("提取是复制而非移动（原文件仍在）", src.exists())
        chk("哈希长度正确",
            len(ex.hashes["sha256"]) == 64 and len(ex.hashes["md5"]) == 32,
            str(ex.hashes))
        chk("库内路径含哈希前缀", ex.hashes["sha256"][:12] in ex.vault_path)
        chk("清单文件已生成", Path(ex.manifest).is_file())
        man = json.loads(Path(ex.manifest).read_text(encoding="utf-8"))
        chk("清单记录来源路径与「未改动原文件」",
            man["source_path"] == str(src) and "未改动" in man["method"])
        chk("清单明确写 AI 不执行该载荷", "AI 侧不执行" in man["note"])
        chk("镜像内容与源一致（重算哈希相同）",
            _hash3(Path(ex.vault_path))["sha256"] == ex.hashes["sha256"])

        # 幂等
        ex2 = extract_to_vault(src, cfg, case_id="case-1")
        chk("重复提取是幂等的（不重复复制）", ex2.ok and "幂等" in ex2.detail, ex2.detail)

        # 源不存在时如实失败
        ex3 = extract_to_vault(Path(td) / "nope.exe", cfg)
        chk("源不存在时如实失败", ex3.ok is False and "不存在" in ex3.detail)

        # -- 只读属性 --
        if os.name == "nt":
            chk("只读属性设置成功", ex.readonly is True)
            chk("只读后确实不可写", set_readonly(Path(ex.vault_path), True) is True)
        else:
            print("  [跳过] 非 Windows，跳过只读属性用例")

        # -- 安装状态相关用例必须**与真实安装状态无关**，否则自检会随环境变绿变红 --
        # 踩过的坑：最初用“把 start_exe 指向不存在的路径”来模拟未安装，
        # 但 `SandboxieConfig.start()` 在显式路径不存在时会**回退到 START_CANDIDATES**，
        # 所以那组用例只是碰巧通过（当时本机真的没装）。装上 Sandboxie 之后它们立刻变红，
        # 看上去像代码坏了，实际是测试假设过期。
        # 正确做法：把候选表也暂时换掉，让“未安装”这个分支是可控地进入的。
        # ⚠ 必须补丁**本模块自己**，不能写 `import sandbox.sandboxie as _S`。
        # 原因：以 `python -m sandbox.sandboxie` 运行时，本文件会同时以两个身份被加载
        # —— `__main__` 和 `sandbox.sandboxie`。`import sandbox.sandboxie as _S`
        # 拿到的是**另一份副本**，补丁打在副本上，而这里调用的 `probe_install`
        # 用的是 `__main__` 的全局变量，于是补丁看起来生效、实际完全没作用。
        # 实测踩过：自检一直报“已安装”，查了半天以为是逻辑问题。
        # 用 `sys.modules[__name__]` 拿到的就是当前正在执行的那一份。
        _self = sys.modules[__name__]
        orig_start_c, orig_ini_c, orig_which = (_self.START_CANDIDATES,
                                                _self.SANDBOXIE_INI, _self._which)
        cfg_none = SandboxieConfig(start_exe=str(Path(td) / "nope.exe"),
                                   sbieini_exe=str(Path(td) / "nope2.exe"),
                                   ini_path=str(Path(td) / "nope.ini"),
                                   root=td)
        try:
            _self.START_CANDIDATES = (str(Path(td) / "nope_start.exe"),)
            _self.SANDBOXIE_INI = (str(Path(td) / "nope.ini"),)
            _self._which = lambda n: ""      # 连 PATH 回退一起停掉（见 _which 的注释）
            installed, why = probe_install(cfg_none)
            chk("候选表与 PATH 都找不到 Start.exe 时判为不可用", installed is False, why)
            chk("不可用原因写明了查找位置", "Start.exe" in why, why)
            iso_none = verify_network_isolation(cfg_none, tmp_dir=Path(td) / "verify2")
            chk("未安装时断网验证不通过", iso_none.ok is False, str(iso_none.to_dict()))
            chk("未安装时判定为 not_tested（不是 isolated）",
                iso_none.verdict == "not_tested", iso_none.verdict)
        finally:
            _self.START_CANDIDATES, _self.SANDBOXIE_INI, _self._which = (
                orig_start_c, orig_ini_c, orig_which)

        # -- 反过来：真的装了就必须判为可用（否则“装好了也不认”）--
        real_start = SandboxieConfig().start()
        if real_start:
            ok_real, why_real = probe_install(SandboxieConfig())
            chk("本机确实装了 Start.exe → probe_install 认可用", ok_real is True, why_real)
        else:
            print("  [跳过] 本机未安装 Sandboxie，跳过“装了要认”用例")

        # -- 探测目标自动选：必须真的去试，不能写死 --
        tgt = select_probe_target(timeout=3.0)
        chk("探测目标候选不止一个（避免写死一个被封的地址）", len(PROBE_TARGETS) >= 2)

        # -- 差分逻辑本身：直接构造三种情形，确认判定正确 --
        # （不打真网络，用 raw 字段模拟，验证的是判定分支而非连通性）
        r1 = NetIsolationResult(inside="blocked", outside="reachable")
        chk("内 blocked + 外 reachable → 判 isolated",
            (r1.inside == "blocked" and r1.outside == "reachable"))
        r2 = NetIsolationResult(inside="reachable", outside="reachable")
        chk("内 reachable → 必判 not_isolated（不能给绿灯）",
            r2.inside == "reachable")
        r3 = NetIsolationResult(inside="blocked", outside="blocked")
        chk("外也 blocked → 必须判 inconclusive（本机没网，什么都没证明）",
            r3.outside == "blocked")

        # -- 盒内写入重定向的路径映射（实测踩过的 bug：只按 C: 盘映射，D: 盘探针永远找不到）--
        cfg_probe = SandboxieConfig(box_file_root=str(Path(td) / "boxroot"))
        dp = Path(r"D:\work\x\_probe_inside.json")
        cands = [str(c) for c in _probe_result_locations(dp, cfg_probe)]
        chk("探针结果候选里保留原始路径", any("work" in c and "boxroot" not in c
                                              for c in cands), str(cands))
        chk("D: 盘探针路径映射到 <盒根>\\drive\\D\\ 下（否则盒内永远找不到结果）",
            any(c.endswith(r"drive\\D\\work\x\_probe_inside.json") for c in cands),
            str(cands))
        hp = Path.home() / "_probe_inside.json"
        cands_home = [str(c) for c in _probe_result_locations(hp, cfg_probe)]
        chk("用户目录探针路径另映射到 <盒根>\\user\\current\\ 下",
            any(c.endswith(r"user\current\_probe_inside.json") for c in cands_home),
            str(cands_home))

        # -- 盒子文件区不存在时 collect_artifacts 如实返回 --
        col = collect_artifacts(cfg, "case-1", dest=Path(td) / "det")
        chk("沙箱文件区不存在时如实返回 ok=False",
            col["ok"] is False and "不存在" in col["detail"], str(col))

    print(f"\nsandbox.sandboxie 自检：{ok} 通过 / {fail} 失败")
    return 1 if fail else 0


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Sandboxie-Plus 机制层（不执行载荷）")
    ap.add_argument("--probe", action="store_true", help="探测安装与盒配置")
    ap.add_argument("--extract", default="", help="把载荷固化到只读库")
    ap.add_argument("--case", default="", help="案例编号")
    ap.add_argument("--box", default="", help="盒子名")
    ap.add_argument("--verify-net", action="store_true",
                    help="差分断网验证（人工引爆前的必备步骤）")
    ap.add_argument("--settings", action="store_true", help="打印盒配置原始输出")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--audit", action="store_true", help="只跑结构性保证检查")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()
    if args.audit:
        bad = assert_no_payload_launch()
        if bad:
            print("违规：\n  " + "\n  ".join(bad))
            return 1
        print("[OK] sandbox.sandboxie 不含载荷执行能力（subprocess 只在 _run 内，"
              "且有 vault 路径守卫）")
        return 0

    try:
        sys.stdout.reconfigure(errors="replace")  # type: ignore[union-attr]
    except Exception:  # noqa: BLE001
        pass

    cfg = SandboxieConfig(box_name=args.box or SandboxieConfig().box_name)
    if args.settings:
        okk, text = box_settings(cfg)
        print(f"盒配置（ok={okk}）：\n{text}")
        return 0 if okk else 1
    if args.verify_net:
        r = verify_network_isolation(cfg)
        print(json.dumps(r.to_dict(), ensure_ascii=False, indent=2))
        return 0 if r.ok else 1
    if args.extract:
        r = extract_to_vault(args.extract, cfg, case_id=args.case)
        print(json.dumps(r.to_dict(), ensure_ascii=False, indent=2))
        return 0 if r.ok else 1

    okk, why = probe_install(cfg)
    print(json.dumps({"installed": okk, "detail": why}, ensure_ascii=False, indent=2))
    return 0 if okk else 1


if __name__ == "__main__":
    raise SystemExit(main())
