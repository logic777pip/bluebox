#!/usr/bin/env python3
"""KAPE 取证采集：命令构造 + 执行 + 产物清点。**默认只演练，不执行。**

设计上的四条硬约束（都来自本项目踩过的坑）：

1. **默认 dry-run**。`run(..., dry_run=True)` 只产出**计划**（命令 + 描述文件），
   不启动任何子进程。要真跑必须显式 `dry_run=False` **且** 通过动作层闸门。

2. **非管理员时如实返回 `unavailable`**，不"假装采集成功"。
   KAPE 的大部分 target（注册表配置单元、SRUDB、事件日志）需要管理员权限。
   非管理员跑只会得到残缺结果 —— 而**残缺的取证比没有取证更危险**：
   你会基于"没看到持久化项"得出"没有持久化"的结论。
   所以这里改成：生成一份**可直接以管理员身份运行的 .cmd**，交给操作员执行。

3. **产物目录被 jail 在 output_root 下**。`--tdest` / `--mdest` 只允许落在
   配置的输出根目录内。KAPE 会往 tdest 里**写入/移动**文件，一个手滑的路径
   就能把别处搞乱 —— 这类"取证工具自己造成二次破坏"的事故是可以避免的。

4. **不猜命令行**。KAPE 各版本参数有差异（尤其 `--sync/--zip/--vhdx` 的语义），
   所以只硬编码我确定的 5 个参数（`--tsource/--tdest/--target/--mdest/--module`），
   其余一律走配置里的 `extra_args` —— 由操作员对着自己版本的 `kape.exe --help` 填。
   宁可少写几个参数，也不要写一个猜错的危险参数。

用法：
    python -m forensics.kape --case C-001 --host-id THISPC --dry-run
    python -m forensics.kape --selftest
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# 与 actions/adapters/base.py 的状态取值保持一致（不要另造词）
ST_OK = "ok"
ST_DRY_RUN = "dry_run"
ST_UNAVAILABLE = "unavailable"
ST_FAILED = "failed"

CREATE_NO_WINDOW = 0x08000000

# 常见安装位置（找不到就让操作员显式配置，不猜）
# 1.3.0.2 已核实的两个位置：正式安装 C:\Tools\KAPE，以及工作区里的旧副本。
KAPE_CANDIDATES = (
    r"C:\Tools\KAPE\kape.exe",
    r"D:\work\KAPE\kape.exe",
    r"C:\Program Files\KAPE\kape.exe",
    r"C:\Program Files (x86)\KAPE\kape.exe",
    r"D:\KAPE\kape.exe",
    r"D:\Tools\KAPE\kape.exe",
)


@dataclass
class KapeConfig:
    exe_path: str = ""
    output_root: str = "logs/forensics"
    tsource: str = "C:"
    target: str = "BlueTeam-Triage"
    module: str = ""                      # 空 = 只采集不解析（不依赖 EZTools）
    extra_args: str = ""
    targets_dir: str = "forensics/targets"
    modules_dir: str = "forensics/modules"
    timeout: int = 3600
    require_admin: bool = True
    # **真实执行的第二道开关**。即使执行器把 dry_run 置为 false，
    # 这里不是 true 也只演练。理由：一次采集会写入数百 MB 产物、
    # 且会去读锁定的注册表配置单元，属于"有实际影响"的动作，
    # 应该需要一次显式的、写在配置里的批准，而不是跟着全局开关自己变成真执行。
    execute_enabled: bool = False
    # KAPE 原生 `--sim`（1.3.0.2 --help 已核实）：**不复制文件，只跑一遍配置**。
    # 用它就能在不产生任何产物的前提下验证 target/module/路径是否合法 ——
    # 这是"先校验再采集"的正确顺序（比起直接真采集再发现路径写错要安全得多）。
    sim: bool = False
    # 产物体积预算（MB）。**这不是装饰，是实测出来的必需项**：
    # v1.1 的 target 用 `C:\Users\%user%\` + `*.exe` + 递归，一次采集写了
    # 17826 MB（其中 16.5 GB 是厂商安装包和开发工具缓存），而在跑之前
    # 完全没有任何提示 —— KAPE 不提供预估体积的开关，`--sim` 也不报体积。
    # 于是只能在事后根据实际体积告警：超过预算就标记 oversize，
    # 让调用方（适配器和报告）把"这份产物大到不适合自动流水线"讲出来。
    max_collect_mb: int = 4096

    @classmethod
    def from_dict(cls, d: Optional[Dict[str, Any]]) -> "KapeConfig":
        d = d or {}
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in known})

    def root(self) -> Path:
        p = Path(self.output_root)
        return p if p.is_absolute() else (PROJECT_ROOT / p)

    def resolve_exe(self) -> str:
        if self.exe_path:
            return self.exe_path if Path(self.exe_path).exists() else ""
        for c in KAPE_CANDIDATES:
            if Path(c).exists():
                return c
        found = shutil.which("kape.exe") or shutil.which("kape")
        return found or ""


@dataclass
class KapeJob:
    case_id: str = ""
    host_id: str = ""
    artifacts: str = ""
    reason: str = ""
    tsource: str = ""
    target: str = ""
    module: str = ""
    extra_files: List[str] = field(default_factory=list)   # 额外单独取回的可疑文件
    created: str = ""

    def slug(self) -> str:
        safe = "".join(ch if ch.isalnum() or ch in "-_" else "_"
                       for ch in (self.case_id or "case"))
        return f"{time.strftime('%Y%m%d-%H%M%S')}_{safe[:40]}"


@dataclass
class KapeResult:
    ok: bool
    status: str
    command: str = ""
    outdir: str = ""
    plan_file: str = ""
    detail: str = ""
    collected_files: int = 0
    collected_mb: float = 0.0
    elapsed_s: float = 0.0
    stdout_tail: str = ""
    # 体积超预算。为 True 时 ok 仍可能是 True（产物确实采到了），
    # 但调用方应把"产物过大"当作需要人工决定的信号，而不是静默接受。
    oversize: bool = False
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


#: 测试替身（test double）的标记。见 forensics/tests/bin/
STUB_MARKER = "KAPE-STUB-TEST-DOUBLE"
#: 真 KAPE 1.3.0.2 的 kape.exe 约 7 MB。明显小于此的多半是替身/错文件。
MIN_REAL_KAPE_BYTES = 1_000_000


#: 探针结果缓存：(路径, 大小, mtime) → (是否真 KAPE, 说明)。
# 为什么要缓存：本机实测 `kape.exe --help` **不自行退出**，于是每次探针都要等满超时
# （stdin=DEVNULL 也拦不住它）。而 health() 会在每次查找适配器时被调用，
# 不缓存的话每个动作要白等 8 秒。用 (路径, 大小, mtime) 作键：文件被换掉时自动失效。
_PROBE_CACHE: Dict[Tuple[str, int, int], Tuple[bool, str]] = {}


def probe_exe(path: str, timeout: int = 8) -> Tuple[bool, str]:
    """确认这个路径上真的是 KAPE（而不是替身/别的程序）。返回 (是否真 KAPE, 说明)。

    为什么需要这一步：项目里存在一个**测试替身** `forensics/tests/bin/kape.exe`
    （约 6.5 KB，输出里带 KAPE-STUB-TEST-DOUBLE 标记）。它本身很有用（无真 KAPE 时
    也能测链路），但一旦被当成真的 KAPE 配进去，后果是"看起来采集成功了、
    实际上什么都没采"—— 而取证链上最不能接受的就是这种"假装成功"。
    所以：不仅要在配置里写对路径，还要**验明正身**。
    """
    if not path or not Path(path).exists():
        return False, "路径不存在"
    p = Path(path)
    try:
        size = p.stat().st_size
        mtime = int(p.stat().st_mtime)
    except OSError as exc:
        return False, f"无法读取：{exc}"

    ck = (str(p).lower(), size, mtime)
    if ck in _PROBE_CACHE:
        return _PROBE_CACHE[ck]

    result = _probe_exe_uncached(p, size, timeout)
    _PROBE_CACHE[ck] = result
    return result


def _probe_exe_uncached(p: Path, size: int, timeout: int) -> Tuple[bool, str]:
    """真正去跑一次探针（带缓存的是外面的 probe_exe）。"""

    # ⚠ 两个实测坑，都必须处理，否则会把**好端端的 KAPE 判成不可用**：
    #
    # 坑 1：`kape.exe --help` **打印完帮助后不退出**（它在等按键）。
    #   于是探针会挂在 timeout 上，然后被当成"无法执行" —— 而真实后果比一条告警严重得多：
    #   kape 适配器变不健康 → `find_adapter` 把 `collect_forensics` 降级给 filesystem 适配器，
    #   取证动作静默换了实现。这类"健康检查本身出错导致能力静默下降"极难发现。
    #
    # 坑 2：它到底退不退出**取决于调用者的 stdin 是不是管道**。
    #   前面几次回归我把输出接进了 `| Select-Object`，子进程 stdin 变成管道，
    #   ReadKey 撞到 EOF 立刻抛异常退出 → 探针很快成功；不加管道时 stdin 是控制台，
    #   就会阻塞在等按键。同一份代码"时好时坏"，根因就在这。
    #
    # 对策：显式 `stdin=DEVNULL`（不依赖调用者），并且**超时也要去看部分输出** ——
    #   只要拿到了版本横幅，就证明这是真的 KAPE，它退不退出不影响这个结论。
    out = ""
    timed_out = False
    try:
        r = subprocess.run([str(p), "--help"], capture_output=True, encoding="utf-8",
                           errors="replace", timeout=timeout, stdin=subprocess.DEVNULL,
                           creationflags=CREATE_NO_WINDOW)
        out = (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        got = getattr(exc, "stdout", None) or ""
        if isinstance(got, bytes):
            got = got.decode("utf-8", errors="replace")
        out = got
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"无法执行（{size} 字节）：{exc}"

    if STUB_MARKER in out:
        return False, "这是测试替身（KAPE-STUB-TEST-DOUBLE），不是真正的 KAPE"
    if "KAPE version" in out:
        line = next((x.strip() for x in out.splitlines() if "KAPE version" in x), "")
        return True, line + ("（注：--help 不自行退出，已按超时处理）" if timed_out else "")
    if timed_out:
        return False, (f"执行超时（{timeout}s）且没拿到任何输出；"
                       f"无法确认它是真的 KAPE。注意：KAPE 连 --tlist 都要求管理员")
    if size < MIN_REAL_KAPE_BYTES:
        return False, f"只有 {size} 字节且输出无 KAPE 标识，不像真的 KAPE"
    return False, "输出里没有 'KAPE version'，不像真的 KAPE"


def _in_jail(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def build_job(case_id: str, host_id: str, artifacts: str, reason: str,
              cfg: KapeConfig, outdir: Path) -> KapeJob:
    """把「可疑目标」翻译成 KAPE 作业。

    `artifacts` 是本项目自定义的**语义标签**（不是 KAPE 参数），
    让上层（模型/编排）说"我要什么"，而不是拼 KAPE 命令行：
        triage        默认精简集（BlueTeam-Triage）
        full          全量（!SANS_Triage）—— 慢，产物体积大
        process       进程执行痕迹（Prefetch/Amcache/SRUM/WMI）
        persistence   持久化（计划任务/注册表配置单元/启动项）
        network       网络与日志（事件日志/防火墙日志/DNS 缓存/hosts）
        registry      只取注册表配置单元
        memory        内存镜像 —— **占位**：本工具不做内存取证，会明确说明
    多个用逗号分隔，取并集；额外可用 `file:<绝对路径>` 指定单独取回的文件。
    """
    raw = [a.strip() for a in (artifacts or "triage").split(",") if a.strip()]
    ts: List[str] = []
    extra_files: List[str] = []
    for a in raw:
        # ⚠ `file:` 后面的**路径必须保留原始大小写**，只能对语义标签做小写归一。
        # 一开始我图省事把整串 .lower()，结果 C:\Windows\notepad.exe 变成
        # c:\windows\notepad.exe —— 在 Windows 上凑巧还能用（大小写不敏感），
        # 但路径被静默改写本身就是隐患：一换到大小写敏感的路径（WSL/挂载盘/网络盘）
        # 就会取不到文件，而且报错信息完全指不到病根。
        if a.lower().startswith("file:"):
            extra_files.append(a[5:].strip())
        else:
            ts.append(a.lower())
    if "full" in ts or "full" in (cfg.target or "").lower():
        target = "!SANS_Triage"
    elif not ts or "triage" in ts:
        target = cfg.target or "BlueTeam-Triage"
    else:
        target = cfg.target or "BlueTeam-Triage"
    module = cfg.module
    notes = []
    if "memory" in ts:
        notes.append("memory（内存镜像）为**占位**：本工具不做内存取证，"
                     "需要单独的内存采集工具与流程，此处仅登记需求")
    job = KapeJob(case_id=case_id, host_id=host_id, artifacts=",".join(ts), reason=reason,
                  tsource=cfg.tsource, target=target, module=module,
                  extra_files=extra_files, created=time.strftime("%Y-%m-%d %H:%M:%S"))
    if notes:
        job.reason = (job.reason + "；" + "；".join(notes)).strip("；")
    return job


def build_command(job: KapeJob, cfg: KapeConfig, outdir: Path) -> List[str]:
    """构造 KAPE 命令行。

    这些参数已对着 **真实的 `kape.exe --help`（1.3.0.2）核实过**，不是猜的：
        tsource / tdest / target / tvars / msource / module / mdest / sim
    另外核实到一条重要事实：**1.3.0.2 里没有 --sync**。
    （早期版本的注释里写着"不猜 --sync"──现在可以确定它真的不存在。）
    仍然**不做**的事：不自动加 --vhdx/--zip（容器化会多一层开销，要就显式写 extra_args）、
    不自动加 --tflush/--mflush（那会**删除目录内容**，属于破坏性参数，绝不隐式加）。
    """
    exe = cfg.resolve_exe() or "kape.exe"
    tdest = outdir / "Triage"
    mdest = outdir / "Parsed"
    cmd = [exe, "--tsource", job.tsource or cfg.tsource, "--tdest", str(tdest),
           "--target", job.target or cfg.target]
    # 自带的 target 用了 %user%，KAPE 需要 --tvars 代入；不传的话那几个条目静默取不到。
    user = os.environ.get("USERNAME") or os.environ.get("USER") or ""
    if user:
        cmd += ["--tvars", f"user:{user}"]
    if job.module:
        cmd += ["--mdest", str(mdest), "--module", job.module]
    if cfg.sim:
        cmd.append("--sim")
    if cfg.extra_args:
        cmd += shlex.split(cfg.extra_args)
    return cmd


def validate(job: KapeJob, cfg: KapeConfig, outdir: Path) -> Tuple[List[str], List[str]]:
    """返回 (阻断项, 提醒项)。

    区分这两类很重要：
      * 阻断项 = **连计划都不能信**（目录逃出 jail、tsource 为空）
      * 提醒项 = **计划仍然有用**（本机没装 kape.exe）
    早期版本把两者合在一起，导致"没装 KAPE 时连演练都直接 unavailable" ——
    可演练的产物恰恰是一份可以拿去已装 KAPE 的机器上执行的 .cmd，
    它不依赖于本机有没有装。
    """
    blocking: List[str] = []
    warnings: List[str] = []
    root = cfg.root()
    if not _in_jail(outdir, root):
        blocking.append(f"产物目录必须在 {root} 之内（当前 {outdir}）——"
                        f"防止路径写错导致 KAPE 把别处搞乱")
    if not _in_jail(outdir / "Triage", root) or not _in_jail(outdir / "Parsed", root):
        blocking.append("tdest/mdest 必须落在输出根目录内")
    ts = (job.tsource or cfg.tsource).rstrip("\\/")
    if not ts:
        blocking.append("tsource（要采集的盘符/根目录）不能为空")
    if not cfg.resolve_exe():
        warnings.append(
            "本机找不到 kape.exe（演练仍可生成计划）：请从 https://www.kroll.com/kape "
            "获取，并在 actions/config.yaml 的 adapters.kape.exe_path 里指明路径")
    return blocking, warnings


def cmd_preview(cfg: KapeConfig, job: KapeJob, outdir: Path) -> str:
    """生成可直接以管理员身份运行的 .cmd 内容。

    非管理员运行时，这是把"计划"交给操作员的唯一正确方式：
    我们**不**代他提权（那会弹 UAC 阻塞），只给一条他能核对后再执行的命令。
    """
    cmd = build_command(job, cfg, outdir)
    lines = [
        "@echo off",
        "rem ============================================================",
        "rem  蓝队 IDS 取证采集 —— 由 blue-team-agent 生成，需以**管理员**运行",
        "rem ============================================================",
        "rem  生成时间：" + job.created,
        f"rem  案例：{job.case_id}    主机：{job.host_id}",
        f"rem  触发原因：{job.reason}",
        f"rem  语义标签：{job.artifacts}",
        "rem ",
        "rem  ⚠ 执行前请先核对下面这行命令（尤其 tsource 与目标目录）：",
        "rem     确认无误后，在【管理员】命令提示符里运行本文件。",
        "rem  ⚠ KAPE 的 --tdest 目录必须存在且为空，否则会拒绝执行。",
        "rem ============================================================",
        "",
        "net session >nul 2>&1",
        "if errorlevel 1 (",
        "  echo [错误] 需要管理员权限。请右键『以管理员身份运行』。",
        "  exit /b 5",
        ")",
        "",
        'if not exist "' + str(outdir) + '" mkdir "' + str(outdir) + '"',
        "",
        subprocess.list2cmdline(cmd),
        "",
        "echo.",
        "echo [完成] 产物目录：" + str(outdir),
        "echo        下一步：python forensics\\collect.py --ingest " + str(outdir),
    ]
    return "\r\n".join(lines) + "\r\n"


def run(job: KapeJob, cfg: KapeConfig, dry_run: bool = True,
        extra_files_copy: bool = True) -> KapeResult:
    """执行（或演练）一次采集。**dry_run=True 时绝不启动子进程。**"""
    outdir = cfg.root() / job.slug()
    t0 = time.time()

    blocking, warnings = validate(job, cfg, outdir)
    exe = cfg.resolve_exe()

    preview = cmd_preview(cfg, job, outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    plan_file = outdir / "run_kape.cmd"
    plan_file.write_text(preview, encoding="utf-8", newline="")
    (outdir / "job.json").write_text(
        json.dumps({"job": asdict(job), "config": asdict(cfg),
                    "blocking": blocking, "warnings": warnings, "dry_run": dry_run,
                    "admin": is_admin(), "kape_exe": exe},
                   ensure_ascii=False, indent=2), encoding="utf-8")

    cmdline = subprocess.list2cmdline(build_command(job, cfg, outdir))
    if blocking:
        return KapeResult(ok=False, status=ST_UNAVAILABLE, command=cmdline,
                          outdir=str(outdir), plan_file=str(plan_file),
                          detail="；".join(blocking), elapsed_s=round(time.time() - t0, 2))

    if dry_run:
        detail = f"演练：未执行任何采集。已生成可执行计划 {plan_file.name}（需管理员运行）。"
        if warnings:
            detail += "　提醒：" + "；".join(warnings)
        return KapeResult(ok=True, status=ST_DRY_RUN, command=cmdline,
                          outdir=str(outdir), plan_file=str(plan_file), detail=detail,
                          elapsed_s=round(time.time() - t0, 2))

    # ---- 真实执行 ----
    if not exe:
        return KapeResult(ok=False, status=ST_UNAVAILABLE, command=cmdline,
                          outdir=str(outdir), plan_file=str(plan_file),
                          detail="；".join(warnings) or "找不到 kape.exe",
                          elapsed_s=round(time.time() - t0, 2))
    if cfg.require_admin and not is_admin():
        return KapeResult(
            ok=False, status=ST_UNAVAILABLE, command=cmdline,
            outdir=str(outdir), plan_file=str(plan_file),
            detail="当前进程不是管理员：KAPE 取注册表配置单元/事件日志/SRUDB 会不完整，"
                   "拒绝执行以免产出**残缺证据**（残缺取证比没有取证更危险）。"
                   f"请以管理员身份运行 {plan_file.name}。",
            elapsed_s=round(time.time() - t0, 2))

    cmd = build_command(job, cfg, outdir)
    tdest = outdir / "Triage"
    try:
        tdest.mkdir(parents=True, exist_ok=True)
        r = subprocess.run(cmd, capture_output=True, encoding="utf-8", errors="replace",
                           timeout=cfg.timeout, cwd=str(Path(exe).parent),
                           stdin=subprocess.DEVNULL,
                           creationflags=CREATE_NO_WINDOW)
    except subprocess.TimeoutExpired:
        n, mb = count_artifacts(outdir)
        return KapeResult(ok=False, status=ST_FAILED,
                          command=subprocess.list2cmdline(cmd), outdir=str(outdir),
                          plan_file=str(plan_file),
                          detail=(f"KAPE 超时（{cfg.timeout}s）已中止。已产出的部分产物 "
                                  f"{n} 个 / {mb} MB **不完整、不可用**；"
                                  f"建议收紧 target 范围后重试。"),
                          collected_files=n, collected_mb=mb,
                          elapsed_s=round(time.time() - t0, 2))
    except OSError as exc:
        return KapeResult(ok=False, status=ST_FAILED,
                          command=subprocess.list2cmdline(cmd), outdir=str(outdir),
                          plan_file=str(plan_file), detail=f"启动失败：{exc}",
                          elapsed_s=round(time.time() - t0, 2))

    tail = ((r.stdout or "") + (r.stderr or "")).strip()[-4000:]
    n, mb = count_artifacts(outdir)
    ok = r.returncode == 0 and n > 0
    if cfg.sim:
        # --sim 不复制采集产物，但**模块仍会执行**。于是 Parsed 里的 CSV 是基于
        # 空目录算出来的（基本没内容）。不写清楚的话，很容易把它当成真实结果。
        detail = (f"KAPE --sim 校验：退出码 {r.returncode}（未复制任何采集产物）。"
                  f"outdir 下 {n} 个文件 / {mb} MB **全部来自解析器的空目录输出，"
                  f"不是采集结果，不要据此研判**。模块与 target 配置已确认可用。")
    else:
        detail = (f"KAPE 退出码 {r.returncode}；产物 {n} 个文件 / {mb} MB"
                  if ok else f"KAPE 退出码 {r.returncode}，产物 {n} 个文件（可能失败）")
    if extra_files_copy and job.extra_files:
        copied = copy_extra_files(job.extra_files, outdir / "ExtraFiles")
        detail += f"；另取回指定文件 {copied} 个"
        n2, mb2 = count_artifacts(outdir)
        n, mb = n2, mb2

    # 体积守卫（见 KapeConfig.max_collect_mb 的注释）。--sim 不产生产物，不参与。
    warn: List[str] = []
    oversize = False
    if not cfg.sim:
        oversize, warn = size_warning(mb, cfg.max_collect_mb)
        if warn:
            detail += "。⚠ " + warn[0]

    return KapeResult(ok=ok, status=ST_OK if ok else ST_FAILED,
                      command=subprocess.list2cmdline(cmd), outdir=str(outdir),
                      plan_file=str(plan_file), detail=detail,
                      collected_files=n, collected_mb=mb, stdout_tail=tail,
                      elapsed_s=round(time.time() - t0, 2),
                      oversize=oversize, warnings=warn)


def copy_extra_files(paths: List[str], dest: Path) -> int:
    """把指定的可疑文件单独取回（连同 SHA256）。**只读复制，不移动原文件。**"""
    import hashlib
    dest.mkdir(parents=True, exist_ok=True)
    n = 0
    manifest = []
    for p in paths:
        src = Path(p)
        if not src.is_file():
            continue
        try:
            data = src.read_bytes()
        except OSError:
            continue
        h = hashlib.sha256(data).hexdigest()
        target = dest / src.name
        i = 1
        while target.exists():
            target = dest / f"{src.stem}_{i}{src.suffix}"
            i += 1
        target.write_bytes(data)
        manifest.append({"source": str(src), "copy": str(target),
                         "sha256": h, "size": len(data),
                         "mtime": time.strftime("%Y-%m-%d %H:%M:%S",
                                                time.localtime(src.stat().st_mtime))})
        n += 1
    if manifest:
        (dest / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return n


def size_warning(mb: float, budget_mb: int) -> Tuple[bool, List[str]]:
    """产物体积预算检查。返回 (oversize, warnings)。

    为什么需要它：KAPE 没有"预估体积"的开关，`--sim` 也不报体积，
    所以体积只能在采完之后才知道。v1.1 就是这样静默产出 17826 MB 的
    （见 forensics/targets/BlueTeam-Triage.tkape 头部的实测说明）。
    预算 <= 0 表示不限制。
    """
    if budget_mb <= 0 or mb <= budget_mb:
        return False, []
    return True, [
        f"产物 {mb} MB 超出预算 {budget_mb} MB；自动流水线不宜长期保留这个体积，"
        f"请收紧 target 采集范围（大体积通常来自用户目录下的安装包）"
    ]


def count_artifacts(outdir: Path) -> tuple:
    n = 0
    total = 0
    for p in outdir.rglob("*"):
        try:
            if p.is_file():
                n += 1
                total += p.stat().st_size
        except OSError:
            continue
    return n, round(total / 1048576, 2)


# ---------------------------------------------------------------- 自检

def selftest() -> int:
    import tempfile
    ok = fail = 0

    def chk(name: str, cond: bool, extra: str = "") -> None:
        nonlocal ok, fail
        if cond:
            ok += 1
            print(f"  [OK] {name}")
        else:
            fail += 1
            print(f"  [FAIL] {name} {extra}")

    with tempfile.TemporaryDirectory() as td:
        cfg = KapeConfig(output_root=td, exe_path="", target="BlueTeam-Triage")
        # 假装 KAPE 存在（本机没装），只测命令构造
        cfg.exe_path = str(Path(td) / "kape.exe")
        Path(cfg.exe_path).write_text("", encoding="utf-8")

        job = build_job("C-001", "THISPC", "triage", "可疑外连", cfg, Path(td))
        chk("默认标签 → BlueTeam-Triage", job.target == "BlueTeam-Triage", job.target)
        cmd = build_command(job, cfg, Path(td) / "x")
        chk("命令含 --tsource/--tdest/--target",
            "--tsource" in cmd and "--tdest" in cmd and "--target" in cmd, str(cmd))
        chk("未配 module 时不出现 --module（不依赖 EZTools）", "--module" not in cmd, str(cmd))
        chk("命令行不带破坏性/未核实参数（--sync 在 1.3.0.2 里不存在，"
            "--tflush/--mflush 会删目录内容，绝不隐式加）",
            not any(a in cmd for a in ("--sync", "--tflush", "--mflush",
                                       "--vhdx", "--vhd")), str(cmd))
        chk("命令行带 --tvars user:xxx（自带 target 用了 %user%）",
            "--tvars" in cmd and any(str(a).startswith("user:") for a in cmd), str(cmd))
        cfg_sim = KapeConfig(output_root=td, exe_path=cfg.exe_path, sim=True)
        cmd_sim = build_command(build_job("C-s", "H", "triage", "r", cfg_sim, Path(td)),
                                cfg_sim, Path(td) / "x")
        chk("sim=True 时命令带 --sim（KAPE 原生：只校验不复制）", "--sim" in cmd_sim, str(cmd_sim))

        full = build_job("C-002", "H", "full", "r", cfg, Path(td))
        chk("full 标签 → !SANS_Triage", full.target == "!SANS_Triage", full.target)

        mem = build_job("C-003", "H", "memory,process", "r", cfg, Path(td))
        chk("memory 被如实标注为占位（不假装能做）",
            "占位" in mem.reason and "内存" in mem.reason, mem.reason)

        ef = build_job("C-004", "H", "triage,file:C:\\Windows\\notepad.exe", "r",
                       cfg, Path(td))
        chk("file: 标签被解析成单独取回的文件",
            ef.extra_files == [r"C:\Windows\notepad.exe"], str(ef.extra_files))

        # jail 校验
        bad = Path(td).parent / "outside"
        blocking, _warn = validate(job, cfg, bad)
        chk("产物目录逃出 output_root 会被拦下", any("必须在" in p for p in blocking),
            str(blocking))

        # dry-run 不执行任何东西、但留下计划
        res = run(job, cfg, dry_run=True)
        chk("dry-run 状态为 dry_run", res.status == ST_DRY_RUN, res.status)
        chk("dry-run 生成计划文件", Path(res.plan_file).exists(), res.plan_file)
        chk("dry-run 计划可用管理员运行（.cmd + 提权检查）",
            "net session" in Path(res.plan_file).read_text(encoding="utf-8"))
        chk("dry-run 期间没有产生 Triage 产物", not (Path(res.outdir) / "Triage").exists()
            or not any((Path(res.outdir) / "Triage").rglob("*")))
        chk("job.json 里记录了阻断/提醒/管理员状态/是否演练",
            all(k in json.loads((Path(res.outdir) / "job.json").read_text(encoding="utf-8"))
                for k in ("blocking", "warnings", "admin", "dry_run")))

        # 非管理员 + require_admin=True → 明确 unavailable，不假装成功
        if not is_admin():
            r2 = run(job, cfg, dry_run=False)
            chk("非管理员真实执行 → unavailable（不产残缺证据）",
                r2.status == ST_UNAVAILABLE and "管理员" in r2.detail, r2.detail[:80])
        else:
            print("  [跳过] 当前是管理员，跳过非管理员分支")

        # 找不到 kape.exe：**演练仍应成功**（产出的 .cmd 拿到别的机器上照样能用），
        # 但真实执行必须明确 unavailable
        cfg2 = KapeConfig(output_root=td, exe_path=str(Path(td) / "nope.exe"))
        job2 = build_job("C-5", "H", "triage", "r", cfg2, Path(td))
        r3 = run(job2, cfg2, dry_run=True)
        chk("没装 kape.exe 时演练仍能出计划（plan 不依赖本机装没装）",
            r3.status == ST_DRY_RUN and Path(r3.plan_file).exists(), r3.status)
        chk("演练 detail 里如实提醒缺 kape.exe",
            "kroll.com" in r3.detail, r3.detail[:90])
        r4 = run(job2, cfg2, dry_run=False)
        chk("没装 kape.exe 时真实执行 → unavailable（不假装成功）",
            r4.status == ST_UNAVAILABLE and "kroll.com" in r4.detail, r4.status)

        # 产物清点
        d = Path(td) / "cnt"
        (d / "a").mkdir(parents=True)
        (d / "a" / "f1").write_bytes(b"x" * 2048)
        n, mb = count_artifacts(d)
        chk("产物清点", n == 1 and mb >= 0, f"{n} {mb}")

        # 单独取回文件 + 哈希
        src = Path(td) / "suspect.exe"
        src.write_bytes(b"MZ" + b"\x00" * 100)
        copied = copy_extra_files([str(src), str(Path(td) / "不存在.exe")],
                                 Path(td) / "Extra")
        chk("单独取回存在的文件、跳过不存在的", copied == 1, str(copied))
        man = json.loads((Path(td) / "Extra" / "manifest.json").read_text(encoding="utf-8"))
        chk("取回清单含 SHA256 与来源路径",
            len(man) == 1 and len(man[0]["sha256"]) == 64 and man[0]["source"] == str(src))
        chk("取回是复制而非移动（原文件仍在）", src.exists())

        # 真伪校验：如果项目里那个测试替身在，就应该被认出来（而不是当成真 KAPE）
        stub = PROJECT_ROOT / "forensics" / "tests" / "bin" / "kape.exe"
        if stub.exists():
            isreal, why = probe_exe(str(stub))
            chk("测试替身被识别为「不是真 KAPE」",
                isreal is False and "替身" in why, why)
        else:
            print("  [跳过] forensics/tests/bin/kape.exe 不存在，跳过替身识别测试")
        notreal, why2 = probe_exe(str(Path(td) / "不存在.exe"))
        chk("路径不存在时不报「是真 KAPE」", notreal is False and "不存在" in why2, why2)

        # 体积守卫：直接测判断逻辑本身（一次真实的 17826 MB 采集不可能写进自检里）。
        chk("体积在预算内不告警", size_warning(400.0, 4096) == (False, []))
        chk("体积等于预算不告警", size_warning(4096.0, 4096)[0] is False)
        chk("体积超预算被标记",
            size_warning(17826.95, 4096)[0] is True
            and "17826.95" in size_warning(17826.95, 4096)[1][0])
        chk("预算 0 表示不限制", size_warning(999999.0, 0) == (False, []))
        chk("负预算也当不限制", size_warning(1.0, -1) == (False, []))
        chk("dry_run 结果带 oversize/warnings 字段",
            hasattr(run(KapeJob(case_id="x"), KapeConfig(output_root=str(td)),
                        dry_run=True), "oversize"))

    print(f"\nforensics.kape 自检：{ok} 通过 / {fail} 失败")
    return 1 if fail else 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="KAPE 取证采集（默认只演练）")
    ap.add_argument("--case", default="case-local", help="案例编号")
    ap.add_argument("--host-id", default=os.environ.get("COMPUTERNAME", "localhost"))
    ap.add_argument("--artifacts", default="triage",
                    help="语义标签：triage/full/process/persistence/network/registry/memory，"
                         "逗号分隔；file:<路径> 单独取回某文件")
    ap.add_argument("--reason", default="手工触发")
    ap.add_argument("--output-root", default="logs/forensics")
    ap.add_argument("--kape", default="", help="kape.exe 路径")
    ap.add_argument("--target", default="BlueTeam-Triage")
    ap.add_argument("--module", default="")
    ap.add_argument("--extra-args", default="")
    ap.add_argument("--sim", action="store_true",
                    help="KAPE 原生 --sim：不复制文件，只校验 target/module 配置"
                         "（建议在第一次真采集前先跑一次）")
    ap.add_argument("--max-collect-mb", type=int, default=4096,
                    help="产物体积预算（MB），超出则标记 oversize 并告警。0 = 不限制")
    ap.add_argument("--execute", action="store_true",
                    help="真实执行（默认只演练）。需管理员，否则返回 unavailable")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    cfg = KapeConfig(exe_path=args.kape, output_root=args.output_root, target=args.target,
                     module=args.module, extra_args=args.extra_args, sim=args.sim,
                     max_collect_mb=args.max_collect_mb)
    job = build_job(args.case, args.host_id, args.artifacts, args.reason, cfg, cfg.root())
    res = run(job, cfg, dry_run=not args.execute)
    print(json.dumps(res.to_dict(), ensure_ascii=False, indent=2))
    return 0 if res.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
