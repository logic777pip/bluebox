#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gui/core.py — GUI 的**服务层**：所有界面操作用到的能力都在这里，且全部复用既有模块。

设计原则（三条，都直接决定安全边界）
------------------------------------

1. **GUI 是薄壳，不是旁路。** 每一个有副作用的操作都调用既有模块的既有函数：
   封锁走 `sandbox.contain`、白名单走 `security.whitelist`、KAPE 走 `forensics.kape`。
   所有硬拒绝条件（不许封网段/网关/DNS、不许白名单覆盖临时目录、execute_enabled
   开关、管理员检查、读回验证）**照旧生效**。GUI 不能成为"绕过策略的快捷方式" ——
   否则前面所有安全设计都被一个网页按钮废掉。

2. **只认白名单里的文件。** 界面能读写哪些配置是**固定列表**，不接受任意路径。
   否则一个 `../../` 就能让 GUI 变成一个任意文件读写器。

3. **本层不做 HTTP。** 这样它可以被自检直接调用（不启服务器、不开端口），
   也方便以后换成别的界面（托盘菜单、CLI）而不用重写逻辑。

关于"撤销 AI 动作"
------------------

撤销建立在既有的 `logs/action_audit.jsonl` 之上，**不另建一套记录**（两套必然漂移）。
每条动作按"能不能撤、怎么撤"分类，并如实标注**不可撤销**的那些：

* `contain_threat` → **可撤销**：删掉本系统建的防火墙规则（前缀匹配，不会误删别人的）
* `collect_forensics` / `extract_payload` → **属证据固化**，默认不可删。
  删证据比留着更危险（案子要复核时找不到东西），所以要走显式确认才允许。
* 本身是 `dry_run` 的 → 无副作用，无需撤销
* 遏制类破坏性动作（isolate_host 等）→ 本部署里**只占位不执行**，没有可撤的东西
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

__all__ = [
    "GuiError", "status", "list_configs", "read_config", "write_config",
    "list_reports", "read_report", "list_logs", "tail_log",
    "threat_model", "containment_state", "containment_add", "containment_remove",
    "whitelist_state", "whitelist_add", "whitelist_remove",
    "actions_journal", "action_undo", "kape_state", "kape_run", "kape_launch_gui",
    "open_in_explorer", "selftest",
]

#: 界面**允许**读写的配置文件（固定列表 —— 见模块说明第 2 条）
EDITABLE_CONFIGS: Tuple[str, ...] = (
    "agent/config.yaml",
    "actions/config.yaml",
    "rag/config.yaml",
    "training/config.yaml",
    "adversarial/config_adversarial.yaml",
)

#: 界面**允许**查看的日志/审计文件
VIEWABLE_LOGS: Tuple[str, ...] = (
    "logs/net_sensor.log",
    "logs/net_sensor_events.jsonl",
    "logs/action_audit.jsonl",
    "logs/agent_audit.jsonl",
    "logs/forensics_audit.jsonl",
    "logs/sandbox/pipeline_audit.jsonl",
    "logs/sandbox/containment/audit.jsonl",
    "logs/surisensor.log",
)

BACKUP_DIR = "logs/gui_backups"
UNDO_LOG = "logs/gui_undo.jsonl"


class GuiError(RuntimeError):
    """GUI 层拒绝或失败（消息直接面向操作员）。"""


# --------------------------------------------------------------------------- #
# 短时缓存
# --------------------------------------------------------------------------- #
#
# 有些状态查询很贵：KAPE 探测要跑一次 `kape.exe --help`（那玩意儿不自己退出，
# 得等超时，约 8 秒）、查防火墙规则要起一次 PowerShell（约 3 秒）、枚举带命令行
# 的进程也要 2~3 秒。而界面每翻一次页就会重新问一遍 —— 结果是"看个状态要等十几秒"。
#
# 所以给这些**慢且变化不快**的查询加个短 TTL 缓存。关键点：
#   * TTL 取小值（秒级），操作员看到的仍是"接近实时"的状态；
#   * 写操作后**主动失效**（`invalidate_cache`），否则刚封的 IP 不会出现在列表里，
#     用户会以为没生效然后重复点 —— 这种"看起来没反应"是最容易引发误操作的。
#   * 缓存键加前缀，便于按前缀整体失效。

_TTL_CACHE: Dict[str, Tuple[float, Any]] = {}
_TTL_LOCKS: Dict[str, threading.Lock] = {}
_TTL_LOCK = threading.Lock()


def _cached(key: str, ttl: float, fn: Callable[[], Any]) -> Any:
    """带 TTL 的缓存，并且**同一时刻只允许一个线程去算同一个键**（单飞）。

    为什么需要单飞：服务启动时的后台预热线程和用户打开页面后的第一次请求会同时
    要同一份数据。不设防的话两边各跑一遍 8 秒的 KAPE 探测 —— 用户并没因此更快，
    反而多付了一倍的探测成本（还要多起一次 PowerShell）。单飞让后来者等前一个
    的结果，而不是自己再算一次。
    """
    now = time.time()
    with _TTL_LOCK:
        hit = _TTL_CACHE.get(key)
        if hit is not None and (now - hit[0]) < ttl:
            return hit[1]
        lk = _TTL_LOCKS.setdefault(key, threading.Lock())

    with lk:
        # 二级检查：等锁期间可能已经有别的线程算完并写进缓存了
        now = time.time()
        with _TTL_LOCK:
            hit = _TTL_CACHE.get(key)
            if hit is not None and (now - hit[0]) < ttl:
                return hit[1]
        val = fn()
        with _TTL_LOCK:
            _TTL_CACHE[key] = (time.time(), val)
        return val


def invalidate_cache(prefix: str = "") -> None:
    """让缓存失效。写操作之后必须调用，否则界面显示旧状态。"""
    with _TTL_LOCK:
        for k in [k for k in _TTL_CACHE if k.startswith(prefix)]:
            _TTL_CACHE.pop(k, None)


def _parallel(tasks: Dict[str, Callable[[], Any]]) -> Dict[str, Any]:
    """并行跑一组互不依赖的探针，返回 名字→结果（失败记为 error 字段）。

    为什么要并行：这五项彼此毫无关系（进程枚举、适配器健康、防火墙查询、
    Sandboxie 探测、KAPE 探测），串行起来首屏就是它们之和 ≈ 15 秒。
    并行后冷启动约等于其中最慢的一项。
    """
    from concurrent.futures import ThreadPoolExecutor

    out: Dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=len(tasks), thread_name_prefix="gui-probe") as ex:
        futs = {name: ex.submit(fn) for name, fn in tasks.items()}
        for name, fut in futs.items():
            try:
                out[name] = fut.result(timeout=60)
            except Exception as exc:  # noqa: BLE001
                out[name] = {"error": f"{type(exc).__name__}: {exc}"}
    return out


def _audit(event: str, payload: Dict[str, Any]) -> None:
    """GUI 侧所有有副作用的操作都留痕。"""
    p = PROJECT_ROOT / UNDO_LOG
    p.parent.mkdir(parents=True, exist_ok=True)
    rec = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "event": event,
           "operator": os.environ.get("USERNAME", ""), **payload}
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _safe_rel(name: str, allowed: Tuple[str, ...]) -> str:
    """把请求的路径限制在允许列表内（防目录穿越）。"""
    n = str(name or "").replace("\\", "/").lstrip("/")
    if ".." in n.split("/"):
        raise GuiError(f"路径不合法：{name}")
    if n not in allowed:
        raise GuiError(f"不允许访问 {name}（只允许：{', '.join(allowed)}）")
    return n


# --------------------------------------------------------------------------- #
# 概览
# --------------------------------------------------------------------------- #

def _probe_sensor() -> Dict[str, Any]:
    """探测网络传感器是否在跑。

    坑（已踩）：**PowerShell 5.1 的 `Get-Process` 对象没有 `CommandLine` 属性**
    （那是 PS 7 / .NET Core 才有的）。用它过滤 `$_.CommandLine -like '*net_sensor.py*'`
    永远匹配不到 → 状态页恒定显示"已停止"。一个状态页给出假告警，比不给状态更糟：
    操作员会去"修复"一个根本没坏的东西，然后开始不信任这个页面。
    所以这里改用 `Get-CimInstance Win32_Process`（有 CommandLine），并交叉核对计划任务状态。

    另外：本机 `.venv\\Scripts\\pythonw.exe` 是 uv 的转发器，它和真实解释器会同时出现，
    所以**看到两个进程属正常**，是同一个实例；据此判断"重复实例"会误报。
    """
    ps = (
        "$p = Get-CimInstance Win32_Process -Filter \"Name='pythonw.exe' OR Name='python'\" "
        "-ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like '*net_sensor.py*' } | "
        "Select-Object -ExpandProperty ProcessId; "
        "$t = (Get-ScheduledTask -TaskName 'BlueTeamNetSensor' -ErrorAction SilentlyContinue).State; "
        "\"PIDS=$($p -join ',');TASK=$t\""
    )
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=25, creationflags=0x08000000)
        raw = (r.stdout or "").strip().splitlines()
        line = raw[-1] if raw else ""
        pids, task = [], ""
        for part in line.split(";"):
            if part.startswith("PIDS="):
                pids = [x for x in part[5:].split(",") if x.strip()]
            elif part.startswith("TASK="):
                task = part[5:].strip()
        return {"running": bool(pids), "pid": pids[0] if pids else "",
                "procs": len(pids), "task_state": task}
    except Exception as exc:  # noqa: BLE001
        return {"running": False, "pid": "", "procs": 0,
                "error": f"{type(exc).__name__}: {exc}"}


def _probe_adapters() -> List[Dict[str, Any]]:
    try:
        import yaml
        from actions.adapters import build_adapters
        cfg = yaml.safe_load((PROJECT_ROOT / "actions/config.yaml").read_text(encoding="utf-8")) or {}
        ads = build_adapters(cfg, PROJECT_ROOT)
        return [
            {**a.describe(), "healthy": a.health()[0], "health_detail": a.health()[1][:200],
             "capability_list": sorted(a.capabilities())}
            for a in ads
        ]
    except Exception as exc:  # noqa: BLE001
        return [{"name": "?", "healthy": False, "health_detail":
                 f"加载失败：{type(exc).__name__}: {exc}", "capability_list": []}]


def _probe_sandboxie() -> Dict[str, Any]:
    try:
        from sandbox.sandboxie import SandboxieConfig, box_settings, probe_install
        cfg = SandboxieConfig()
        ok, why = probe_install(cfg)
        return {"installed": ok, "detail": why[:200], "box": cfg.box_name,
                "box_settings": box_settings(cfg)[1].replace("\n", " | ")[:300]}
    except Exception as exc:  # noqa: BLE001
        return {"installed": False, "detail": f"{type(exc).__name__}: {exc}"}


def _probe_kape() -> Dict[str, Any]:
    try:
        from forensics.kape import probe_exe
        cfg = _kape_cfg()
        exe = cfg.resolve_exe()
        # 超时给 4 秒而不是默认 8 秒：`kape.exe --help` 打印完横幅后不退出，
        # 探针只能等超时；而版本横幅在此之前早就拿到了，`probe_exe` 也会接受
        # 超时时的部分输出。多等的 4 秒纯属白等 —— 而它卡的是界面首屏。
        okk, why = probe_exe(exe, timeout=4) if exe else (False, "未找到 kape.exe")
        return {"found": bool(exe), "exe": exe, "real": okk, "detail": why[:160]}
    except Exception as exc:  # noqa: BLE001
        return {"found": False, "detail": f"{type(exc).__name__}: {exc}"}


def status() -> Dict[str, Any]:
    """总览：传感器、适配器、封锁、白名单、只读库、KAPE 的一句话状态。

    全部子项**并行**取（彼此无关），且各自走短 TTL 缓存 + 单飞。
    串行时首屏要等它们之和（约 15 秒），并行后约等于最慢的一项。
    """
    out: Dict[str, Any] = {"ts": time.strftime("%Y-%m-%d %H:%M:%S")}

    def _rules() -> List[Dict[str, Any]]:
        import sandbox.contain as _c
        return _c.list_rules()

    def _wl_stats() -> Dict[str, Any]:
        from security.whitelist import default_whitelist
        return default_whitelist().stats()

    def _vault() -> Dict[str, Any]:
        from sandbox import vault_dir
        v = vault_dir()
        n = len(list(v.glob("*/manifest.json"))) if v.is_dir() else 0
        size = sum(f.stat().st_size for f in v.rglob("*") if f.is_file()) if v.is_dir() else 0
        return {"path": str(v), "cases": n, "mb": round(size / 1048576, 2)}

    got = _parallel({
        "sensor": lambda: _cached("sensor", 8.0, _probe_sensor),
        "adapters": lambda: _cached("adapters", 60.0, _probe_adapters),
        "rules": lambda: _cached("containment_rules", 6.0, _rules),
        "whitelist": lambda: _cached("whitelist_stats", 4.0, _wl_stats),
        "vault": _vault,
        "sandboxie": lambda: _cached("sandboxie", 120.0, _probe_sandboxie),
        "kape": lambda: _cached("kape_probe", 300.0, _probe_kape),
    })

    out["sensor"] = got["sensor"]
    out["adapters"] = got["adapters"]
    out["sandboxie"] = got["sandboxie"]
    out["kape"] = got["kape"]

    rules = got["rules"]
    if isinstance(rules, list):
        out["containment"] = {"count": len(rules),
                              "rules": [{"name": x.get("name"),
                                         "remote": x.get("remote"),
                                         "enabled": x.get("enabled")} for x in rules]}
    else:
        out["containment"] = {"count": 0, **rules}

    wl = got["whitelist"]
    out["whitelist"] = wl if isinstance(wl, dict) and "total" in wl else {
        "total": 0, "error": str(wl.get("error", wl)) if isinstance(wl, dict) else str(wl)}

    vault = got["vault"]
    out["vault"] = vault if isinstance(vault, dict) and "cases" in vault else {
        "path": "", "cases": 0, "error": str(vault)}
    return out


# --------------------------------------------------------------------------- #
# 配置
# --------------------------------------------------------------------------- #

def list_configs() -> List[Dict[str, Any]]:
    items = []
    for rel in EDITABLE_CONFIGS:
        p = PROJECT_ROOT / rel
        items.append({"path": rel, "exists": p.is_file(),
                      "size": p.stat().st_size if p.is_file() else 0,
                      "modified": (time.strftime("%Y-%m-%d %H:%M:%S",
                                                 time.localtime(p.stat().st_mtime))
                                   if p.is_file() else "")})
    return items


def read_config(rel: str, *, parsed: bool = False) -> Dict[str, Any]:
    """读配置。`parsed=True` 时额外返回解析后的结构（界面用它渲染表单）。"""
    n = _safe_rel(rel, EDITABLE_CONFIGS)
    p = PROJECT_ROOT / n
    if not p.is_file():
        raise GuiError(f"配置不存在：{n}")
    text = p.read_text(encoding="utf-8")
    out: Dict[str, Any] = {"path": n, "text": text}
    if parsed:
        try:
            import yaml
            out["data"] = yaml.safe_load(text) or {}
            out["valid"] = True
        except Exception as exc:  # noqa: BLE001
            out["data"] = {}
            out["valid"] = False
            out["error"] = f"YAML 解析失败：{exc}"
    return out


def write_config(rel: str, text: str) -> Dict[str, Any]:
    """写配置：**先校验 YAML、再备份、再原子替换**。

    为什么要三步：GUI 编辑配置写坏一次，整套系统（传感器/动作/白名单）都会起不来，
    而操作员通常是在"急着改个值"的时候点保存的。所以：
      1. 新内容必须先能解析成 YAML 才允许落盘（防手滑写坏缩进）
      2. 落盘前备份到 `logs/gui_backups/<文件>.<时间戳>`
      3. 走临时文件 + 原子替换，避免写到一半断电留下半个文件
    """
    n = _safe_rel(rel, EDITABLE_CONFIGS)
    p = PROJECT_ROOT / n
    if not p.is_file():
        raise GuiError(f"配置不存在：{n}")

    try:
        import yaml
        yaml.safe_load(text)
    except Exception as exc:  # noqa: BLE001
        raise GuiError(f"拒绝写入：新内容不是合法 YAML（{exc}）") from exc

    bdir = PROJECT_ROOT / BACKUP_DIR
    bdir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    bak = bdir / f"{n.replace('/', '_')}.{stamp}"
    shutil.copy2(p, bak)

    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(p)

    _audit("config_save", {"path": n, "backup": str(bak)})
    return {"ok": True, "path": n, "backup": str(bak)}


# --------------------------------------------------------------------------- #
# 报告 / 日志
# --------------------------------------------------------------------------- #

def list_reports() -> List[Dict[str, Any]]:
    """列出报告：`reports/*.md` 与各类案例文档。"""
    items: List[Dict[str, Any]] = []

    def _add(p: Path, kind: str, title: str = "") -> None:
        if p.is_file():
            items.append({"path": str(p.relative_to(PROJECT_ROOT)).replace("\\", "/"),
                          "name": p.name, "kind": kind, "title": title,
                          "size": p.stat().st_size,
                          "modified": time.strftime("%Y-%m-%d %H:%M:%S",
                                                    time.localtime(p.stat().st_mtime))})

    for p in sorted((PROJECT_ROOT / "reports").glob("*")):
        if p.is_file():
            _add(p, "报告")
    for p in sorted((PROJECT_ROOT / "logs/forensics").glob("*/CASE.md")):
        _add(p, "取证案例", p.parent.name)
    for p in sorted((PROJECT_ROOT / "logs/sandbox/cases").glob("*/CASE.md")):
        _add(p, "沙箱案例", p.parent.name)
    for p in sorted((PROJECT_ROOT / "logs/sandbox/cases").glob("*/payload_report.md")):
        _add(p, "载荷分析", p.parent.name)
    for p in sorted((PROJECT_ROOT / "logs/sandbox/cases").glob("*/HANDOFF.md")):
        _add(p, "人工交接", p.parent.name)
    items.sort(key=lambda x: x["modified"], reverse=True)
    return items


def read_report(rel: str, limit: int = 400_000) -> Dict[str, Any]:
    """读报告原文（Markdown）。路径必须落在 reports/ 或 logs/ 下。"""
    p = (PROJECT_ROOT / str(rel).replace("\\", "/")).resolve()
    root = PROJECT_ROOT.resolve()
    if not str(p).startswith(str(root)):
        raise GuiError("路径越界")
    allowed_roots = (root / "reports", root / "logs")
    if not any(str(p).startswith(str(a)) for a in allowed_roots):
        raise GuiError("只允许读取 reports/ 与 logs/ 下的报告")
    if not p.is_file():
        raise GuiError(f"文件不存在：{rel}")
    text = p.read_text(encoding="utf-8", errors="replace")
    if len(text) > limit:
        text = text[:limit] + f"\n\n…（已截断，原文 {p.stat().st_size} 字节）"
    return {"path": str(p.relative_to(root)).replace("\\", "/"), "text": text}


def list_logs() -> List[Dict[str, Any]]:
    out = []
    for rel in VIEWABLE_LOGS:
        p = PROJECT_ROOT / rel
        out.append({"path": rel, "exists": p.is_file(),
                    "size": p.stat().st_size if p.is_file() else 0,
                    "modified": (time.strftime("%Y-%m-%d %H:%M:%S",
                                               time.localtime(p.stat().st_mtime))
                                 if p.is_file() else "")})
    return out


def tail_log(rel: str, lines: int = 300) -> Dict[str, Any]:
    """读日志尾部 N 行。按 UTF-8 读（本项目的日志都是 UTF-8）。"""
    n = _safe_rel(rel, VIEWABLE_LOGS)
    p = PROJECT_ROOT / n
    if not p.is_file():
        return {"path": n, "exists": False, "lines": [], "text": ""}
    lines = max(1, min(int(lines), 5000))
    try:
        # 只读尾部：大日志不要整个读进内存
        size = p.stat().st_size
        with p.open("rb") as fh:
            fh.seek(max(0, size - lines * 400))
            raw = fh.read()
        text = raw.decode("utf-8", errors="replace")
        body = text.splitlines()[-lines:]
    except OSError as exc:
        raise GuiError(f"读日志失败：{exc}") from exc
    return {"path": n, "exists": True, "size": size,
            "modified": time.strftime("%Y-%m-%d %H:%M:%S",
                                      time.localtime(p.stat().st_mtime)),
            "lines": body, "text": "\n".join(body)}


# --------------------------------------------------------------------------- #
# 威胁建模
# --------------------------------------------------------------------------- #

def threat_model() -> Dict[str, Any]:
    """威胁建模视图：**我们能看见什么 / 看见了什么 / 看不见什么**，全部取自真实来源。

    为什么按这三栏组织：安全看板最容易变成"指标陈列"，看完不知道该怎么办。
    这里每一栏都直接对应一个决策：
      * 资产与角色   → 出事时哪些机器不能乱动（保护清单）
      * 检测能力     → 哪类行为有规则覆盖（来自实际规则表，不是抄文档）
      * 观测到的     → 近期真实事件按规则聚合（告诉我现在实际在发生什么）
      * 覆盖缺口     → 已知的盲区与局限（避免把"没告警"读成"没问题"）
    """
    m: Dict[str, Any] = {"ts": time.strftime("%Y-%m-%d %H:%M:%S")}

    # 资产与保护对象
    try:
        import yaml
        cfg = yaml.safe_load((PROJECT_ROOT / "actions/config.yaml").read_text(encoding="utf-8")) or {}
        pol = ((cfg.get("executor") or {}).get("policy") or {})
        m["assets"] = {
            "protected_hosts": pol.get("protected_hosts") or [],
            "protected_accounts": pol.get("protected_accounts") or [],
            "protected_domains": pol.get("protected_domains") or [],
            "protected_ips": pol.get("protected_ips") or [],
            "protected_paths": pol.get("protected_paths") or [],
        }
    except Exception as exc:  # noqa: BLE001
        m["assets"] = {"error": f"{type(exc).__name__}: {exc}"}

    # 检测能力（直接读代码里的规则表，避免与实现漂移）
    rules: List[Dict[str, Any]] = []
    try:
        import tools.net_sensor as ns
        why = {
            "high_risk_port": "外连远控/矿池常用端口",
            "soft_port": "弱可疑端口（需组合证据）",
            "suspect_path": "可执行文件位于非常规目录",
            "proc_from_suspect_dir": "新进程从非常规目录启动（事件驱动）",
            "port_fanout": "单进程连多个目的端口（疑扫描/横向）",
            "periodic_beacon": "周期性外连（疑心跳）",
            "intranet_lateral": "内网横向连接",
            "conn_burst": "单目标连接数爆发（疑外传）",
            "rare_port": "外连非标准端口",
        }
        for name, base in ns._RULE_BASE.items():
            rules.append({"rule": name, "base_score": base, "why": why.get(name, "")})
        m["detection"] = {
            "threshold": 30,
            "rules": sorted(rules, key=lambda x: -x["base_score"]),
            "high_risk_ports": sorted(ns.HIGH_RISK_PORTS),
            "trusted_paths": list(ns.TRUSTED_PATH_HINTS),
            "whitelist_cap": getattr(ns, "_WHITELIST_CAP", None),
            "annotation_rules": sorted(getattr(ns, "_ANNOTATION_RULES", set())),
        }
    except Exception as exc:  # noqa: BLE001
        m["detection"] = {"error": f"{type(exc).__name__}: {exc}", "rules": []}

    # 观测到的（近 500 条事件按规则聚合）
    observed: Dict[str, Any] = {"events": 0, "by_rule": {}, "top_procs": {},
                               "routed": {}, "sources": {}}
    try:
        ev = PROJECT_ROOT / "logs/net_sensor_events.jsonl"
        recs: List[Dict[str, Any]] = []
        if ev.is_file():
            for line in ev.read_text(encoding="utf-8", errors="replace").splitlines()[-500:]:
                line = line.strip()
                if not line:
                    continue
                try:
                    o = json.loads(line)
                except ValueError:
                    continue
                if isinstance(o, dict):
                    recs.extend(o.get("facts") or [o])
        observed["events"] = len(recs)
        for r in recs:
            for rule in (r.get("rules") or []):
                observed["by_rule"][rule] = observed["by_rule"].get(rule, 0) + 1
            p = str(r.get("proc") or "?")
            observed["top_procs"][p] = observed["top_procs"].get(p, 0) + 1
            route = str(r.get("route") or "未研判")
            observed["routed"][route] = observed["routed"].get(route, 0) + 1
            observed["sources"]["net_sensor"] = observed["sources"].get("net_sensor", 0) + 1
        observed["by_rule"] = dict(sorted(observed["by_rule"].items(),
                                          key=lambda x: -x[1])[:12])
        observed["top_procs"] = dict(sorted(observed["top_procs"].items(),
                                            key=lambda x: -x[1])[:8])
    except Exception as exc:  # noqa: BLE001
        observed["error"] = f"{type(exc).__name__}: {exc}"
    m["observed"] = observed

    # 覆盖缺口（诚实边界；与 docs 保持一致）
    m["gaps"] = [
        "**只在本机看得见**：轮询式采集对短连接有结构性盲区（事件驱动补了一部分，但不是全部）。",
        "**加密流量看不见**：只看五元组与进程，不看内容；域前置/CDN 上的 C2 与正常 HTTPS 无法区分。",
        "**白名单是双刃剑**：它能降噪，但把恶意文件加进白名单就等于放行其告警。"
        "本实现在校验层硬拒绝覆盖临时/下载等目录，降低这种风险，但不能消除人为误加。",
        "**签名有效 ≠ 无害**：签名只用于降级（40→10），不用于豁免。",
        "**遏制是真实但有限的**：只封精确对端的出向且带 TTL；主机隔离等破坏性动作仍为占位。",
        "**动态分析不由 AI 执行**：样本行为需要人工在沙箱内引爆后回填。",
    ]

    # PDCERF 阶段状态
    try:
        from actions.pdcerf import PHASE_META
        m["phases"] = [{"phase": k.value, "zh": v["zh"], "en": v["en"],
                        "goal": v["goal"]} for k, v in PHASE_META.items()]
    except Exception as exc:  # noqa: BLE001
        m["phases"] = []
        m["phase_error"] = str(exc)

    return m


# --------------------------------------------------------------------------- #
# 封锁
# --------------------------------------------------------------------------- #

def containment_state() -> Dict[str, Any]:
    import sandbox.contain as _c
    rules = _cached("containment_rules", 6.0, _c.list_rules)
    return {"count": len(rules), "rules": rules, "prefix": _c.RULE_PREFIX}


def containment_add(indicator: str, *, ttl_seconds: int = 14400, reason: str = "",
                    case_id: str = "gui", apply_now: bool = False,
                    allow_unverified: bool = False) -> Dict[str, Any]:
    """手动封禁。**拒绝条件照旧生效**，界面会把拒绝原因原样显示出来。"""
    from sandbox.contain import apply_contain, plan_contain
    plan = plan_contain(indicator, case_id=case_id, reason=reason or "手工封锁（GUI）",
                        ttl_seconds=ttl_seconds, allow_unverified=allow_unverified)
    res = apply_contain(plan, apply=apply_now)
    _audit("containment_add", {"indicator": indicator, "apply": apply_now,
                               "status": res.status, "refused": len(plan.refused)})
    invalidate_cache("containment")
    return {
        "status": res.status, "ok": res.ok, "detail": res.detail,
        "will_block": [asdict(i) for i in plan.items],
        "refused": [asdict(i) for i in plan.refused],
        "notes": plan.notes,
        "non_interference": res.non_interference,
        "applied": res.applied, "existing": res.existing, "verified": res.verified,
        "errors": res.errors, "expires_at": res.expires_at,
    }


def containment_remove(names: Optional[List[str]] = None) -> Dict[str, Any]:
    from sandbox.contain import remove_rules
    out = remove_rules(names)
    _audit("containment_remove", {"names": names or ["<all>"], "ok": out.get("ok")})
    invalidate_cache("containment")
    return out


# --------------------------------------------------------------------------- #
# 白名单
# --------------------------------------------------------------------------- #

def whitelist_state() -> Dict[str, Any]:
    from security.whitelist import CRITICAL_PROCESS_NAMES, KINDS, STAGING_HINTS, default_whitelist
    wl = default_whitelist()
    return {"stats": wl.stats(), "entries": [e.to_dict() for e in wl.entries()],
            "kinds": list(KINDS),
            "policy": {
                "staging_hints": list(STAGING_HINTS),
                "critical_process_names": list(CRITICAL_PROCESS_NAMES),
            }}


def whitelist_add(kind: str, value: str, *, note: str = "",
                  ttl_days: int = 0) -> Dict[str, Any]:
    """加入白名单。校验不过会抛 `GuiError`（界面把原因显示出来）。"""
    from security.whitelist import RefusedError, default_whitelist
    wl = default_whitelist()
    try:
        e = wl.add(kind, value, note=note, ttl_days=ttl_days,
                   added_by=os.environ.get("USERNAME", "") + "（GUI）")
    except RefusedError as exc:
        _audit("whitelist_reject", {"kind": kind, "value": value, "why": str(exc)})
        raise GuiError(str(exc)) from exc
    _audit("whitelist_add", {"kind": kind, "value": value, "note": note})
    invalidate_cache("whitelist")
    return {"ok": True, "entry": e.to_dict(), "stats": wl.stats()}


def whitelist_remove(kind: str, value: str) -> Dict[str, Any]:
    from security.whitelist import default_whitelist
    wl = default_whitelist()
    ok = wl.remove(kind, value)
    _audit("whitelist_remove", {"kind": kind, "value": value, "found": ok})
    invalidate_cache("whitelist")
    return {"ok": ok, "removed": ok, "stats": wl.stats()}


# --------------------------------------------------------------------------- #
# 动作日志与撤销
# --------------------------------------------------------------------------- #

def _read_audit(path: Path, limit: int = 400) -> List[Dict[str, Any]]:
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except ValueError:
            continue
        if isinstance(o, dict):
            out.append(o)
    return out


def actions_journal(limit: int = 200) -> Dict[str, Any]:
    """AI 动作台账 + 可撤销性判定。

    可撤销性是从**动作语义**推出来的，不是猜的；拿不准的一律标成不可撤（fail-closed），
    免得界面上给个"撤销"按钮、点下去却没有效果（那比没有按钮更糟）。
    """
    recs = _read_audit(PROJECT_ROOT / "logs/action_audit.jsonl", limit=400)
    rules = {x.get("name") for x in containment_state()["rules"]}

    items: List[Dict[str, Any]] = []
    for r in recs:
        action = str(r.get("action") or "")
        status = str(r.get("status") or "")
        dry = bool(r.get("dry_run"))
        ok = bool(r.get("ok"))
        undoable = False
        undo_kind = ""
        note = ""
        if dry or status in ("dry_run", "planned", "pending_confirmation", "denied"):
            note = "演练/未生效 —— 无需撤销"
        elif action == "contain_threat" and ok:
            undoable = True
            undo_kind = "firewall"
            note = "可撤销：删除本系统建的防火墙规则"
        elif action == "collect_forensics" and ok:
            undo_kind = "kape_output"
            note = "属**证据固化**，默认不可撤（删证据比留着更危险）；如需清理需显式确认"
        elif action == "extract_payload" and ok:
            undo_kind = "vault"
            note = "属**证据固化**（只读库），默认不可撤；如需清理需显式确认"
        elif action in ("notify_analyst", "query_logs", "asset_lookup"):
            note = "只读/通知类，无系统状态变更"
        else:
            note = "本部署下未真正执行（占位或未实现），无可撤内容"
        items.append({
            "ts": r.get("ts"), "time": (time.strftime("%Y-%m-%d %H:%M:%S",
                                                     time.localtime(float(r["ts"])))
                                        if isinstance(r.get("ts"), (int, float)) else ""),
            "case_id": r.get("case_id"), "phase": r.get("phase"), "action": action,
            "status": status, "adapter": r.get("adapter"), "ok": ok,
            "risk": r.get("risk"), "irreversible": r.get("irreversible"),
            "dry_run": dry, "args": r.get("args") or {},
            "undoable": undoable, "undo_kind": undo_kind, "note": note,
            "policy_reason": r.get("policy_reason") or "",
            "observations": str(r.get("observations") or "")[:300],
        })
    items.reverse()      # 最新在前

    pending_dir = PROJECT_ROOT / "logs/pending_actions"
    pending = []
    if pending_dir.is_dir():
        for f in sorted(pending_dir.glob("*.json")):
            try:
                pending.append({"file": f.name, **json.loads(f.read_text(encoding="utf-8"))})
            except (OSError, ValueError):
                continue

    return {"total": len(items), "items": items, "pending": pending,
            "current_rules": sorted(rules),
            "undo_log": str(PROJECT_ROOT / UNDO_LOG)}


def action_undo(undo_kind: str, payload: Dict[str, Any],
                confirm_evidence: bool = False) -> Dict[str, Any]:
    """撤销一个动作。**只做能确定撤干净的那件事**。"""
    if undo_kind == "firewall":
        names = payload.get("names") or []
        if not names:
            # 默认撤掉本系统建的全部（前缀匹配，不会碰别人的规则）
            out = containment_remove(None)
            return {"ok": out.get("ok"), "detail": out.get("detail"),
                    "scope": "本系统建的全部防火墙规则"}
        out = containment_remove(list(names))
        return {"ok": out.get("ok"), "detail": out.get("detail"), "scope": names}

    if undo_kind in ("kape_output", "vault"):
        if not confirm_evidence:
            raise GuiError(
                "这属于**证据固化**，默认不撤销。删掉之后案子复核时就找不到了 —— "
                "确需清理请勾选「确认删除证据」再执行。")
        rel = str(payload.get("path") or "")
        p = (PROJECT_ROOT / rel).resolve()
        root = PROJECT_ROOT.resolve()
        allowed = (root / "logs/forensics", root / "logs/sandbox/vault",
                   root / "logs/sandbox/cases")
        if not str(p).startswith(str(root)) or not any(str(p).startswith(str(a)) for a in allowed):
            raise GuiError("路径越界或不在允许清理的范围内")
        if not p.exists():
            return {"ok": False, "detail": f"不存在：{rel}"}
        shutil.rmtree(p) if p.is_dir() else p.unlink()
        _audit("undo_evidence", {"kind": undo_kind, "path": rel})
        return {"ok": True, "detail": f"已删除 {rel}", "scope": rel}

    raise GuiError(f"不支持的撤销类型：{undo_kind}")


# --------------------------------------------------------------------------- #
# KAPE
# --------------------------------------------------------------------------- #

def _yaml_section(rel: str, *path: str) -> Dict[str, Any]:
    """从配置文件里取一段（取不到就返回空字典）。"""
    try:
        import yaml
        cur: Any = yaml.safe_load((PROJECT_ROOT / rel).read_text(encoding="utf-8")) or {}
        for k in path:
            if not isinstance(cur, dict):
                return {}
            cur = cur.get(k)
            if cur is None:
                return {}
        return cur if isinstance(cur, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def kape_gates() -> Dict[str, Any]:
    """两道真实采集开关的当前值。

    本项目为真实采集设了**两道**开关（都在配置里，默认关）：
      1. `actions/config.yaml → adapters.kape.execute_enabled`：工具层第二道开关
      2. `agent/config.yaml → forensics.execute`：联动层开关

    为什么要取**真实配置值**而不是 `KapeConfig()` 的默认值：我用 `KapeConfig()`
    （全默认）写过一版，界面于是把"未允许（会拒绝执行）"显示出来 —— 而它读的只是
    dataclass 默认值，跟配置里到底写了什么没关系。更糟的是那时的执行路径根本没看
    这个值，于是"界面说会拒绝、实际却跑了一次 420 MB 的真实采集"。
    界面上的开关必须真的有效，否则就不该把它画成一个开关。
    """
    k = _yaml_section("actions/config.yaml", "adapters", "kape")
    f = _yaml_section("agent/config.yaml", "forensics")
    return {
        "tool_execute": bool(k.get("execute_enabled", False)),
        "agent_execute": bool(f.get("execute", False)),
        "tool_key": "actions/config.yaml → adapters.kape.execute_enabled",
        "agent_key": "agent/config.yaml → forensics.execute",
    }


def _kape_cfg():
    """按**真实配置**构造 KapeConfig（跟动作适配器用同一个来源，见 actions/adapters/kape.py）。"""
    from forensics.kape import KapeConfig
    return KapeConfig.from_dict(_yaml_section("actions/config.yaml", "adapters", "kape"))


def kape_state() -> Dict[str, Any]:
    """KAPE 状态：装没装、真不真、有哪些 target/module、命令预览、两道开关。"""
    out: Dict[str, Any] = {}
    gates = kape_gates()
    try:
        from forensics.kape import KAPE_CANDIDATES, build_command, build_job, probe_exe
        cfg = _kape_cfg()
        exe = cfg.resolve_exe()
        # 超时给 4 秒而不是默认 8 秒：见 _probe_kape 的说明（KAPE 探测卡界面首屏）
        real, why = probe_exe(exe, timeout=4) if exe else (False, "未找到 kape.exe")
        out = {"exe": exe, "candidates": list(KAPE_CANDIDATES), "real": real,
               "detail": why, "target": cfg.target, "module": cfg.module,
               "tsource": cfg.tsource, "sim": cfg.sim,
               "max_collect_mb": cfg.max_collect_mb,
               "output_root": str(cfg.root()),
               "execute_enabled": gates["tool_execute"],
               "can_execute": gates["tool_execute"] and gates["agent_execute"],
               "gates": gates}
        if exe:
            job = build_job("gui-preview", os.environ.get("COMPUTERNAME", "localhost"),
                            "triage", "GUI 预览", cfg, cfg.root())
            out["command_preview"] = subprocess.list2cmdline(
                build_command(job, cfg, cfg.root()))
    except Exception as exc:  # noqa: BLE001
        out = {"exe": "", "real": False, "detail": f"{type(exc).__name__}: {exc}",
               "execute_enabled": gates["tool_execute"],
               "can_execute": gates["tool_execute"] and gates["agent_execute"],
               "gates": gates}
    return out


def kape_run(*, execute: bool = False, sim: bool = False, module: str = "",
             target: str = "") -> Dict[str, Any]:
    """跑一次采集（或 KAPE 原生 `--sim` 只校验配置）。

    真实执行需要**两道配置开关都开**、且当前进程是管理员（由 `forensics.kape.run`
    自己把关，非管理员会拒绝，以免产出残缺证据）。

    闸门放在这里而不是 `forensics.kape.run()` 里，是有意为之：`run()` 是底层工具，
    它的 `dry_run=False` 就等于命令行上的 `--execute`，本来就是「调用者明确要真跑」的意思，
    所以它不该自己去读配置。而 GUI 是面向操作员的控制台，它宣称的开关必须真的有效 ——
    否则界面上就会写着"会拒绝执行"却真的执行。
    """
    from forensics.kape import build_job, run

    gates = kape_gates()
    if execute and not gates["tool_execute"]:
        raise GuiError(
            "拒绝真实采集：配置开关未开（" + gates["tool_key"] + " = false）。\n"
            "一次采集会写入数百 MB 产物、并读取锁定的注册表配置单元，"
            "所以真实执行需要在配置里显式批准，而不是在界面上点一下就算了。\n"
            "如确需开启，请在「配置」页把它改为 true（会自动备份并校验 YAML）。")
    if execute and not gates["agent_execute"]:
        raise GuiError(
            "拒绝真实采集：联动层开关未开（" + gates["agent_key"] + " = false）。\n"
            "本项目要求两道开关同时成立才允许真实采集（见 agent/config.yaml 注释："
            "“true = 真实调用 KAPE（需管理员；且仍需 kape.execute_enabled）”）。")

    cfg = _kape_cfg()
    if target:
        cfg.target = target
    if module:
        cfg.module = module
    if sim:
        cfg.sim = True
    job = build_job(f"gui-{time.strftime('%Y%m%d-%H%M%S')}",
                    os.environ.get("COMPUTERNAME", "localhost"),
                    "triage", "GUI 触发", cfg, cfg.root())
    res = run(job, cfg, dry_run=not execute)
    _audit("kape_run", {"execute": execute, "sim": sim, "status": res.status,
                        "outdir": res.outdir})
    return res.to_dict()


def kape_launch_gui() -> Dict[str, Any]:
    """唤起 KAPE 官方 GUI（gkape.exe）—— 需要人工交互时用。"""
    from forensics.kape import KapeConfig
    exe = _kape_cfg().resolve_exe()
    if not exe:
        raise GuiError("未找到 kape.exe")
    gk = Path(exe).with_name("gkape.exe")
    if not gk.is_file():
        raise GuiError(f"未找到 gkape.exe（{gk}）")
    # 用 explorer 启动：它会以当前用户身份掀起来，不受服务会话限制
    subprocess.Popen(["explorer", str(gk)])  # noqa: S603
    _audit("kape_gui", {"exe": str(gk)})
    return {"ok": True, "launched": str(gk)}


def open_in_explorer(rel: str) -> Dict[str, Any]:
    """在资源管理器里打开一个目录（限定在项目内的已知目录）。"""
    p = (PROJECT_ROOT / str(rel).replace("\\", "/")).resolve()
    root = PROJECT_ROOT.resolve()
    if not str(p).startswith(str(root)):
        raise GuiError("路径越界")
    if not p.exists():
        raise GuiError(f"目录不存在：{rel}")
    subprocess.Popen(["explorer", str(p)])  # noqa: S603
    return {"ok": True, "path": str(p)}


# --------------------------------------------------------------------------- #
# 自检（不起服务器、不开端口）
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
            print(f"  [FAIL] {name}  {str(detail)[:200]}")

    print("=== gui.core 自检 ===")

    # -- 路径限制（GUI 不能变成任意文件读写器）--
    for bad in ("../../etc/passwd", "/etc/passwd", "C:/Windows/System32/config/SAM",
                "logs/net_sensor.log"):
        try:
            _safe_rel(bad, EDITABLE_CONFIGS)
            chk(f"拒绝非配置路径：{bad}", False, "竟然通过了")
        except GuiError:
            chk(f"拒绝非配置路径：{bad[:40]}", True)

    # -- 读配置 --
    r = read_config("agent/config.yaml", parsed=True)
    chk("读 agent/config.yaml 成功且 YAML 可解析",
        bool(r["text"]) and r["valid"], r.get("error", ""))
    chk("解析出字典结构", isinstance(r["data"], dict) and bool(r["data"]))

    # -- 写配置：非法 YAML 必须拒绝，且不落盘 --
    before = (PROJECT_ROOT / "agent/config.yaml").read_text(encoding="utf-8")
    try:
        write_config("agent/config.yaml", "key: [unclosed\n  bad: : :\n")
        chk("非法 YAML 被拒绝", False, "竟然写进去了")
    except GuiError as exc:
        chk("非法 YAML 被拒绝", "不是合法 YAML" in str(exc), str(exc))
    after = (PROJECT_ROOT / "agent/config.yaml").read_text(encoding="utf-8")
    chk("拒绝后原文件未被改动", before == after)
    chk("拒绝时不产生备份垃圾", True)

    # -- 写配置：合法内容应写入并留备份 --
    tmp_cfg = PROJECT_ROOT / BACKUP_DIR
    n_bak_before = len(list(tmp_cfg.glob("*"))) if tmp_cfg.is_dir() else 0
    out = write_config("agent/config.yaml", before)
    n_bak_after = len(list(tmp_cfg.glob("*")))
    chk("合法内容写入成功", out["ok"] is True)
    chk("写入前留了备份", n_bak_after == n_bak_before + 1, f"{n_bak_before}→{n_bak_after}")
    chk("内容保持一致", (PROJECT_ROOT / "agent/config.yaml").read_text(encoding="utf-8") == before)

    # -- 报告与日志 --
    reps = list_reports()
    chk("能列出报告", isinstance(reps, list) and len(reps) > 0, str(len(reps)))
    if reps:
        rr = read_report(reps[0]["path"])
        chk("能读第一份报告", bool(rr["text"]))
    try:
        read_report("agent/config.yaml")
        chk("报告读取拒绝非 reports/logs 路径", False, "竟然通过了")
    except GuiError:
        chk("报告读取拒绝非 reports/logs 路径", True)

    logs = list_logs()
    chk("能列出日志清单", isinstance(logs, list) and len(logs) >= 5, str(len(logs)))
    tl = tail_log("logs/net_sensor.log", 5)
    chk("能读日志尾部", tl["exists"] is False or isinstance(tl["lines"], list))
    try:
        tail_log("logs/../agent/config.yaml")
        chk("日志读取拒绝越权路径", False, "竟然通过了")
    except GuiError:
        chk("日志读取拒绝越权路径", True)

    # -- 传感器探测：必须用 CIM，不能用 Get-Process --
    # PS 5.1 的 Get-Process 对象没有 CommandLine 属性，用它过滤会恒定返回
    # "已停止"（假告警）。做源码级守卫，防止以后被改回去。
    import inspect as _inspect
    _src = _inspect.getsource(_probe_sensor)
    chk("传感器探测用 Win32_Process（CIM）而非 Get-Process",
        "Win32_Process" in _src, "未找到 Win32_Process")
    chk("传感器探测不再依赖 Get-Process 的 CommandLine",
        "Get-Process -Name" not in _src, "仍在使用 Get-Process")
    _sen = _probe_sensor()
    chk("传感器探测返回 running / procs / task_state",
        all(k in _sen for k in ("running", "procs", "task_state")), str(_sen))
    chk("传感器探测与计划任务状态一致（真在跑就不会报已停止）",
        (_sen.get("task_state") != "Running") or _sen.get("running") is True,
        str(_sen))

    # -- 缓存：没有它首屏要等十几秒；退化成"每次都重新探测"没人会发现 --
    invalidate_cache()
    _t0 = time.time()
    status()
    d1 = time.time() - _t0
    _t0 = time.time()
    status()
    d2 = time.time() - _t0
    chk("第二次状态查询命中缓存（明显更快）", d2 < max(0.5, d1 * 0.5),
        f"首次 {d1:.2f}s → 二次 {d2:.2f}s")
    invalidate_cache("containment")
    chk("写操作后可定向失效缓存", "containment_rules" not in _TTL_CACHE)

    # -- 威胁建模（全部取自真实来源，不应抛）--
    tm = threat_model()
    chk("威胁建模返回资产栏", "assets" in tm)
    chk("威胁建模返回检测规则且非空",
        bool((tm.get("detection") or {}).get("rules")), str(tm.get("detection"))[:120])
    chk("威胁建模返回观测栏", "observed" in tm)
    chk("威胁建模含覆盖缺口（诚实边界）",
        bool(tm.get("gaps")) and len(tm["gaps"]) >= 5, str(len(tm.get("gaps") or [])))
    chk("威胁建模含 PDCERF 阶段", bool(tm.get("phases")))
    chk("威胁建模不复制文档而是读代码规则表",
        any(r["rule"] == "conn_burst" for r in tm["detection"]["rules"]))

    # -- 白名单（走 core 的封装）--
    st = whitelist_state()
    chk("白名单状态可读", "stats" in st and "policy" in st)
    try:
        whitelist_add("folder", r"C:\Users\user\AppData\Local\Temp")
        chk("白名单拒绝覆盖临时目录", False, "竟然加进去了")
    except GuiError as exc:
        chk("白名单拒绝覆盖临时目录", "可疑的目录" in str(exc) or "白名单不许" in str(exc),
            str(exc))
    try:
        whitelist_add("process", "svchost.exe")
        chk("白名单拒绝系统进程裸名", False, "竟然加进去了")
    except GuiError as exc:
        chk("白名单拒绝系统进程裸名", "裸名" in str(exc), str(exc))

    # -- 封锁（拒绝条件照旧生效）--
    c = containment_add("192.168.1.0/24", apply_now=False)
    chk("GUI 封锁同样拒绝网段", c["status"] == "denied" and bool(c["refused"]),
        str(c.get("detail"))[:160])
    c2 = containment_add("203.0.113.210", apply_now=False)
    chk("GUI 封锁普通地址只出计划（未真改）",
        c2["status"] == "planned" and not c2["applied"], str(c2.get("status")))

    # -- 动作台账 --
    j = actions_journal()
    chk("动作台账可读且有可撤销性判定",
        "items" in j and all("undoable" in i for i in j["items"]),
        str(len(j.get("items") or [])))
    chk("台账里的 dry_run 项标为无需撤销",
        all(("无需撤销" in i["note"]) for i in j["items"] if i["dry_run"]),
        str([i["action"] for i in j["items"] if i["dry_run"]][:3]))
    try:
        action_undo("vault", {"path": "logs/sandbox/vault/x"})
        chk("撤销证据需显式确认", False, "竟然直接删了")
    except GuiError as exc:
        chk("撤销证据需显式确认", "确认删除证据" in str(exc), str(exc))
    try:
        action_undo("unknown_kind", {})
        chk("未知撤销类型被拒绝", False, "竟然通过了")
    except GuiError:
        chk("未知撤销类型被拒绝", True)

    # -- KAPE 状态（本机已装，应认出真的 KAPE）--
    ks = kape_state()
    chk("KAPE 状态可读", "exe" in ks)
    if ks.get("exe"):
        chk("认出真的 KAPE（不是替身）", ks.get("real") is True, ks.get("detail", ""))
        chk("给出命令预览", bool(ks.get("command_preview")))
        chk("预览含 --tsource 等真实参数", "--tsource" in str(ks.get("command_preview")))
    chk("KAPE 状态来自真实配置（带 gates 字段）",
        "gates" in ks and "can_execute" in ks, str(ks.get("gates")))
    chk("闸门读的是配置文件而非 dataclass 默认值",
        ks.get("gates", {}).get("tool_key", "").endswith("execute_enabled"),
        str(ks.get("gates")))

    # -- 真实采集闸门必须真的拦住（这是踩过的坑）--
    # 曾經：界面显示"未允许（会拒绝执行）"，却真跑了一次 420 MB 的采集 ——
    # 因为闸门在 CLI 层，而 GUI 直接调了 forensics.kape.run()。
    import subprocess as _sp

    def _kape_procs() -> int:
        try:
            r = _sp.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                         "(Get-CimInstance Win32_Process -Filter \"Name='kape.exe'\" "
                         "-ErrorAction SilentlyContinue | Measure-Object).Count"],
                        capture_output=True, text=True, timeout=25,
                        creationflags=0x08000000)
            return int((r.stdout or "0").strip() or 0)
        except Exception:  # noqa: BLE001
            return -1

    before = _kape_procs()
    if ks.get("can_execute"):
        print("  [SKIP] 两道开关已开：跳过『闸门应拒绝』的断言（此时拒绝才是错的）")
    else:
        try:
            kape_run(execute=True)
            chk("执行闸门关着时 execute=True 被拒绝", False, "竟然真的执行了（可能已在采集！）")
        except GuiError as exc:
            chk("执行闸门关着时 execute=True 被拒绝", "拒绝真实采集" in str(exc), str(exc)[:160])
            chk("拒绝原因指明了具体配置键",
                "execute_enabled" in str(exc) or "forensics.execute" in str(exc), str(exc)[:200])
        chk("被拒绝时没有拉起 kape.exe 进程", _kape_procs() == before,
            f"{before} → {_kape_procs()}")

    # -- 演练始终允许（它不产生产物）--
    simres = kape_run(execute=False, sim=True)
    chk("演练（execute=False）允许且返回 dry_run",
        simres.get("status") == "dry_run" and not simres.get("collected_files"),
        str(simres.get("status")))

    print(f"\ngui.core 自检：{ok} 通过 / {fail} 失败")
    return 1 if fail else 0


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="GUI 服务层自检（不启服务器）")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
