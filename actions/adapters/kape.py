#!/usr/bin/env python3
"""actions/adapters/kape.py —— 把 `collect_forensics` 动作接到 KAPE 取证（forensics/kape.py）。

分工（与 base.py 的约定一致）：
  * 适配器**不做安全校验** —— schema / 两阶段确认 / 保护资产仍由 ActionExecutor 负责。
    这里只做「执行 + 如实汇报」。
  * 不可用必须**显式** `unavailable`：没装 KAPE、不是管理员、产物目录越界，
    都如实说明，绝不静默降级成"假装采集成功"。

为什么非管理员要拒绝而不是"尽力而为"：
    KAPE 的注册表配置单元 / SRUDB / 事件日志在非管理员下取不全。
    取不全的结果拿去研判，会让人得出"没有持久化项"这种**错误结论**——
    残缺的取证比没有取证更危险。所以这里改成产出**一份可提权执行的 .cmd**，
    把"执行"这一步交回给人。
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, Set, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from actions.adapters.base import (Adapter, ExecutionFailed, STATUS_DRY_RUN,  # noqa: E402
                                  STATUS_FAILED, STATUS_OK, STATUS_UNAVAILABLE,
                                  ToolContext, ToolResult)
from forensics import kape as kape_mod                                   # noqa: E402
from security.action_schema import Action                                # noqa: E402


class KapeAdapter(Adapter):
    name = "kape"
    #: 标 True 是**故意的**：KAPE 会真的写产物（数百 MB）、真的读被采集主机。
    #: 它不改变被取证主机的状态（因此可以自由预取），但它不是"仿真"——
    #: 标成 False 会让执行器把结果当成模拟结果，那是误导。
    real_effects = True

    def __init__(self, cfg: Dict[str, Any] | None = None) -> None:
        self.cfg = kape_mod.KapeConfig.from_dict(cfg)

    def capabilities(self) -> Set[str]:
        return {"collect_forensics"}

    def health(self) -> Tuple[bool, str]:
        """缺 KAPE 也算"可用"：演练仍能产出可执行的计划文件。
        真正不能做的事（本机没装 / 是替身 / 非管理员）在执行时如实返回 unavailable。"""
        rev = self.cfg.root()
        try:
            rev.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return False, f"取证输出目录不可写：{rev}（{exc}）"
        exe = self.cfg.resolve_exe()
        if not exe:
            return True, ("未找到 kape.exe：本机不能真实采集，"
                          "但可生成计划（需另机/提权执行）")
        # 验明正身：项目里有个测试替身也叫 kape.exe，配错了会"假装采集成功"。
        ok, why = kape_mod.probe_exe(exe)
        if not ok:
            return False, f"{exe} 不是可用的 KAPE：{why}"
        return True, f"kape.exe 可用：{why}"

    def execute(self, action: Action, ctx: ToolContext) -> ToolResult:
        args = action.args or {}
        host_id = str(args.get("host_id") or "")
        artifacts = str(args.get("artifacts") or "triage")
        case_id = str(args.get("case_id") or ctx.case_id or "case")
        reason = action.rationale or "由 Agent 提案"

        dry = bool(ctx.dry_run) or not self.cfg.execute_enabled
        try:
            job = kape_mod.build_job(case_id, host_id, artifacts, reason, self.cfg,
                                     self.cfg.root())
            res = kape_mod.run(job, self.cfg, dry_run=dry)
        except Exception as exc:  # noqa: BLE001
            raise ExecutionFailed(f"KAPE 适配器异常：{exc}") from exc

        status = res.status
        if status not in (STATUS_OK, STATUS_DRY_RUN, STATUS_UNAVAILABLE, STATUS_FAILED):
            status = STATUS_FAILED

        obs = self._observe(res, dry)
        return ToolResult(ok=res.ok, action="collect_forensics", adapter=self.name,
                          status=status, output=res.to_dict(),
                          observations=obs, error="" if res.ok else res.detail,
                          latency_ms=int(res.elapsed_s * 1000))

    @staticmethod
    def _observe(res: kape_mod.KapeResult, dry: bool) -> str:
        """给模型看的观测。**如实**说明采集没采集、为什么。"""
        if res.status == STATUS_DRY_RUN:
            return (f"[取证-演练] 未执行采集。已生成计划：{res.plan_file}"
                    f"（含完整命令行，需以管理员身份运行）。"
                    f"产物目录规划在 {res.outdir}。")
        if res.status == STATUS_UNAVAILABLE:
            return (f"[取证-不可用] 未采集。原因：{res.detail}"
                    f"　→ 请以管理员身份运行 {res.plan_file}。")
        if res.status == STATUS_OK:
            base = (f"[取证-完成] 产物 {res.collected_files} 个文件 / {res.collected_mb} MB，"
                    f"位于 {res.outdir}。注意：取证完成不等于根因已定位，"
                    f"下一步应解析产物（模块 Parsing）并做时间线关联。")
            if res.oversize:
                # 体积超预算必须在观测里说出来。否则模型只会看到"取证完成"，
                # 而流水线已经悄悄往磁盘上写了几个 GB。（v1.1 实测 17826 MB。）
                base += (f"　⚠ 体积超出预算：{res.detail.split('⚠')[-1].strip()}"
                         f"建议人工确认后再对下一台主机采集。")
            return base
        return f"[取证-失败] {res.detail}"


def build(cfg: Dict[str, Any] | None = None) -> KapeAdapter:  # 供注册表按名实例化
    return KapeAdapter(cfg)
