#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""actions/adapters/sandboxie.py — 把沙箱/载荷/最小影响封锁接进 PDCERF 动作系统。

支持的动作（**只有这四个**）
----------------------------

    extract_payload            载荷镜像提取到只读库 + 报警
    analyze_payload            静态取证分析（不执行样本）
    prepare_dynamic_analysis   生成人工动态分析交接包（不执行样本）
    contain_threat             最小影响封锁（只封精确对端的出向，带 TTL）

⚠ **本适配器没有、也不会有 `detonate_payload`。**
需求是「禁止 AI 进行动态分析」。所以它不仅在配置里关着，而是整条链路都不存在：
`security/action_schema.ACTION_SPECS` 里没有这个名字（default-deny 会直接拒绝），
`sandbox/sandboxie.py` 有 vault 路径守卫 + AST 断言证明无法执行库内载荷，
`sandbox/dynamic_handoff.py` 连 `subprocess` 都不 import。
要加动态分析能力，得同时改四处且过不了自检 —— 这才算"约束"。

设计约定（与其它适配器一致）
----------------------------

* 适配器**不做**安全校验（schema / 两阶段确认 / 保护资产）——那是 `ActionExecutor`
  的职责。这里只"执行 + 如实汇报"。
* 不可用必须**显式**返回 `unavailable`，不允许静默降级成"假装成功"。
* 有真实副作用的动作（提取写盘、封锁改防火墙）**默认只演练**，
  要显式 `execute_enabled: true` 且 `ctx.dry_run` 为假才真做。
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from actions.adapters.base import (  # noqa: E402
    Adapter,
    STATUS_DENIED,
    STATUS_DRY_RUN,
    STATUS_FAILED,
    STATUS_OK,
    STATUS_UNAVAILABLE,
    ToolContext,
    ToolResult,
)

CAP_EXTRACT = "extract_payload"
CAP_ANALYZE = "analyze_payload"
CAP_HANDOFF = "prepare_dynamic_analysis"
CAP_CONTAIN = "contain_threat"


class SandboxAdapter(Adapter):
    """沙箱联动适配器。"""

    name = "sandbox"
    #: 会写盘（只读库/案例目录）与改防火墙，属于真实副作用。
    #: 标 False 会让执行器把它当模拟，反而更危险。
    real_effects = True

    def __init__(self, cfg: Optional[Dict[str, Any]] = None) -> None:
        self.cfg = cfg or {}
        self.enabled = bool(self.cfg.get("enabled", False))
        self.sbox_cfg = None            # 延迟构造（读 sandboxie.SandboxieConfig）

    # ---------------------------------------------------------------- 能力
    def capabilities(self) -> Set[str]:
        if not self.enabled:
            return set()
        return {CAP_EXTRACT, CAP_ANALYZE, CAP_HANDOFF, CAP_CONTAIN}

    def _config(self):
        """构造 SandboxieConfig（延迟 import，避免包初始化顺序问题）。"""
        if self.sbox_cfg is None:
            from sandbox.sandboxie import SandboxieConfig  # noqa: PLC0415
            self.sbox_cfg = SandboxieConfig.from_dict(self.cfg)
        return self.sbox_cfg

    def health(self) -> Tuple[bool, str]:
        """可用性：只读库可写即可。Sandboxie 与管理员状态如实附在说明里。

        为什么"没装 Sandboxie"不算不健康：提取与静态分析是纯 Python 实现的，
        不依赖 Sandboxie；Sandboxie 只影响**人工**引爆那一步（交接包里会说明）。
        把整条链路因为缺 Sandboxie 而判不可用，会让"发现威胁先固定证据"
        这个最该自动化的动作也做不了，得不偿失。
        """
        if not self.enabled:
            return False, "配置里 adapters.sandbox.enabled 为 false"
        notes: List[str] = []
        try:
            vault = self._config().vault_path()
            vault.mkdir(parents=True, exist_ok=True)
            probe = vault / ".write_probe"
            probe.write_text("x", encoding="utf-8")
            probe.unlink(missing_ok=True)
            notes.append(f"只读库可写：{vault}")
        except OSError as exc:
            return False, f"只读库不可写：{exc}"

        try:
            from sandbox.sandboxie import probe_install  # noqa: PLC0415
            installed, why = probe_install(self._config())
            notes.append(("Sandboxie 可用：" if installed else "Sandboxie 不可用（只影响人工引爆）：")
                         + why[:120])
        except Exception as exc:  # noqa: BLE001
            notes.append(f"Sandboxie 探测异常：{type(exc).__name__}")

        from sandbox.contain import is_admin  # noqa: PLC0415
        notes.append("管理员权限：有" if is_admin() else "管理员权限：无（真实封锁会拒绝执行）")
        return True, "；".join(notes)

    # ---------------------------------------------------------------- 执行
    def execute(self, action, ctx: ToolContext) -> ToolResult:
        name = action.name
        args = dict(getattr(action, "args", {}) or {})
        t0 = time.time()
        # 真做的前提：配置放行 + 执行器没在演练
        dry = bool(ctx.dry_run) or not bool(self.cfg.get("execute_enabled", False))

        try:
            if name == CAP_EXTRACT:
                res, obs, output = self._do_extract(args, ctx, dry)
            elif name == CAP_ANALYZE:
                res, obs, output = self._do_analyze(args, ctx, dry)
            elif name == CAP_HANDOFF:
                res, obs, output = self._do_handoff(args, ctx, dry)
            elif name == CAP_CONTAIN:
                res, obs, output = self._do_contain(args, ctx, dry)
            else:
                return ToolResult(
                    ok=False, action=name, adapter=self.name, status=STATUS_UNAVAILABLE,
                    error=f"本适配器不支持动作 {name}",
                    observations=(f"[不可用] {self.name} 不支持 {name}。"
                                  f"特别是 `detonate_payload`：AI 侧不存在这个能力，"
                                  f"动态分析必须由人工按交接包进行。"))
        except Exception as exc:  # noqa: BLE001  适配器不得吞异常，但要转成可见失败
            return ToolResult.failed(name, self.name,
                                     f"{type(exc).__name__}: {exc}")

        return ToolResult(
            ok=res.get("ok", False), action=name, adapter=self.name,
            status=res.get("status", STATUS_FAILED), output=output,
            observations=obs, error="" if res.get("ok") else res.get("detail", ""),
            latency_ms=int((time.time() - t0) * 1000), dry_run=dry,
        )

    # ------------------------------------------------------------ 各动作实现
    def _do_extract(self, args: Dict[str, Any], ctx: ToolContext,
                    dry: bool) -> Tuple[Dict[str, Any], str, Dict[str, Any]]:
        from sandbox.sandboxie import extract_to_vault  # noqa: PLC0415

        path = str(args.get("path", ""))
        case_id = str(args.get("case_id") or ctx.case_id or "")
        if not path:
            return ({"ok": False, "status": STATUS_DENIED, "detail": "缺少 path"},
                    "[拒绝] extract_payload 需要 path（要固化的载荷路径）。", {})

        if dry:
            return ({"ok": True, "status": STATUS_DRY_RUN,
                     "detail": f"演练：将把 {path} 复制进只读库（不改动原文件）"},
                    (f"[演练] 未固化和复制。计划：把 `{path}` 按字节复制进只读库，"
                     f"算 MD5/SHA-1/SHA-256，设只读属性，写 manifest.json。"
                     f"原文件保持不变（取证第一原则：先固定、不改现场）。"),
                    {"path": path, "dry_run": True})

        ex = extract_to_vault(path, self._config(), case_id=case_id)
        out = ex.to_dict()
        if not ex.ok:
            return ({"ok": False, "status": STATUS_FAILED, "detail": ex.detail},
                    f"[失败] 载荷固化未完成：{ex.detail}", out)

        # 报警：提取到攻击载荷是明确的事件，必须让人知道。
        notified = self._notify_extract(ex, case_id)
        out["notified"] = notified
        obs = (f"[完成] 载荷已固化到只读库：`{ex.vault_path}`"
               f"（SHA-256 `{ex.hashes.get('sha256', '')[:16]}…`，"
               f"{ex.hashes.get('size', 0)} 字节"
               + ("，已设只读" if ex.readonly else "，⚠ 只读属性设置失败") + "）。"
               f"原文件未被改动。已报警：{'是' if notified else '否'}。"
               f"下一步：analyze_payload 做静态分析；"
               f"动态分析需 prepare_dynamic_analysis 生成人工交接包。")
        return ({"ok": True, "status": STATUS_OK, "detail": ex.detail}, obs, out)

    def _do_analyze(self, args: Dict[str, Any], ctx: ToolContext,
                    dry: bool) -> Tuple[Dict[str, Any], str, Dict[str, Any]]:
        from sandbox.payload import analyse, render_markdown  # noqa: PLC0415
        from sandbox import case_dir  # noqa: PLC0415

        path = str(args.get("path", ""))
        if not path:
            return ({"ok": False, "status": STATUS_DENIED, "detail": "缺少 path"},
                    "[拒绝] analyze_payload 需要 path（要分析的文件；"
                    "建议传只读库里的镜像路径）。", {})

        if dry:
            return ({"ok": True, "status": STATUS_DRY_RUN,
                     "detail": f"演练：将对 {path} 做静态分析"},
                    (f"[演练] 未分析。计划对 `{path}` 做**静态**分析："
                     f"三份哈希、PE 结构（节区/熵/导入表/时间戳/overlay）、"
                     f"Authenticode 签名、字符串与可疑指标匹配。"
                     f"**不执行样本。**"),
                    {"path": path, "dry_run": True})

        rep = analyse(path, with_signature=True, with_strings=True)
        case_id = str(args.get("case_id") or ctx.case_id or "ad-hoc")
        out_dir = case_dir(case_id, self.cfg.get("root") or None)
        out_dir.mkdir(parents=True, exist_ok=True)
        md_path = out_dir / f"payload_report_{Path(path).stem[:40]}.md"
        json_path = out_dir / f"payload_report_{Path(path).stem[:40]}.json"
        md_path.write_text(render_markdown(rep), encoding="utf-8")
        json_path.write_text(rep.to_json(), encoding="utf-8")

        top = [h["why"] for h in (rep.anomalies or [])[:3]]
        top += [f"导入 {a['api']}" for a in (rep.api_hits or [])[:3]]
        top += [h["why"] for h in ((rep.indicators or {}).get("hits") or [])[:3]]
        obs = (f"[完成] 静态分析结束：{rep.file_type}，风险 **{rep.risk}**"
               f"（{rep.score}/100）。签名 {rep.signature.get('status', '未查')}。"
               + (f"主要指标：{'；'.join(top[:4])}。" if top else "未见明显指标。")
               + f" 报告：`{md_path}`。"
               "注意：静态分析看不到运行时行为，加壳样本尤其如此；"
               "**这不等于安全**。要动态行为请让人工按交接包执行。")
        return ({"ok": True, "status": STATUS_OK, "report_md": str(md_path),
                 "report_json": str(json_path), "risk": rep.risk, "score": rep.score},
                obs, rep.to_dict())

    def _do_handoff(self, args: Dict[str, Any], ctx: ToolContext,
                    dry: bool) -> Tuple[Dict[str, Any], str, Dict[str, Any]]:
        from sandbox.dynamic_handoff import build_handoff  # noqa: PLC0415
        from sandbox.sandboxie import verify_network_isolation  # noqa: PLC0415
        from sandbox import case_dir  # noqa: PLC0415
        from sandbox.payload import hashes  # noqa: PLC0415

        case_id = str(args.get("case_id") or ctx.case_id or "")
        path = str(args.get("path", ""))
        if not case_id:
            return ({"ok": False, "status": STATUS_DENIED, "detail": "缺少 case_id"},
                    "[拒绝] prepare_dynamic_analysis 需要 case_id。", {})
        if not path:
            path = self._find_vault_payload(case_id)
            if not path:
                return ({"ok": False, "status": STATUS_DENIED,
                         "detail": f"案例 {case_id} 没有已固化的载荷"},
                        (f"[拒绝] 案例 `{case_id}` 在只读库里找不到已固化的载荷。"
                         f"先执行 extract_payload，再进行人工动态分析的交接。"),
                        {})

        if dry:
            return ({"ok": True, "status": STATUS_DRY_RUN,
                     "detail": f"演练：将为 {case_id} 生成人工交接包"},
                    (f"[演练] 未生成文件。计划为案例 `{case_id}` 的载荷 `{path}` 生成："
                     f"`run_dynamic_analysis.cmd`（人工双击执行，纯 ASCII）、"
                     f"`HANDOFF.md`（中文操作手册，含观察重点与前置条件）、"
                     f"`handoff.json`（机器可读记录，`executed_by_ai=false`）。"),
                    {"case_id": case_id, "path": path, "dry_run": True})

        iso = verify_network_isolation(self._config())
        h = build_handoff(case_id, path, hashes(path),
                          case_dir(case_id, self.cfg.get("root") or None),
                          box_name=self.cfg.get("box_name", "BlueTeamDynamic"),
                          box_verified=iso.ok, verify_note=iso.detail)
        obs = (f"[完成] 人工动态分析交接包已生成：`{h.cmd_file}` 与 `{h.md_file}`。"
               f"**AI 不会执行它**（`executed_by_ai=false`；本模块结构上无法执行样本）。"
               f"断网验证：{iso.verdict} —— {iso.detail}"
               + ("" if iso.ok else "　⚠ 断网验证**未通过**：人工在验证通过前不应引爆样本。"))
        return ({"ok": True, "status": STATUS_OK, "handoff": h.to_dict(),
                 "net_isolation": iso.to_dict()}, obs, h.to_dict())

    def _do_contain(self, args: Dict[str, Any], ctx: ToolContext,
                    dry: bool) -> Tuple[Dict[str, Any], str, Dict[str, Any]]:
        from sandbox.contain import apply_contain, plan_contain  # noqa: PLC0415

        indicator = str(args.get("indicator", ""))
        if not indicator:
            return ({"ok": False, "status": STATUS_DENIED, "detail": "缺少 indicator"},
                    "[拒绝] contain_threat 需要 indicator（要封的 IP/域名/URL）。", {})

        plan = plan_contain(
            indicator,
            case_id=str(args.get("case_id") or ctx.case_id or ""),
            reason=str(args.get("reason", "")),
            ttl_seconds=int(args.get("ttl_seconds") or self.cfg.get("ttl_seconds", 14400)),
            allow_unverified=bool(self.cfg.get("allow_unverified_target", False)),
        )
        if not plan.will_block:
            res = apply_contain(plan, apply=False)
            obs = (f"[拒绝] 没有可执行的封锁目标（{indicator}）。"
                   f"原因：{'；'.join(i.reason for i in plan.refused) or '无法识别的 IOC'}"
                   f"　说明：{'；'.join(plan.notes)}")
            return ({"ok": False, "status": STATUS_DENIED, "detail": res.detail},
                    obs, res.to_dict())

        res = apply_contain(plan, apply=not dry)
        if dry:
            obs = (f"[演练] 未改防火墙。将新增 {len(plan.will_block)} 条**出向 Block** "
                   f"规则（TTL {plan.ttl_seconds // 60} 分钟）："
                   + "、".join(i.address for i in plan.will_block)
                   + f"。不影响业务的原因：{res.non_interference}")
        else:
            obs = (f"[完成] 封锁已生效并读回确认 {len(res.verified)} 条："
                   f"{'、'.join(res.verified) or '（无）'}，到期 {res.expires_at}。"
                   f"{res.non_interference}"
                   + (f"　失败：{res.errors[:2]}" if res.errors else ""))
        return (res.to_dict(), obs, res.to_dict())

    # ------------------------------------------------------------ 辅助
    def _find_vault_payload(self, case_id: str) -> str:
        """在只读库里按案例号找已固化的载荷（读 manifest.json）。"""
        vault = self._config().vault_path()
        if not vault.is_dir():
            return ""
        best = ""
        newest = 0.0
        for man in vault.glob("*/manifest.json"):
            try:
                d = json.loads(man.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if str(d.get("case_id", "")) != case_id:
                continue
            p = Path(str(d.get("vault_path", "")))
            if p.is_file() and p.stat().st_mtime >= newest:
                newest = p.stat().st_mtime
                best = str(p)
        return best

    def _notify_extract(self, ex, case_id: str) -> bool:
        """提取到攻击载荷后弹通知。失败不影响取证结果（只记录）。"""
        if not self.cfg.get("notify", True):
            return False
        try:
            from tools.win_notify import notify  # noqa: PLC0415
            sha = str(ex.hashes.get("sha256", ""))[:16]
            return bool(notify(
                "蓝队：已提取攻击载荷",
                f"案例 {case_id or '-'}　SHA-256 {sha}…\n"
                f"已固化到只读库，未执行该样本。\n"
                f"{ex.vault_path}",
                subtitle="只读固化 · 静态分析 · 动态分析需人工",
            ))
        except Exception as exc:  # noqa: BLE001
            print(f"[sandbox] 通知失败（不影响取证）：{exc}", file=sys.stderr)
            return False
