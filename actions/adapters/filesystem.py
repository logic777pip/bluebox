#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""actions/adapters/filesystem.py — 沙箱文件适配器（证据归档 / 复盘报告 / 本地样本隔离）。

适用场景：
  没有 SOAR 时，至少让「证据链」与「复盘产物」真的落到磁盘上，且**无法逃出沙箱根目录**。
  契约（重要，避免语义漂移）：
    * `quarantine_file` / `delete_file` 只作用于**沙箱根目录内已存在的文件**；
      目标主机上的文件路径无法被本适配器直接操作——那种情况应由 SOAR/EDR 适配器处理。
      路径越界或文件不存在 → 如实失败，不做任何"假装成功"。
    * `archive_evidence` / `write_postmortem` / `collect_forensics` 生成真实的
      目录 + manifest（含 sha256），这是后续复核与交接的依据。

安全约束：
  R4 不涉及凭据；R5 由 ActionExecutor 负责（两阶段确认），本模块只做路径 jail。
"""

from __future__ import annotations

import hashlib
import json
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

from security.action_schema import Action
from security.sanitize import get_logger, mask_text

from .base import Adapter, ExecutionFailed, STATUS_OK, ToolContext, ToolResult

__all__ = ["FilesystemAdapter"]

LOG = get_logger("actions.fs")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class FilesystemAdapter(Adapter):
    """受限文件系统适配器（沙箱内）。"""

    name = "filesystem"
    real_effects = True

    def __init__(self, root: Path, enabled: bool = True) -> None:
        self.root = Path(root).resolve()
        self.enabled = bool(enabled)
        self.root.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    def capabilities(self) -> Set[str]:
        return {"quarantine_file", "delete_file", "collect_forensics",
                "archive_evidence", "write_postmortem"}

    def health(self) -> Tuple[bool, str]:
        if not self.enabled:
            return False, "适配器已禁用（actions/config.yaml: adapters.filesystem.enabled）"
        if not self.root.exists():
            return False, f"沙箱根不存在: {self.root}"
        return True, f"沙箱根 = {self.root}"

    # ------------------------------------------------------------------ #
    def _resolve(self, relative: str) -> Path:
        """把相对路径解析到沙箱内，越界直接拒绝。"""
        rel = str(relative).replace("\\", "/").lstrip("/")
        if not rel or rel.startswith("..") or "/../" in rel:
            raise ExecutionFailed(f"路径越界（拒绝）: {relative!r}")
        target = (self.root / rel).resolve()
        if target != self.root and self.root not in target.parents:
            raise ExecutionFailed(f"路径逃出沙箱（拒绝）: {relative!r}")
        return target

    def _case_dir(self, case_id: str) -> Path:
        safe = "".join(ch for ch in case_id if ch.isalnum() or ch in "._-") or "case"
        d = self._resolve(f"cases/{safe}")
        d.mkdir(parents=True, exist_ok=True)
        return d

    @staticmethod
    def _write_manifest(case_dir: Path, name: str, entries: List[Dict[str, Any]]) -> Path:
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "entries": entries,
        }
        path = case_dir / name
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    # ------------------------------------------------------------------ #
    def execute(self, action: Action, ctx: ToolContext) -> ToolResult:
        t0 = time.time()
        try:
            output, obs = getattr(self, f"_do_{action.name}")(action, action.args, ctx)
        except ExecutionFailed as exc:
            return ToolResult.failed(action.name, self.name, str(exc))
        except OSError as exc:
            return ToolResult.failed(action.name, self.name, f"文件系统错误: {exc}")
        return ToolResult(
            ok=True, action=action.name, adapter=self.name, status=STATUS_OK,
            output={**output, "sandbox_root": str(self.root)},
            observations=f"[本地沙箱] {obs}",
            latency_ms=int((time.time() - t0) * 1000),
        )

    # ------------------------------------------------------------------ #
    def _do_collect_forensics(self, action: Action, args: Dict[str, Any],
                              ctx: ToolContext) -> Tuple[Dict[str, Any], str]:
        case_dir = self._case_dir(str(args.get("case_id") or ctx.case_id or "case-unspecified"))
        host = str(args["host_id"])
        entries: List[Dict[str, Any]] = []
        for art in args["artifacts"]:
            rec = {"host_id": host, "artifact": str(art), "collected_at": time.time()}
            entries.append(rec)
        manifest = self._write_manifest(case_dir, f"forensics-{host}.json", entries)
        return (
            {"manifest": str(manifest.relative_to(self.root)), "items": entries},
            f"已在沙箱内为 {host} 登记 {len(entries)} 项取证产物 → "
            f"{manifest.relative_to(self.root)}。"
            f"（真实环境中此处应调用 EDR 的取证 API；本适配器只落盘登记，不谎称已取证。）",
        )

    def _do_quarantine_file(self, action: Action, args: Dict[str, Any],
                            ctx: ToolContext) -> Tuple[Dict[str, Any], str]:
        src = self._resolve(str(args["path"]))
        if not src.exists() or not src.is_file():
            raise ExecutionFailed(
                f"沙箱内不存在文件 {args['path']!r}（本适配器只处理沙箱内文件；"
                f"主机侧文件请交给 SOAR/EDR 适配器）"
            )
        digest = _sha256_file(src)
        declared = args.get("sha256")
        if declared and declared.lower() != digest:
            raise ExecutionFailed(
                f"哈希不匹配：调用方声明 {declared[:16]}… 实际 {digest[:16]}…；"
                f"拒绝隔离（可能指向了错误文件）"
            )
        case_dir = self._case_dir(str(ctx.case_id or "case-unspecified"))
        dest = case_dir / "quarantine" / src.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)          # 保留原件 → 可回溯
        (case_dir / "quarantine" / f"{src.name}.sha256").write_text(digest, encoding="utf-8")
        return (
            {"original": str(src.relative_to(self.root)),
             "quarantined_to": str(dest.relative_to(self.root)), "sha256": digest},
            f"已把 {src.relative_to(self.root)} 复制到隔离区并锁定 sha256={digest[:16]}…"
            f"（原件保留，未删除——取证需要样本）。",
        )

    def _do_delete_file(self, action: Action, args: Dict[str, Any],
                        ctx: ToolContext) -> Tuple[Dict[str, Any], str]:
        src = self._resolve(str(args["path"]))
        if not src.exists() or not src.is_file():
            raise ExecutionFailed(f"沙箱内不存在文件 {args['path']!r}")
        digest = _sha256_file(src)
        case_dir = self._case_dir(str(ctx.case_id or "case-unspecified"))
        vault = case_dir / "deleted" / src.name
        vault.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(vault))   # 移入案件保险箱而非物理抹除（可回溯）
        return (
            {"removed": str(src.relative_to(self.root)),
             "vaulted_to": str(vault.relative_to(self.root)), "sha256": digest},
            f"已从沙箱工作区移除 {src.relative_to(self.root)}"
            f"（移入案件保险箱 {vault.relative_to(self.root)}，可回溯）；sha256={digest[:16]}…",
        )

    def _do_archive_evidence(self, action: Action, args: Dict[str, Any],
                             ctx: ToolContext) -> Tuple[Dict[str, Any], str]:
        case_id = str(args["case_id"])
        case_dir = self._case_dir(case_id)
        entries: List[Dict[str, Any]] = []
        missing: List[str] = []
        for art in args["artifacts"]:
            p = self._resolve(str(art))
            if p.exists() and p.is_file():
                entries.append({"path": str(p.relative_to(self.root)),
                                "sha256": _sha256_file(p), "size": p.stat().st_size})
            else:
                missing.append(str(art))
        manifest = self._write_manifest(case_dir, "evidence-manifest.json", entries)
        if missing:
            # 部分缺失必须显式暴露，否则 manifest 会给人"全都归档了"的错觉
            (case_dir / "evidence-missing.txt").write_text("\n".join(missing), encoding="utf-8")
        msg = (f"证据链已归档 → {manifest.relative_to(self.root)}"
               f"（{len(entries)} 项，含 sha256）")
        if missing:
            msg += f"；⚠ {len(missing)} 项在沙箱内不存在，已记入 evidence-missing.txt：{', '.join(missing[:5])}"
        if args.get("host_id"):
            msg += f"（涉及主机 {args['host_id']}）"
        return ({"manifest": str(manifest.relative_to(self.root)),
                 "archived": len(entries), "missing": missing}, msg)

    def _do_write_postmortem(self, action: Action, args: Dict[str, Any],
                             ctx: ToolContext) -> Tuple[Dict[str, Any], str]:
        case_id = str(args["case_id"])
        case_dir = self._case_dir(case_id)
        path = case_dir / "postmortem.md"
        summary = str(args.get("summary", "")).strip()
        body = [
            f"# 事件复盘 {case_id}",
            "",
            f"- 生成时间：{datetime.now(timezone.utc).isoformat()}",
            f"- 处置阶段（PDCERF）：{ctx.phase}",
            "",
            "## 摘要",
            "",
            summary or "（未提供摘要 —— 需人工补全根因、时间线与改进项）",
            "",
            "## 待补全清单",
            "",
            "- [ ] 根因与攻击链（含 ATT&CK 技术编号）",
            "- [ ] 检测盲区与绕过路径",
            "- [ ] 处置有效性（哪些动作真正阻断了攻击）",
            "- [ ] 误伤与业务影响",
            "- [ ] 改进项、责任人与截止时间",
        ]
        path.write_text("\n".join(body) + "\n", encoding="utf-8")
        return (
            {"postmortem": str(path.relative_to(self.root))},
            f"复盘报告骨架已写入 {path.relative_to(self.root)}"
            + ("（含摘要）" if summary else "（摘要为空，需人工补全）"),
        )


def sanitize_note(text: str) -> str:
    """日志用：脱敏后返回（R1）。"""
    return mask_text(text)
