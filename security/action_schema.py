#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""security/action_schema.py — 模型输出 → 可执行动作 的 schema 校验与两阶段确认。

规则：
  R3 模型输出必须经过 schema 校验后才能执行任何动作。
  R5 不可逆操作必须两阶段确认。

默认拒绝（default-deny）：不在白名单内的动作名一律拒绝。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .sanitize import mask_text  # noqa: F401  (便于外部 `from action_schema import *`)

__all__ = [
    "SchemaError",
    "ConfirmationError",
    "Action",
    "validate_action",
    "parse_actions",
    "is_irreversible",
    "TwoPhaseGuard",
]

# --------------------------------------------------------------------------- #
# 动作白名单（蓝队防御动作）
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ActionSpec:
    required: Tuple[str, ...]
    optional: Tuple[str, ...] = ()
    irreversible: bool = False
    description: str = ""


# 按 PDCERF 应急响应模型分组：准备(P) / 检测(D) / 遏制(C) / 根除(E) / 恢复(R) / 复盘(F)
# 阶段归属、风险等级、目标参数等元数据在 actions/pdcerf.py（本表只做「能不能执行」的闸门）。
ACTION_SPECS: Dict[str, ActionSpec] = {
    # ---- 原有白名单（微调模型已训练，勿改名/勿删）----
    "query_logs": ActionSpec(("host_id", "query"), (), False, "查询主机/SIEM 日志"),
    "collect_forensics": ActionSpec(("host_id", "artifacts"), ("case_id",), False, "采集取证镜像/内存"),
    "notify_analyst": ActionSpec(("summary",), ("severity",), False, "通知值班分析员"),
    "close_case": ActionSpec(("case_id",), ("verdict",), True, "关闭事件工单"),
    "block_ip": ActionSpec(("src_ip",), ("direction", "ttl_seconds"), True, "封禁 IP（防火墙变更）"),
    "isolate_host": ActionSpec(("host_id",), ("mode", "case_id"), True, "网络隔离主机"),
    "kill_process": ActionSpec(("host_id", "pid"), ("reason",), True, "终止进程"),
    "quarantine_file": ActionSpec(("host_id", "path"), ("sha256",), True, "隔离文件"),
    "disable_account": ActionSpec(("account",), ("domain", "reason"), True, "禁用账号"),
    "restore_host": ActionSpec(("host_id",), ("snapshot_id",), True, "恢复主机（回滚）"),
    # ---- P 准备：资产可见性、回滚点、备份可用性、采集粒度 ----
    "asset_lookup": ActionSpec(("asset",), (), False, "查询资产台账与责任人"),
    "snapshot_host": ActionSpec(("host_id",), ("label",), False, "创建主机快照（回滚点）"),
    "verify_backup": ActionSpec(("host_id",), ("snapshot_id",), False, "校验备份可用性"),
    "raise_log_level": ActionSpec(("host_id",), ("scope",), False, "提升日志/遥测采集粒度"),
    # ---- D 检测：情报富化、流量、时间线、抓包 ----
    "enrich_ioc": ActionSpec(("indicator",), (), False, "IOC 情报富化"),
    "query_flow": ActionSpec(("host_id",), ("window_minutes",), False, "查询网络会话/流量"),
    "collect_timeline": ActionSpec(("case_id",), ("host_id",), False, "聚合事件时间线"),
    "capture_pcap": ActionSpec(("host_id", "duration_seconds"), (), False, "抓取流量包"),
    # ---- C 遏制：域名封禁、会话吊销、账号降权 ----
    "block_domain": ActionSpec(("domain",), ("ttl_seconds",), True, "封禁域名（DNS/出口）"),
    "revoke_session": ActionSpec(("account",), ("domain", "reason"), True, "吊销账号会话令牌"),
    "restrict_account": ActionSpec(("account",), ("domain", "reason"), True, "降权账号（最小权限）"),
    # ---- E 根除：清持久化、删恶意文件、轮换凭据、打补丁、重建 ----
    "remove_persistence": ActionSpec(("host_id", "mechanism"), ("path",), True, "清除持久化项"),
    "delete_file": ActionSpec(("host_id", "path"), ("sha256",), True, "删除恶意文件"),
    "reset_credential": ActionSpec(("account",), ("domain", "reason"), True, "强制轮换凭据"),
    "patch_vulnerability": ActionSpec(("host_id", "cve"), ("service",), True, "修补漏洞"),
    "rebuild_host": ActionSpec(("host_id",), ("image",), True, "从黄金镜像重建主机"),
    # ---- R 恢复：备份恢复、服务重启、解除隔离、完整性校验 ----
    "restore_from_backup": ActionSpec(("host_id", "snapshot_id"), (), True, "从备份恢复主机"),
    "restart_service": ActionSpec(("host_id", "service"), (), True, "重启服务"),
    "lift_isolation": ActionSpec(("host_id",), ("mode", "case_id"), True, "解除网络隔离"),
    "verify_integrity": ActionSpec(("host_id",), ("artifacts",), False, "完整性校验"),
    # ---- F 复盘：证据归档、复盘报告、检测规则、IOC 登记 ----
    "archive_evidence": ActionSpec(("case_id", "artifacts"), ("host_id",), False, "归档证据链"),
    "write_postmortem": ActionSpec(("case_id",), ("summary",), False, "生成复盘报告"),
    "update_detection_rule": ActionSpec(("rule_id", "rule"), (), True, "更新检测规则"),
    "publish_ioc": ActionSpec(("indicator",), ("ttl_seconds",), True, "登记/共享 IOC"),

    # ---- 沙箱与载荷（Sandboxie 联动）----
    # ⚠ 这里**刻意没有** `detonate_payload` / `run_payload` 之类的动作。
    # 需求是「禁止 AI 进行动态分析」—— 如果把它做成「有但默认关着」的动作，
    # 那么它随时可以被一个配置改动打开，约束就只剩文档效力。
    # 现在 AI 连「提出引爆请求」这件事都做不到：动作白名单里没有这个名字，
    # 模型即使写出来也会被 `validate_action` 直接拒绝（default-deny）。
    # 照应：`sandbox/sandboxie.py` 的 subprocess 调用有 vault 路径守卫，
    # 且 AST 自检确保该模块不存在载荷执行函数（结构上也做不到）。
    "extract_payload": ActionSpec(("host_id", "path"), ("sha256", "case_id"), False,
                                  "载荷镜像提取到只读沙箱库（复制不移动）"),
    "analyze_payload": ActionSpec(("path",), ("case_id", "artifacts"), False,
                                  "载荷静态取证分析（不执行样本）"),
    "prepare_dynamic_analysis": ActionSpec(("case_id",), ("path", "label"), False,
                                           "生成动态分析人工交接包（不执行样本）"),
    "contain_threat": ActionSpec(("host_id", "indicator"), ("ttl_seconds", "reason"), True,
                                 "最小影响封锁：只封精确对端的出向，带 TTL"),
}

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,127}$")
_INDICATOR_RE = re.compile(r"^[A-Za-z0-9._:/@+\[\]\-]{2,512}$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_PERSISTENCE_MECHANISMS = (
    "scheduled_task", "service", "registry_run", "cron",
    "startup", "ssh_authorized_key", "wmi_subscription", "all",
)
_PATH_RE = re.compile(r"^[A-Za-z0-9_\-./\\:][^\x00]{0,511}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class SchemaError(ValueError):
    """动作不符合 schema。"""


class ConfirmationError(RuntimeError):
    """两阶段确认失败（缺失 / 过期 / 不匹配 / 重放）。"""


@dataclass
class Action:
    name: str
    args: Dict[str, Any] = field(default_factory=dict)
    irreversible: bool = False
    rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def fingerprint(self) -> str:
        """动作的唯一指纹，用于确认 token 绑定（防止确认后被篡改）。"""
        payload = json.dumps(
            {"name": self.name, "args": self.args}, sort_keys=True, ensure_ascii=False
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def is_irreversible(name: str) -> bool:
    spec = ACTION_SPECS.get(name)
    return bool(spec and spec.irreversible)


# --------------------------------------------------------------------------- #
# 校验
# --------------------------------------------------------------------------- #

def _check_type(name: str, key: str, value: Any) -> Any:
    if key in ("pid",):
        if isinstance(value, str) and value.isdigit():
            value = int(value)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise SchemaError(f"{name}.{key} 必须是正整数，收到 {value!r}")
        return value
    if key == "ttl_seconds":
        if isinstance(value, str) and value.isdigit():
            value = int(value)
        if not isinstance(value, int) or isinstance(value, bool) or not (1 <= value <= 86400):
            raise SchemaError(f"{name}.{key} 必须是 1..86400 的整数秒")
        return value
    if key in ("artifacts",):
        if not isinstance(value, (list, tuple)) or not value:
            raise SchemaError(f"{name}.{key} 必须是非空字符串列表")
        return [str(v) for v in value]
    if key in ("host_id", "account", "domain", "case_id", "snapshot_id"):
        value = str(value)
        if not _ID_RE.match(value):
            raise SchemaError(f"{name}.{key} 含非法字符: {mask_text(value)!r}")
        return value
    if key in ("src_ip",):
        value = str(value)
        if not _ID_RE.match(value) and not re.match(r"^[0-9a-fA-F:.]+$", value):
            raise SchemaError(f"{name}.{key} 不是合法 IP/网段")
        return value
    if key in ("path",):
        value = str(value).strip()
        if not _PATH_RE.match(value) or ".." in Path(value).parts:
            raise SchemaError(f"{name}.{key} 路径非法或含目录穿越")
        return value
    if key in ("sha256",):
        value = str(value).strip().lower()
        if not _SHA256_RE.match(value):
            raise SchemaError(f"{name}.{key} 必须是 64 位十六进制")
        return value
    if key in ("mode",):
        value = str(value).lower()
        if value not in ("soft", "hard"):
            raise SchemaError(f"{name}.mode 只能是 soft|hard")
        return value
    if key in ("direction",):
        value = str(value).lower()
        if value not in ("inbound", "outbound", "both"):
            raise SchemaError(f"{name}.direction 只能是 inbound|outbound|both")
        return value
    if key in ("severity",):
        value = str(value).upper()
        if value not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            raise SchemaError(f"{name}.severity 只能是 LOW|MEDIUM|HIGH|CRITICAL")
        return value
    if key in ("verdict",):
        value = str(value).lower()
        if value not in ("true_positive", "false_positive", "benign"):
            raise SchemaError(f"{name}.verdict 只能是 true_positive|false_positive|benign")
        return value
    # ---- PDCERF 扩展动作的参数类型 ----
    if key in ("asset", "label"):
        value = str(value).strip()
        if not (1 <= len(value) <= 256) or "\x00" in value:
            raise SchemaError(f"{name}.{key} 长度必须在 1..256 且不含 NUL")
        return value
    if key == "indicator":
        value = str(value).strip()
        if not _INDICATOR_RE.match(value):
            raise SchemaError(f"{name}.indicator 不是合法 IOC（IP/域名/哈希/URL）: {mask_text(value)!r}")
        return value
    if key == "scope":
        value = str(value).lower()
        if value not in ("process", "network", "auth", "all"):
            raise SchemaError(f"{name}.scope 只能是 process|network|auth|all")
        return value
    if key == "window_minutes":
        if isinstance(value, str) and value.isdigit():
            value = int(value)
        if not isinstance(value, int) or isinstance(value, bool) or not (1 <= value <= 10080):
            raise SchemaError(f"{name}.{key} 必须是 1..10080 的整数分钟")
        return value
    if key == "duration_seconds":
        if isinstance(value, str) and value.isdigit():
            value = int(value)
        if not isinstance(value, int) or isinstance(value, bool) or not (1 <= value <= 3600):
            raise SchemaError(f"{name}.{key} 必须是 1..3600 的整数秒")
        return value
    if key == "mechanism":
        value = str(value).lower()
        if value not in _PERSISTENCE_MECHANISMS:
            raise SchemaError(f"{name}.mechanism 只能是 {'|'.join(_PERSISTENCE_MECHANISMS)}")
        return value
    if key in ("service", "rule_id", "image"):
        value = str(value)
        if not _ID_RE.match(value):
            raise SchemaError(f"{name}.{key} 含非法字符: {mask_text(value)!r}")
        return value
    if key == "cve":
        value = str(value).strip().upper()
        if not _CVE_RE.match(value):
            raise SchemaError(f"{name}.cve 必须是 CVE-YYYY-NNNN 形式")
        return value
    if key == "rule":
        value = str(value)
        if not (1 <= len(value) <= 4000) or "\x00" in value:
            raise SchemaError(f"{name}.rule 长度必须在 1..4000 且不含 NUL")
        return value
    if key in ("summary", "reason", "query"):
        value = str(value).strip()
        if not (1 <= len(value) <= 2000):
            raise SchemaError(f"{name}.{key} 长度必须在 1..2000")
        return value
    return value


def validate_action(raw: Any) -> Action:
    """把模型原始输出（dict 或 JSON 字符串）校验为 Action。

    默认拒绝：动作名不在白名单 / 缺字段 / 类型错 / 含未知字段，全部抛 SchemaError。
    """
    if isinstance(raw, (str, bytes)):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SchemaError(f"动作不是合法 JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise SchemaError(f"动作必须是 JSON 对象，收到 {type(raw).__name__}")

    name = str(raw.get("action") or raw.get("name") or "").strip().lower()
    if name not in ACTION_SPECS:
        raise SchemaError(f"动作不在白名单内: {name!r}（默认拒绝）")

    spec = ACTION_SPECS[name]
    args_in = raw.get("args") or raw.get("arguments") or {}
    if not isinstance(args_in, dict):
        raise SchemaError(f"{name}.args 必须是对象")

    missing = [k for k in spec.required if k not in args_in]
    if missing:
        raise SchemaError(f"{name} 缺少必填字段: {', '.join(missing)}")

    unknown = [k for k in args_in if k not in spec.required + spec.optional]
    if unknown:
        raise SchemaError(f"{name} 含未知字段（拒绝）: {', '.join(unknown)}")

    args: Dict[str, Any] = {k: _check_type(name, k, v) for k, v in args_in.items()}
    return Action(
        name=name,
        args=args,
        irreversible=spec.irreversible,
        rationale=str(raw.get("rationale", ""))[:500],
    )


def parse_actions(text: str) -> List[Action]:
    """从模型文本中提取一个或多个动作。

    期望格式：```action\\n{"action": ..., "args": {...}}\\n``` 或裸 JSON 行。
    非法项会被跳过（并返回给调用方决定是否计入失败率）。
    """
    candidates: List[str] = []
    for block in re.findall(r"```(?:action|json)?\s*(.+?)```", text, flags=re.S | re.I):
        candidates.append(block.strip())
    if not candidates:
        candidates = [ln.strip() for ln in text.splitlines() if ln.strip().startswith("{")]

    actions: List[Action] = []
    for cand in candidates:
        try:
            actions.append(validate_action(cand))
        except SchemaError:
            continue
    return actions


# --------------------------------------------------------------------------- #
# 两阶段确认门（R5）
# --------------------------------------------------------------------------- #

class TwoPhaseGuard:
    """不可逆操作的两阶段确认。

    阶段一 `propose()`  → 落盘 pending 记录，返回 proposal_id（无确认能力）
    阶段二 `confirm()`  → 校验 HMAC token（绑定动作指纹、TTL、单次使用）
    """

    def __init__(
        self,
        pending_dir: Path,
        ttl_seconds: int = 300,
        secret: Optional[bytes] = None,
    ) -> None:
        self.pending_dir = Path(pending_dir)
        self.pending_dir.mkdir(parents=True, exist_ok=True)
        self.ttl = int(ttl_seconds)
        # 规则 R4：禁止硬编码；优先环境变量，缺省自动生成随机密钥（进程内有效）
        env_secret = os.environ.get("BLUE_TEAM_CONFIRM_SECRET")
        self._secret = secret or (env_secret.encode("utf-8") if env_secret else secrets.token_bytes(32))
        self._used: set[str] = set()

    # -- 内部 -- #
    def _sign(self, proposal_id: str, fingerprint: str, expires_at: int) -> str:
        msg = f"{proposal_id}:{fingerprint}:{expires_at}".encode("utf-8")
        return hmac.new(self._secret, msg, hashlib.sha256).hexdigest()

    def _path(self, proposal_id: str) -> Path:
        if not re.match(r"^[0-9a-f]{16}$", proposal_id):
            raise ConfirmationError("proposal_id 非法")
        return self.pending_dir / f"{proposal_id}.json"

    # -- 阶段一 -- #
    def propose(self, action: Action, case_id: str = "") -> Tuple[str, Dict[str, Any]]:
        """登记待确认动作。返回 (proposal_id, 审计记录)。"""
        proposal_id = secrets.token_hex(8)
        now = int(time.time())
        record = {
            "proposal_id": proposal_id,
            "created_at": now,
            "expires_at": now + self.ttl,
            "status": "pending",
            "case_id": case_id,
            "action": action.to_dict(),
            "fingerprint": action.fingerprint(),
        }
        self._path(proposal_id).write_text(
            json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return proposal_id, record

    # -- 阶段二 -- #
    def confirm(self, proposal_id: str, provided_signature: str, action: Action) -> Dict[str, Any]:
        """校验确认签名。返回审计记录；任一环节失败抛 ConfirmationError。"""
        path = self._path(proposal_id)
        if not path.exists():
            raise ConfirmationError("proposal 不存在")
        if proposal_id in self._used:
            raise ConfirmationError("该确认已被使用（拒绝重放）")

        record = json.loads(path.read_text(encoding="utf-8"))
        if int(time.time()) > int(record["expires_at"]):
            raise ConfirmationError("确认已过期")
        if record["fingerprint"] != action.fingerprint():
            raise ConfirmationError("动作在确认前后被篡改，拒绝执行")
        if not hmac.compare_digest(
            self._sign(proposal_id, record["fingerprint"], int(record["expires_at"])),
            str(provided_signature),
        ):
            raise ConfirmationError("确认签名不匹配")

        self._used.add(proposal_id)
        record["status"] = "confirmed"
        record["confirmed_at"] = int(time.time())
        path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
        return record

    def expected_signature(self, proposal_id: str, action: Action) -> str:
        """离线/人工确认场景：由策略引擎或人工用同一密钥计算并回填。"""
        path = self._path(proposal_id)
        record = json.loads(path.read_text(encoding="utf-8"))
        return self._sign(proposal_id, action.fingerprint(), int(record["expires_at"]))
