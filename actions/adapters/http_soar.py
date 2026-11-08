#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""actions/adapters/http_soar.py — 通用 SOAR / EDR / 防火墙 HTTP 适配器。

这是「接真实环境」的唯一入口：把校验通过的动作 POST 给外部编排平台
（SOAR、EDR API、防火墙管理面、IAM 接口……），由对方真正落地。

约定（对应仓库安全规则）：
  R2  超时 + 重试上限；**只对幂等动作重试**（GET 语义的检索类），写操作一律不自动重试
      —— 否则「封禁失败」会被重试成「重复封禁」，并在两阶段确认之外产生额外副作用。
  R4  密钥只从环境变量读（`api_key_env` 指定变量名），缺密钥即不可用（fail-closed），
      绝不内置默认凭据。
  R5  本适配器**不做**确认校验；到达这里的动作已经被 ActionExecutor 放行。

请求契约（对接方按此实现即可）：
    POST {base_url}/{prefix}/{action_name}
    Authorization: Bearer <env 中的密钥>        （require_api_key=false 时可省）
    Content-Type: application/json
    {"action": "isolate_host", "args": {...}, "case_id": "...", "phase": "C", "dry_run": false}

响应契约（二选一）：
    {"ok": true,  "observations": "...", "output": {...}}
    {"ok": false, "error": "..."}     → 适配器返回 STATUS_FAILED
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from security.action_schema import Action
from security.sanitize import get_logger, mask_text

from .base import Adapter, ExecutionFailed, STATUS_OK, ToolContext, ToolResult

__all__ = ["HttpSoarAdapter"]

LOG = get_logger("actions.soar")

# 默认的幂等动作（可安全重试）
_DEFAULT_IDEMPOTENT = (
    "query_logs", "query_flow", "asset_lookup", "enrich_ioc", "verify_backup",
    "verify_integrity", "collect_timeline",
)


class HttpSoarAdapter(Adapter):
    name = "soar"
    real_effects = True

    def __init__(self, cfg: Dict[str, Any]) -> None:
        self.enabled = bool(cfg.get("enabled", False))
        self.base_url = str(cfg.get("base_url", "")).rstrip("/")
        self.prefix = str(cfg.get("prefix", "actions")).strip("/")
        self.api_key_env = str(cfg.get("api_key_env", "SOAR_API_KEY"))
        self.require_api_key = bool(cfg.get("require_api_key", True))
        self.timeout = int(cfg.get("timeout", 15))
        self.retries = int(cfg.get("retries", 2))
        self.verify_tls = bool(cfg.get("verify_tls", True))
        self.extra_headers: Dict[str, str] = dict(cfg.get("headers", {}) or {})
        idem = cfg.get("idempotent_actions") or list(_DEFAULT_IDEMPOTENT)
        self.idempotent: Set[str] = {str(x) for x in idem}
        caps = cfg.get("capabilities")
        # capabilities 未配置时：声明支持全部（由编排平台自己拒绝不支持的动作）
        self._caps: Optional[Set[str]] = {str(x) for x in caps} if caps else None

    # ------------------------------------------------------------------ #
    def capabilities(self) -> Set[str]:
        if self._caps is not None:
            return self._caps
        import sys
        from pathlib import Path
        root = Path(__file__).resolve().parents[2]
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
        from security.action_schema import ACTION_SPECS  # noqa: PLC0415
        return set(ACTION_SPECS)

    def health(self) -> Tuple[bool, str]:
        if not self.enabled:
            return False, "适配器未启用（actions/config.yaml: adapters.soar.enabled=false）"
        if not self.base_url:
            return False, "未配置 base_url"
        if not self.base_url.startswith(("http://", "https://")):
            return False, f"base_url 必须以 http(s):// 开头，收到 {self.base_url!r}"
        if self.require_api_key and not self._api_key():
            return False, f"缺少环境变量 {self.api_key_env}（R4：不内置默认密钥）"
        return True, f"endpoint = {self.base_url}/{self.prefix}"

    def _api_key(self) -> str:
        import os
        return os.environ.get(self.api_key_env, "")

    # ------------------------------------------------------------------ #
    def _post(self, action: Action, ctx: ToolContext) -> Dict[str, Any]:
        url = f"{self.base_url}/{self.prefix}/{action.name}"
        body = json.dumps({
            "action": action.name,
            "args": action.args,
            "rationale": action.rationale,
            "case_id": ctx.case_id,
            "phase": ctx.phase,
            "dry_run": bool(ctx.dry_run),
        }, ensure_ascii=False).encode("utf-8")

        headers = {"Content-Type": "application/json", **self.extra_headers}
        key = self._api_key()
        if key:
            headers["Authorization"] = f"Bearer {key}"

        last_err = ""
        # R2：只有幂等动作才重试
        attempts = (self.retries + 1) if action.name in self.idempotent else 1
        for attempt in range(attempts):
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                    raw = resp.read().decode("utf-8", errors="replace")
                try:
                    return json.loads(raw) if raw.strip() else {"ok": True}
                except json.JSONDecodeError:
                    return {"ok": True, "observations": mask_text(raw[:2000])}
            except urllib.error.HTTPError as exc:
                detail = ""
                try:
                    detail = mask_text(exc.read().decode("utf-8", errors="replace")[:500])
                except Exception:  # noqa: BLE001
                    pass
                # 4xx 是调用方问题，重试无意义
                if 400 <= exc.code < 500:
                    raise ExecutionFailed(f"SOAR 返回 HTTP {exc.code}: {detail}") from exc
                last_err = f"HTTP {exc.code}: {detail}"
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_err = f"{type(exc).__name__}: {exc}"
            if attempt < attempts - 1:
                LOG.warning("SOAR 调用失败（第 %d/%d 次），%.1fs 后重试：%s",
                            attempt + 1, attempts, 1.0 * (2 ** attempt), mask_text(last_err))
                time.sleep(1.0 * (2 ** attempt))  # 指数退避

        raise ExecutionFailed(f"SOAR 调用失败（已尝试 {attempts} 次）：{last_err}")

    # ------------------------------------------------------------------ #
    def execute(self, action: Action, ctx: ToolContext) -> ToolResult:
        t0 = time.time()
        payload = self._post(action, ctx)
        latency = int((time.time() - t0) * 1000)
        if not payload.get("ok", True):
            return ToolResult(
                ok=False, action=action.name, adapter=self.name, status="failed",
                error=str(payload.get("error", "后端报告失败")),
                observations=str(payload.get("observations", "")) or "SOAR 报告该动作未成功。",
                latency_ms=latency,
            )
        return ToolResult(
            ok=True, action=action.name, adapter=self.name, status=STATUS_OK,
            output=dict(payload.get("output", {}) or {}),
            observations=str(payload.get("observations", "")) or "SOAR 已受理并执行。",
            latency_ms=latency,
        )


def describe_endpoints(adapters: Sequence[Adapter]) -> List[Dict[str, Any]]:
    return [a.describe() for a in adapters]
