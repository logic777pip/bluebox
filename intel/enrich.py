#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""intel/enrich.py — 把情报查询结果整理成「可注入上下文」的紧凑块。

要点：
  * **带出处与置信度**：每条结论都标注 provider 与 confidence，模型必须能区分
    「某引擎判定恶意」与「未命中情报」。
  * **反「未命中即安全」**：显式写明「无记录 ≠ 安全」，避免模型把查询无结果
    表述成「该地址安全」——这是 CTI 场景最常见的一类幻觉。
  * **落地缓存**：按 IOC 缓存结果（默认 24h TTL），避免重复计费/触发限流。
  * **日志脱敏（R1）**：日志里只出现掩码后的 IOC；注入给模型的上下文保留原值
    （否则无法与本案观测做接地校验）。

用法:
    python intel/enrich.py --ioc 203.0.113.9 --providers mock
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from intel.providers import IntelResult, classify_ioc, query_ioc  # noqa: E402
from security.sanitize import get_logger, mask_text  # noqa: E402

LOG = get_logger("intel.enrich")

CACHE_PATH = PROJECT_ROOT / "logs" / "intel_cache.json"
CACHE_TTL_SECONDS = 24 * 3600

# verdict -> 严重度排序（聚合时取最高）
_SEVERITY = {"malicious": 4, "suspicious": 3, "unknown": 2, "benign": 1}
_VERDICT_ZH = {"malicious": "恶意", "suspicious": "可疑", "unknown": "未知", "benign": "良性"}


@dataclass
class IntelContext:
    iocs: List[str] = field(default_factory=list)
    records: List[IntelResult] = field(default_factory=list)
    text: str = ""
    queried_at: float = 0.0
    skipped: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "iocs": self.iocs,
            "records": [r.to_dict() for r in self.records],
            "queried_at": self.queried_at,
            "skipped": self.skipped,
        }


def _load_cache() -> Dict[str, Any]:
    if not CACHE_PATH.exists():
        return {}
    try:
        return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — 缓存损坏不应影响主流程
        LOG.warning("情报缓存损坏，将重建: %s", CACHE_PATH)
        return {}


def _save_cache(cache: Dict[str, Any]) -> None:
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CACHE_PATH.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")


def enrich(iocs: Sequence[str], providers: Optional[List[str]] = None,
           max_iocs: int = 6, use_disk_cache: bool = True) -> IntelContext:
    """查询并组装情报上下文。

    max_iocs 用于控制上下文长度与 API 配额：按原顺序截取，其余记入 skipped。
    """
    clean: List[str] = []
    seen: set[str] = set()
    for raw in iocs:
        v = (raw or "").strip()
        if not v or v in seen:
            continue
        if classify_ioc(v) == "unknown":
            continue
        seen.add(v)
        clean.append(v)

    ctx = IntelContext(queried_at=time.time())
    ctx.skipped = clean[max_iocs:]

    cache = _load_cache() if use_disk_cache else {}
    dirty = False

    for ioc in clean[:max_iocs]:
        ctx.iocs.append(ioc)
        for res in query_ioc(ioc, providers):
            # 磁盘缓存命中（按 provider+ioc 精确匹配）
            key = f"{res.provider}|{classify_ioc(ioc)}|{ioc.lower()}"
            if res.status == "unavailable":
                continue
            old = cache.get(key)
            if old and (time.time() - float(old.get("ts", 0))) < CACHE_TTL_SECONDS:
                try:
                    res = IntelResult(**{**old["result"]})
                except Exception:  # noqa: BLE001
                    pass
            else:
                cache[key] = {"ts": time.time(), "result": res.to_dict()}
                dirty = True
            ctx.records.append(res)

    if dirty:
        _save_cache(cache)

    ctx.text = render(ctx)
    LOG.info("情报富化完成: %d 个 IOC, %d 条结果（跳过 %d 个）",
             len(ctx.iocs), len(ctx.records), len(ctx.skipped))
    return ctx


def aggregate_verdict(records: Iterable[IntelResult]) -> str:
    """聚合多个 provider 的判定：取「有信息量」的最严重一档。

    注意：不能在初值就放 unknown —— unknown 的严重度（2）高于 benign（1），
    会导致「全部 provider 都判定良性」被错误地聚合成「未知」。
    因此只在存在非 unknown 的判定时参与比较；全部无信息才返回 unknown。
    """
    found = [r.verdict for r in records
             if r.status == "ok" and r.verdict in _SEVERITY and r.verdict != "unknown"]
    if not found:
        return "unknown"
    return max(found, key=lambda v: _SEVERITY.get(v, 0))


def render(ctx: IntelContext) -> str:
    """渲染为注入提示词的情报块。"""
    if not ctx.records:
        return ("【威胁情报检索结果】\n"
                "（未配置可用情报源或未提供 IOC。注意：**没有情报不等于安全**，"
                "不得据此得出「该指标安全」的结论。）")

    lines: List[str] = ["【威胁情报检索结果】", ""]
    by_ioc: Dict[str, List[IntelResult]] = {}
    for r in ctx.records:
        by_ioc.setdefault(r.ioc, []).append(r)

    for ioc, rs in by_ioc.items():
        agg = aggregate_verdict(rs)
        lines.append(f"- {ioc}（{classify_ioc(ioc)}）→ 综合判定：{_VERDICT_ZH.get(agg, agg)}")
        for r in rs:
            conf = f"{r.confidence:.2f}" if r.confidence else "n/a"
            note = r.summary or r.error or r.status
            lines.append(f"    · {r.provider}（{r.status}，confidence={conf}）：{note}")

    if ctx.skipped:
        lines.append(f"- （因配额限制未查询：{', '.join(ctx.skipped)}）")

    lines += [
        "",
        "约束：以上是**外部情报**，必须与本案观测交叉验证；",
        "引用时必须标注 provider 与置信度；对 status=unavailable/not_found 的来源，",
        "只能表述为「未获取到情报」，**严禁表述为「安全/无威胁」**。",
    ]
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="IOC 情报富化")
    ap.add_argument("--ioc", action="append", required=True, help="可重复传入")
    ap.add_argument("--providers", default="mock")
    ap.add_argument("--no-cache", action="store_true")
    args = ap.parse_args(argv)

    providers = [s.strip() for s in args.providers.split(",") if s.strip()]
    ctx = enrich(args.ioc, providers, use_disk_cache=not args.no_cache)
    print(ctx.text)
    print("\n[结构化]", json.dumps(ctx.to_dict(), ensure_ascii=False)[:600])
    # R1 演示：真实地址会被掩码；RFC5737/3849 文档网段是**有意豁免**的（不指向真实主机）
    demo = "".join(args.ioc) + " 8.8.8.8"
    LOG.info("日志脱敏示例: %s", mask_text(demo))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
