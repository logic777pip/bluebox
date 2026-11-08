#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""intel/providers.py — 威胁情报 API 适配层。

设计原则（对应 security/SECURITY_RULES.md）：
  * **R2 超时 + 重试上限**：所有出站请求 connect/read 超时 + 指数退避 + 最大重试次数。
  * **R4 禁止硬编码凭据**：密钥只从环境变量读取；缺失则该 provider 直接标记为
    `unavailable` 并跳过（fail-closed），绝不内置默认 key。
  * **R1 日志脱敏**：日志统一走 security.sanitize。
  * **可离线**：`mock` provider 提供确定性合成响应，保证无网络/无 key 时也能跑通全链路与测试。

支持的真实 provider（均需自备 key，不随仓库分发）：
    abuseipdb   ABUSEIPDB_API_KEY      IP 信誉与滥用报告
    otx         OTX_API_KEY            AlienVault OTX 情报（pulses）
    virustotal  VIRUSTOTAL_API_KEY     文件/IP/域名多引擎检测
    threatfox   ABUSECH_AUTH_KEY       abuse.ch ThreatFox IOC
    ip_api      (无需 key)             仅地理/ASN 归属，低价值但可作上下文
    mock        (无需网络)             确定性合成，用于测试与离线开发

用法:
    python intel/providers.py --list
    python intel/providers.py --ioc 203.0.113.9 --providers mock
    python intel/providers.py --ioc 1.2.3.4 --providers abuseipdb,otx
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security.sanitize import get_logger, mask_text  # noqa: E402

LOG = get_logger("intel")

# R2：全局预算
TIMEOUT_SECONDS = 8
MAX_RETRIES = 3
BACKOFF_BASE = 1.0
# 单次进程内同一 IOC 的缓存，避免重复计费/触发限流
_CACHE: Dict[str, "IntelResult"] = {}


@dataclass
class IntelResult:
    provider: str
    ioc: str
    ioc_type: str
    status: str = "ok"                 # ok | not_found | unavailable | error
    verdict: str = "unknown"           # malicious | suspicious | benign | unknown
    confidence: float = 0.0            # 0..1，来源自报置信度（没有则 0）
    summary: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider, "ioc": self.ioc, "ioc_type": self.ioc_type,
            "status": self.status, "verdict": self.verdict,
            "confidence": self.confidence, "summary": self.summary,
            "details": self.details, "error": self.error,
        }


def classify_ioc(value: str) -> str:
    import re
    v = value.strip()
    if re.fullmatch(r"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)", v):
        return "ipv4"
    if re.fullmatch(r"[0-9a-fA-F]{64}", v):
        return "sha256"
    if re.fullmatch(r"[0-9a-fA-F]{32}", v):
        return "md5"
    if re.fullmatch(r"[0-9a-fA-F]{40}", v):
        return "sha1"
    if re.fullmatch(r"[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", v):
        return "domain"
    if v.lower().startswith(("http://", "https://")):
        return "url"
    return "unknown"


# --------------------------------------------------------------------------- #
#  HTTP 基础设施（R2）
# --------------------------------------------------------------------------- #

def _http_json(url: str, headers: Dict[str, str], data: Optional[bytes] = None,
               method: str = "GET") -> Dict[str, Any]:
    last: Optional[Exception] = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers=headers, data=data, method=method)
            with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            # 4xx 是确定性错误，重试无意义
            if 400 <= exc.code < 500:
                raise RuntimeError(f"HTTP {exc.code}") from exc
            last = exc
        except Exception as exc:  # noqa: BLE001
            last = exc
        if attempt < MAX_RETRIES:
            time.sleep(BACKOFF_BASE * (2 ** (attempt - 1)))
    raise RuntimeError(f"请求失败（已重试 {MAX_RETRIES} 次）: {mask_text(str(last))}")


def _require_env(name: str) -> Optional[str]:
    """R4：只从环境变量取密钥；缺失返回 None（调用方标 unavailable）。"""
    val = os.environ.get(name)
    return val if val and val.strip() else None


# --------------------------------------------------------------------------- #
#  Provider 实现
# --------------------------------------------------------------------------- #

def _mock(ioc: str, ioc_type: str) -> IntelResult:
    """确定性合成情报（离线测试用）。

    规则刻意做成可预测：RFC5737 文档网段 → benign；其余公网 IP → suspicious；
    哈希以字母开头 → malicious。这样单测与验收可以断言具体取值。
    """
    if ioc.startswith(("192.0.2.", "198.51.100.", "203.0.113.")):
        return IntelResult("mock", ioc, ioc_type, "ok", "benign", 0.9,
                           "RFC5737 文档专用网段，按定义不指向真实主机（示例占位）。",
                           {"note": "documentation-range"})
    if ioc_type == "ipv4":
        return IntelResult("mock", ioc, ioc_type, "ok", "suspicious", 0.55,
                           "合成情报：该地址在样例数据集中出现过可疑出站连接。",
                           {"first_seen": "2026-07-01", "tags": ["c2-candidate"]})
    if ioc_type in ("sha256", "md5", "sha1"):
        verdict = "malicious" if ioc[:1].isalpha() else "unknown"
        return IntelResult("mock", ioc, ioc_type, "ok", verdict, 0.7 if verdict == "malicious" else 0.0,
                           f"合成情报：样本判定 {verdict}。", {"family": "DemoStealer"})
    return IntelResult("mock", ioc, ioc_type, "not_found", "unknown", 0.0,
                       "合成情报：无该类型记录。", {})


def _abuseipdb(ioc: str, ioc_type: str) -> IntelResult:
    if ioc_type != "ipv4":
        return IntelResult("abuseipdb", ioc, ioc_type, "unavailable", "unknown", 0.0,
                           "该 provider 仅支持 IPv4。")
    key = _require_env("ABUSEIPDB_API_KEY")
    if not key:
        return IntelResult("abuseipdb", ioc, ioc_type, "unavailable", "unknown", 0.0,
                           "缺少环境变量 ABUSEIPDB_API_KEY（未配置则跳过，不内置默认密钥）。")
    url = ("https://api.abuseipdb.com/api/v2/check?"
           + urllib.parse.urlencode({"ipAddress": ioc, "maxAgeInDays": 90}))
    data = _http_json(url, {"Accept": "application/json", "Key": key})
    d = (data or {}).get("data", {})
    score = int(d.get("abuseConfidenceScore", 0))
    verdict = "malicious" if score >= 75 else "suspicious" if score >= 25 else "benign"
    return IntelResult("abuseipdb", ioc, ioc_type, "ok", verdict, score / 100.0,
                       f"滥用置信度 {score}/100，报告数 {d.get('totalReports', 0)}。",
                       {"country": d.get("countryCode"), "isp": d.get("isp"),
                        "usageType": d.get("usageType")})


def _otx(ioc: str, ioc_type: str) -> IntelResult:
    key = _require_env("OTX_API_KEY")
    if not key:
        return IntelResult("otx", ioc, ioc_type, "unavailable", "unknown", 0.0,
                           "缺少环境变量 OTX_API_KEY。")
    section = {"ipv4": "IPv4", "domain": "domain", "url": "url",
               "sha256": "file", "md5": "file", "sha1": "file"}.get(ioc_type)
    if not section:
        return IntelResult("otx", ioc, ioc_type, "unavailable", "unknown", 0.0, "不支持该 IOC 类型。")
    url = f"https://otx.alienvault.com/api/v1/indicators/{section}/{urllib.parse.quote(ioc)}/general"
    data = _http_json(url, {"X-OTX-API-KEY": key, "Accept": "application/json"})
    pulses: List[Dict[str, Any]] = (data or {}).get("pulse_info", {}).get("pulses", []) or []
    n = len(pulses)
    verdict = "malicious" if n >= 3 else "suspicious" if n >= 1 else "unknown"
    tags = sorted({t for p in pulses[:5] for t in (p.get("tags") or [])})[:8]
    return IntelResult("otx", ioc, ioc_type, "ok", verdict, min(1.0, n / 5.0),
                       f"命中 {n} 个情报 pulse。", {"pulse_count": n, "tags": tags})


def _virustotal(ioc: str, ioc_type: str) -> IntelResult:
    key = _require_env("VIRUSTOTAL_API_KEY")
    if not key:
        return IntelResult("virustotal", ioc, ioc_type, "unavailable", "unknown", 0.0,
                           "缺少环境变量 VIRUSTOTAL_API_KEY。")
    path = {"ipv4": f"ip_addresses/{ioc}", "domain": f"domains/{ioc}",
            "sha256": f"files/{ioc}", "md5": f"files/{ioc}", "sha1": f"files/{ioc}"}.get(ioc_type)
    if not path:
        return IntelResult("virustotal", ioc, ioc_type, "unavailable", "unknown", 0.0, "不支持该 IOC 类型。")
    data = _http_json(f"https://www.virustotal.com/api/v3/{path}", {"x-apikey": key})
    stats = ((data or {}).get("data", {}).get("attributes", {}) or {}).get("last_analysis_stats", {}) or {}
    bad = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
    total = sum(int(v) for v in stats.values()) or 1
    verdict = "malicious" if bad >= 5 else "suspicious" if bad >= 1 else "benign"
    return IntelResult("virustotal", ioc, ioc_type, "ok", verdict, min(1.0, bad / 10.0),
                       f"{bad}/{total} 引擎标记为恶意/可疑。", {"stats": stats})


def _threatfox(ioc: str, ioc_type: str) -> IntelResult:
    key = _require_env("ABUSECH_AUTH_KEY")
    if not key:
        return IntelResult("threatfox", ioc, ioc_type, "unavailable", "unknown", 0.0,
                           "缺少环境变量 ABUSECH_AUTH_KEY。")
    body = json.dumps({"query": "search_ioc", "search_term": ioc}).encode("utf-8")
    data = _http_json("https://threatfox-api.abuse.ch/api/v1/",
                      {"Auth-Key": key, "Content-Type": "application/json"},
                      data=body, method="POST")
    rows = (data or {}).get("data")
    if not isinstance(rows, list) or not rows:
        return IntelResult("threatfox", ioc, ioc_type, "not_found", "unknown", 0.0,
                           "ThreatFox 无该 IOC 记录。", {})
    first = rows[0] if isinstance(rows[0], dict) else {}
    return IntelResult("threatfox", ioc, ioc_type, "ok", "malicious", 0.7,
                       f"命中 {len(rows)} 条 IOC 记录，家族 {first.get('malware') or '未知'}。",
                       {"malware": first.get("malware"), "threat_type": first.get("threat_type"),
                        "first_seen": first.get("first_seen_utc")})


def _ip_api(ioc: str, ioc_type: str) -> IntelResult:
    """无需 key 的归属查询；只提供背景信息，**不作为恶意判定依据**。"""
    if ioc_type != "ipv4":
        return IntelResult("ip_api", ioc, ioc_type, "unavailable", "unknown", 0.0, "仅支持 IPv4。")
    data = _http_json(f"http://ip-api.com/json/{ioc}?fields=status,country,regionName,city,isp,org,as,proxy,hosting",
                      {"Accept": "application/json"})
    if (data or {}).get("status") != "success":
        return IntelResult("ip_api", ioc, ioc_type, "not_found", "unknown", 0.0, "查询失败。", {})
    return IntelResult("ip_api", ioc, ioc_type, "ok", "unknown", 0.0,
                       f"归属 {data.get('country')}/{data.get('city')}，ASN {data.get('as')}"
                       f"{'（代理/VPN）' if data.get('proxy') else ''}"
                       f"{'（托管商机房）' if data.get('hosting') else ''}。",
                       {"isp": data.get("isp"), "proxy": data.get("proxy"), "hosting": data.get("hosting")})


PROVIDERS: Dict[str, Callable[[str, str], IntelResult]] = {
    "mock": _mock,
    "abuseipdb": _abuseipdb,
    "otx": _otx,
    "virustotal": _virustotal,
    "threatfox": _threatfox,
    "ip_api": _ip_api,
}

DEFAULT_PROVIDERS = ["virustotal", "abuseipdb", "otx", "threatfox", "ip_api"]


# --------------------------------------------------------------------------- #
#  对外接口
# --------------------------------------------------------------------------- #

def query_ioc(ioc: str, providers: Optional[List[str]] = None,
              use_cache: bool = True) -> List[IntelResult]:
    """并发无关的顺序查询（保持可预测的日志顺序，便于审计）。"""
    ioc = (ioc or "").strip()
    if not ioc:
        return []
    ioc_type = classify_ioc(ioc)
    names = providers or DEFAULT_PROVIDERS

    results: List[IntelResult] = []
    for name in names:
        fn = PROVIDERS.get(name)
        if fn is None:
            LOG.warning("未知情报 provider: %s（可选 %s）", name, list(PROVIDERS))
            continue
        cache_key = f"{name}:{ioc_type}:{ioc.lower()}"
        if use_cache and cache_key in _CACHE:
            results.append(_CACHE[cache_key])
            continue
        try:
            res = fn(ioc, ioc_type)
        except Exception as exc:  # noqa: BLE001
            res = IntelResult(name, ioc, ioc_type, "error", "unknown", 0.0,
                              "查询异常。", {}, error=mask_text(str(exc)))
            LOG.warning("provider %s 查询失败: %s", name, res.error)
        _CACHE[cache_key] = res
        results.append(res)
        LOG.info("[intel] %-11s %-18s %-9s conf=%.2f", res.provider, res.ioc_type,
                 res.status, res.confidence)
    return results


def available_providers() -> Dict[str, bool]:
    """返回 provider -> 是否可用（含密钥检查），用于启动自检。"""
    out: Dict[str, bool] = {}
    for name in PROVIDERS:
        if name in ("mock", "ip_api"):
            out[name] = True
        elif name == "abuseipdb":
            out[name] = _require_env("ABUSEIPDB_API_KEY") is not None
        elif name == "otx":
            out[name] = _require_env("OTX_API_KEY") is not None
        elif name == "virustotal":
            out[name] = _require_env("VIRUSTOTAL_API_KEY") is not None
        elif name == "threatfox":
            out[name] = _require_env("ABUSECH_AUTH_KEY") is not None
    return out


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="威胁情报 API 查询")
    ap.add_argument("--ioc", default=None)
    ap.add_argument("--providers", default=None, help="逗号分隔，默认按优先级全试")
    ap.add_argument("--list", action="store_true", help="列出 provider 与可用性")
    args = ap.parse_args(argv)

    if args.list or not args.ioc:
        print("provider 可用性（缺失环境变量即不可用，不会内置默认密钥）：")
        for name, ok in available_providers().items():
            print(f"  {'[OK]' if ok else '[--]'} {name}")
        return 0

    names = [s.strip() for s in args.providers.split(",")] if args.providers else None
    results = query_ioc(args.ioc, names)
    print(json.dumps([r.to_dict() for r in results], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
