#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""security/sanitize.py — 日志与数据脱敏工具（规则 R1）。

设计要点：
  * 幂等：同一实体在一条文本内始终映射到同一个占位符（<IP_1>, <IP_2> ...）。
  * 可组合：`mask_text()` 用于纯文本，`mask_obj()` 用于嵌套 dict/list。
  * 可直接挂到 logging：`get_logger()` 返回的 logger 已装配 SanitizingFilter，
    任何 `logger.info("... %s", ip)` 都会在落盘前被脱敏。

仅依赖标准库。
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict

__all__ = [
    "mask_text",
    "mask_obj",
    "SanitizingFilter",
    "get_logger",
]

# --------------------------------------------------------------------------- #
# 正则定义
# --------------------------------------------------------------------------- #

_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
# 宽松 IPv6：至少两组冒号分隔的十六进制，或含 "::"
_IPV6_RE = re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_URL_CRED_RE = re.compile(r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.\-]*://)(?P<user>[^/\s:@]+):(?P<pwd>[^/\s@]+)@")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")
_BEARER_RE = re.compile(r"(?i)\b(?:bearer|token)\s+[A-Za-z0-9._\-]{12,}")
_HEX_SECRET_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")
# 常见云 / Git 平台密钥前缀
_PREFIX_SECRET_RE = re.compile(r"\b(?:sk|rk|pk|ghp|gho|ghs|ghu|glpat|xox[baprs])[-_][A-Za-z0-9\-_]{8,}\b")
_AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_KV_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|private[_-]?key)\b"
    r"\s*[:=]\s*([^\s,;\"'`]{3,})"
)

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# --- 豁免区（不得脱敏的机器可读标识）------------------------------------------
# 1) RFC5737 / RFC3849 文档专用地址：按定义不可能指向真实主机，遮了反而破坏
#    动作 JSON 的 src_ip 参数，使其过不了 action_schema 校验。
# 2) `sha256: <64hex>`：文件哈希是公开可分享的 IOC，不是凭据；被 HEX 规则遮掉会
#    使 quarantine_file 的 sha256 参数失效。
DOC_IP_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.", "127.0.0.1")
DOC_IPV6_PREFIXES = ("2001:db8:", "2001:0db8:")
_SHA256_KV_RE = re.compile(r'(?i)("?sha256"?\s*[:=]\s*"?)([0-9a-fA-F]{64})')
_PROTECT_TMPL = "\x00PROTECTED{}\x00"


class _Mapper:
    """为单条文本维护 实体 -> 占位符 的稳定映射（保证幂等）。"""

    def __init__(self) -> None:
        self._maps: Dict[str, Dict[str, str]] = {}
        self._counters: Dict[str, int] = {}

    def sub(self, kind: str, value: str) -> str:
        bucket = self._maps.setdefault(kind, {})
        if value not in bucket:
            self._counters[kind] = self._counters.get(kind, 0) + 1
            bucket[value] = f"<{kind}_{self._counters[kind]}>"
        return bucket[value]


def mask_text(text: Any, mask_ip: bool = True) -> str:
    """把文本中的敏感实体替换为占位符。

    Args:
        text: 任意对象，会先转成 str。
        mask_ip: 是否脱敏 IP。日志场景恒为 True；
                 数据预处理在需要保留网络拓扑语义时可置 False
                 （此时凭据/邮箱仍会被脱敏）。
    """
    if text is None:
        return ""
    s = _ANSI_RE.sub("", str(text))
    m = _Mapper()

    # 先把 sha256 值挖出来占位，最后再放回去（避免被 HEX 规则误遮）
    protected: Dict[str, str] = {}
    def _stash(match: "re.Match[str]") -> str:
        token = _PROTECT_TMPL.format(len(protected))
        protected[token] = match.group(2)
        return match.group(1) + token

    s = _SHA256_KV_RE.sub(_stash, s)

    # 顺序很重要：先处理带凭据的 URL，避免 user:pass 被当成 KV 密钥
    s = _URL_CRED_RE.sub(lambda x: f"{x.group('scheme')}<CRED>@", s)

    s = _EMAIL_RE.sub(lambda x: m.sub("EMAIL", x.group(0)), s)

    for kind, rx in (
        ("SECRET", _JWT_RE),
        ("SECRET", _BEARER_RE),
        ("SECRET", _PREFIX_SECRET_RE),
        ("SECRET", _AWS_KEY_RE),
    ):
        s = rx.sub(lambda x: m.sub(kind, x.group(0)), s)

    s = _KV_SECRET_RE.sub(
        lambda x: f"{x.group(1)}=<PASSWORD>" if x.group(1).lower() not in ("api_key", "api-key", "apikey")
        else f"{x.group(1)}=<SECRET>",
        s,
    )
    # 长十六进制（哈希/密钥）放在 KV 之后，避免误伤已被替换的内容
    s = _HEX_SECRET_RE.sub(lambda x: m.sub("SECRET", x.group(0)), s)

    if mask_ip:
        def _ipv4(x: "re.Match[str]") -> str:
            ip = x.group(0)
            # RFC5737 文档网段按定义不指向真实主机，遮了反而使动作 JSON 的
            # src_ip 参数过不了 action_schema 校验，因此原样保留。
            return ip if ip.startswith(DOC_IP_PREFIXES) else m.sub("IP", ip)

        def _ipv6(x: "re.Match[str]") -> str:
            ip = x.group(0)
            return ip if ip.lower().startswith(DOC_IPV6_PREFIXES) else m.sub("IP", ip)

        s = _IPV4_RE.sub(_ipv4, s)
        s = _IPV6_RE.sub(_ipv6, s)

    # 还原被保护的 sha256
    for token, value in protected.items():
        s = s.replace(token, value)

    return s


def mask_obj(obj: Any, mask_ip: bool = True) -> Any:
    """递归脱敏 dict / list / tuple / str。非容器类型原样返回。"""
    if isinstance(obj, str):
        return mask_text(obj, mask_ip=mask_ip)
    if isinstance(obj, dict):
        return {k: mask_obj(v, mask_ip=mask_ip) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return type(obj)(mask_obj(v, mask_ip=mask_ip) for v in obj)
    return obj


class SanitizingFilter(logging.Filter):
    """logging 过滤器：在消息渲染后统一脱敏（含 args 展开结果）。"""

    def __init__(self, mask_ip: bool = True) -> None:
        super().__init__()
        self.mask_ip = mask_ip

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        try:
            record.msg = mask_text(record.getMessage(), mask_ip=self.mask_ip)
            record.args = ()
        except Exception:  # 永不因为脱敏失败而丢日志/抛异常
            pass
        return True


def get_logger(name: str = "blue-team-agent", level: int = logging.INFO) -> logging.Logger:
    """获取已装配脱敏过滤器与统一格式的 logger（规则 R1 唯一入口）。"""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.addFilter(SanitizingFilter())
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(handler)
        logger.propagate = False
    logger.setLevel(level)
    return logger


if __name__ == "__main__":  # 自检
    demo = (
        "connect from 192.168.1.44:443 by admin@corp.local "
        "Bearer eyJhbGciOiJIUzI1NiJ9.abcdefgh.abcdefghijkl "
        "aws AKIAIOSFODNN7EXAMPLE password=Sup3rS3cret! "
        "https://user:pass@10.0.0.9/api sk-abcdef1234567890abcdef"
    )
    print(mask_text(demo))
    print(mask_text(demo))  # 幂等性：两次结果应一致
