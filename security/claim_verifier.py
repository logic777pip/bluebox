#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""security/claim_verifier.py — **编造判据检测器**：回答里的事实是否真出自遥测。

为什么需要它（本项目最该抓的失败模式）
--------------------------------------

`grounding_check` 只能核对 **IOC 类指标**（IP/哈希/域名/CVE/路径）是否出自上下文。
但隐蔽信道评测实测出的失败是**另一类编造**：模型套用刚学到的「隐蔽信道模板」，
把遥测里根本不存在的**统计形状**说成存在。实证原文：

| 回答里的断言 | 遥测事实 | 性质 |
| --- | --- | --- |
| 「报文长度取值集中在少数几个档位」 | 14 个不同取值 | **编造判据** |
| 「各档占比接近均匀」 | 19.6% / 19.1% / 14.9% … / 1.1%（极偏斜） | **编造判据** |
| 「远小于正常交互流量的标准差」 | 遥测只给了均值 0.87 / 标准差 0.74，**没有基线** | **编造基线** |
| 「目标端口为常见但非典型 UDP 端口」 | 端口是 443（QUIC 标准端口） | **事实错误** |

这类编造比「说错 IP」更危险：它**看起来有据可依**，会直接把闸门引向误伤。

检查项
------

* `unsupported_numbers`   —— 回答里出现、遥测里没有的数值
* `shape_misread`         —— 把多档偏斜分布说成「少数档位 / 接近均匀」
* `baseline_invented`     —— 与遥测未给出的基线做「远小于/远超」比较
* `port_misread`          —— 把标准端口说成「非标准 / 非典型」
* `distinct_lengths`      —— 遥测里真实的长度取值档数（供核对）

用法::

    python security/claim_verifier.py --selftest
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security.asset_inventory import default_inventory  # noqa: E402
from security.sanitize import get_logger  # noqa: E402

LOG = get_logger("security.claim_verifier")

# 数值（含小数）；排除纯端口号误报：统一按「取值集合包含」判定
_NUM_RE = re.compile(r"\d+(?:\.\d+)?")
# 只有**带统计单位**的数字才算「关于遥测的断言」。
# 不这么收窄会大量假阳性：`T1571` 里的 1571、年份 2026、模型自选的 TTL 86400、
# 举例用的端口 65535 —— 它们都不是对遥测统计量的断言，不该被当成编造。
_NUM_UNIT_RE = re.compile(
    r"(\d+(?:\.\d+)?)\s*(%|B\b|字节|个|档|分钟|毫秒|ms\b|s\b|次|包)")
# 长度取值行：`报文长度取值：192B 占 24.0%、288B 占 26.5%…`
_LEN_LINE_RE = re.compile(r"报文长度取值[:：]\s*(.+)")
_LEN_PAIR_RE = re.compile(r"(\d+)\s*B\s*占\s*(\d+(?:\.\d+)?)\s*%")
_DEST_PORT_RE = re.compile(r"目标端口\s*(\d{1,5})")

_FEW_BUCKET_PHRASES = ("少数几个档位", "少数档位", "少数几个取值", "少数取值",
                       "少数几个长度", "几个档位", "取值集中", "集中在少数",
                       "局限在少数", "集中在几个")
_UNIFORM_PHRASES = ("接近均匀", "占比接近", "分布均匀", "占比均匀", "近似均匀", "基本均匀")
_BASELINE_PHRASES = ("远小于正常", "远大于正常", "远超正常", "远低于正常", "远高于正常",
                     "明显偏离正常基线", "远小于基线", "远超基线")
_NONSTANDARD_PHRASES = ("非标准端口", "非典型端口", "非常规端口", "非标准udp端口",
                        "常见但非典型", "不属于标准端口")

_FEW_BUCKET_MAX = 5          # 真实档数 > 此值时就不得称「少数几个档位」
_UNIFORM_SPREAD_MAX = 10.0   # 占比极差 > 此值（百分点）时就不得称「接近均匀」


@dataclass
class ClaimReport:
    telemetry_numbers: List[str] = field(default_factory=list)
    unsupported_numbers: List[str] = field(default_factory=list)
    distinct_lengths: int = 0
    length_spread: float = 0.0
    shape_misread: List[str] = field(default_factory=list)
    baseline_invented: List[str] = field(default_factory=list)
    port_misread: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not (self.unsupported_numbers or self.shape_misread
                    or self.baseline_invented or self.port_misread)

    @property
    def fabrications(self) -> List[str]:
        return self.shape_misread + self.baseline_invented + self.port_misread

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["ok"] = self.ok
        d["fabrications"] = self.fabrications
        return d


def _parse_length_stats(telemetry: str) -> tuple[int, float]:
    """从遥测里解析「报文长度取值」的档数与占比极差（百分点）。"""
    m = _LEN_LINE_RE.search(telemetry or "")
    if not m:
        return 0, 0.0
    pairs = _LEN_PAIR_RE.findall(m.group(1))
    if not pairs:
        return 0, 0.0
    pcts = [float(p) for _, p in pairs]
    return len(pairs), round(max(pcts) - min(pcts), 2)


def verify_claims(answer: str, telemetry: str,
                  inventory: Any = None) -> ClaimReport:
    """核对回答里的事实与判据是否真出自遥测。"""
    answer = answer or ""
    telemetry = telemetry or ""
    inv = inventory or default_inventory()

    t_nums = set(_NUM_RE.findall(telemetry))

    # 「遥测值」不能只看字面：极差 / 比值 是**合法推导**，不是编造。
    # 例：真实回答写「各档占比极差达 18.5 个百分点」——18.5 = 19.6 − 1.1，
    #    是正确计算。若不认推导值，判定器就会把诚实回答判成编造
    #    （本项目已因「判据过宽」栽过多次，这里宁可保守）。
    tvals = {float(x) for x in t_nums}
    derived = set()
    for a in tvals:
        for b in tvals:
            if a == b:
                continue
            derived.add(round(abs(a - b), 1))
            if b:
                derived.add(round(a / b, 1))
    supported = t_nums | {f"{d:g}" for d in derived}

    # 只核对**带单位**的数字（即真正在陈述统计量的那些）
    claimed = {m.group(1) for m in _NUM_UNIT_RE.finditer(answer)}
    unsupported = sorted(n for n in claimed - supported)

    distinct, spread = _parse_length_stats(telemetry)
    rep = ClaimReport(
        telemetry_numbers=sorted(t_nums),
        unsupported_numbers=unsupported,
        distinct_lengths=distinct,
        length_spread=spread,
    )

    low = answer.lower()
    if distinct > _FEW_BUCKET_MAX:
        for ph in _FEW_BUCKET_PHRASES:
            if ph in answer:
                rep.shape_misread.append(
                    f"称「{ph}」，但遥测里长度取值有 {distinct} 档")
                break
    if distinct >= 3 and spread > _UNIFORM_SPREAD_MAX:
        for ph in _UNIFORM_PHRASES:
            if ph in answer:
                rep.shape_misread.append(
                    f"称「{ph}」，但各档占比极差为 {spread} 个百分点（明显偏斜）")
                break

    for ph in _BASELINE_PHRASES:
        if ph in answer:
            rep.baseline_invented.append(f"「{ph}」——遥测未给出该基线，无法成立")
            break

    pm = _DEST_PORT_RE.search(telemetry)
    if pm:
        port = int(pm.group(1))
        if str(port) in inv.well_known_ports:
            for ph in _NONSTANDARD_PHRASES:
                if ph in low:
                    rep.port_misread.append(
                        f"称端口 {port} 为「{ph}」，但它是标准端口：{inv.port_note(port)}")
                    break
    return rep


# --------------------------------------------------------------------------- #
#  自检（用实测原文，锁住回归）
# --------------------------------------------------------------------------- #

_SKEWED_TELEMETRY = (
    "[NDR] 主机 db-229（192.0.2.39）与 203.0.113.216:443 之间存在持续 UDP 会话。\n"
    "目标端口 443。\n"
    "报文长度取值：105B 占 4.4%、167B 占 2.3%、263B 占 2.3%、383B 占 3.1%、565B 占 1.1%、"
    "678B 占 11.7%、926B 占 1.7%、1061B 占 14.9%、1118B 占 19.1%、1326B 占 19.6%。\n"
    "包间隔：均值 0.87s，标准差 0.74s。"
)
_FABRICATED_ANSWER = (
    "【研判结论】判定为噪声型隐蔽信道。\n"
    "1. 报文长度取值集中于少数几个档位，且各档占比接近均匀。\n"
    "2. 包间隔标准差仅为 0.74s，远小于正常交互流量。\n"
    "3. 目标端口为常见但非典型 UDP 端口。"
)
_HONEST_ANSWER = (
    "【研判结论】无充分证据判定为隐蔽信道。\n"
    "1. 长度取值有 10 档，各档占比极差达 18.5 个百分点，属偏斜分布，不符合人工塑形特征。\n"
    "2. 目标端口 443 是 QUIC 标准端口，无需特别处理。\n"
    "3. 不确定项：未获取到进程归属信息。"
)
# 必须**不**被当成编造的数字：ATT&CK 编号、年份、自选 TTL、举例端口
_SAFE_NUMBERS_ANSWER = (
    "【研判结论】疑似 T1571，建议 block_ip 带 ttl_seconds=86400（2026 年基准策略），"
    "举例端口 65535 不作为依据。包间隔均值 0.87s 与标准差 0.74s 已核实。"
)


def selftest() -> int:
    ok = total = 0

    def check(name: str, cond: bool, detail: str = "") -> None:
        nonlocal ok, total
        total += 1
        if cond:
            ok += 1
        print(f"  [{'ok  ' if cond else 'FAIL'}] {name}{(' — ' + detail) if detail and not cond else ''}")

    rep = verify_claims(_FABRICATED_ANSWER, _SKEWED_TELEMETRY)
    check("识别『少数档位』误读", any("少数" in s for s in rep.shape_misread), str(rep.shape_misread))
    check("识别『接近均匀』误读", any("均匀" in s for s in rep.shape_misread))
    check("识别『远小于正常』编造基线", bool(rep.baseline_invented))
    check("识别『443 非典型端口』事实错误", bool(rep.port_misread))
    check("编造回答整体判不通过", not rep.ok)
    check("档数解析正确(10)", rep.distinct_lengths == 10, str(rep.distinct_lengths))

    rep2 = verify_claims(_HONEST_ANSWER, _SKEWED_TELEMETRY)
    check("诚实回答判通过", rep2.ok, str(rep2.fabrications))
    check("诚实回答无编造数值", not rep2.unsupported_numbers, str(rep2.unsupported_numbers))

    # 回归：T1571 / 2026 / 86400 / 65535 这类数字不得被当成编造
    rep3 = verify_claims(_SAFE_NUMBERS_ANSWER, _SKEWED_TELEMETRY)
    check("ATT&CK 编号/年份/TTL/举例端口不算编造",
          not rep3.unsupported_numbers, str(rep3.unsupported_numbers))

    print(f"  {ok}/{total} 通过")
    return 0 if ok == total else 1


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="编造判据检测器")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--answer-file", default=None)
    ap.add_argument("--telemetry-file", default=None)
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    if args.answer_file and args.telemetry_file:
        import json
        a = Path(args.answer_file).read_text(encoding="utf-8")
        t = Path(args.telemetry_file).read_text(encoding="utf-8")
        print(json.dumps(verify_claims(a, t).to_dict(), ensure_ascii=False, indent=2))
        return 0
    ap.error("需要 --selftest，或同时提供 --answer-file 与 --telemetry-file")


if __name__ == "__main__":
    raise SystemExit(main())
