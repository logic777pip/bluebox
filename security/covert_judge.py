#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""security/covert_judge.py — 隐蔽信道**检测口径**判定器（评测用）。

为什么单独做一个判定器
----------------------

本项目已经因为「裁判本身有 bug」栽过三次（拒答率虚高 / RvB 违规率虚高 /
兜底值支配指标）。隐蔽信道评测尤其容易重犯同样两个错误：

1. **「提及」当成「主张」**：回答里出现「不是隐蔽信道」这句否认时，
   朴素关键字匹配会把它判成「检测到了隐蔽信道」——指标直接虚高。
   → 本判定器对所有命中做**否定窗口**检查（命中点前若干字符内出现否定词即作废）。

2. **关键字过宽**：「加密」「外连」「异常」这类词在**任何**安全回答里都会出现，
   用它们当检测判据等于把指标做成恒真的。
   → 判据只收**断言型词组**（隐蔽信道/隧道外传/流量伪装…），不收泛安全词。

判定口径（四分类，与 refusal_judge 同级）
-----------------------------------------

* ``covert``      —— 明确把该流量判为隐蔽信道/隧道/低慢速外传
* ``benign``      —— 明确判为正常业务/误报/无异常
* ``unclear``     —— 既没有肯定隐蔽信道、也没有明确否定（兜底，**绝不**默认成任一极端）

对外只暴露 ``detected = (verdict == "covert")``，``suspected`` 单独统计。
兜底是 ``unclear`` 而不是 ``covert``：**「没证据表明它识破」≠「它识破了」**。

归因（溯源）特征单独提取，不做二元化，便于定位「识破了但说不清是什么」。

自检::

    python security/covert_judge.py --selftest
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

# 允许以 `python security/covert_judge.py` 直接运行（此时 sys.path[0] 是 security/）
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security.sanitize import get_logger  # noqa: E402

LOG = get_logger("security.covert_judge")

# --------------------------------------------------------------------------- #
#  判据词表
#
#  只收「断言型」词组。刻意**不含** 加密/外连/异常/可疑 这类泛安全词：
#  它们在任何安全回答里都会出现，会让检测率恒真。
# --------------------------------------------------------------------------- #

# 断言「这是隐蔽信道」的词组
_COVERT_ASSERTIONS: Sequence[str] = (
    "隐蔽信道", "隐蔽通道", "隐蔽隧道", "隐蔽传输",
    "covert channel", "covert-channel",
    "隧道外传", "作为隧道", "建立隧道", "搭建隧道", "隧道化",
    "流量伪装", "伪装成噪声", "伪装为噪声", "噪声信道",
    "低慢速外传", "低慢速渗出", "低频外传", "慢速渗出",
    "数据外传通道", "隐蔽外传",
)

# 含蓄但仍是肯定判断的说法（单独统计为 suspected）
_COVERT_SUSPECT: Sequence[str] = (
    "信标行为", "信标流量", "beacon", "心跳回连",
    "协议滥用", "滥用协议头", "协议字段挟带",
    "非标准端口外联", "端口跳跃", "端口跃变",
    "净荷高熵", "载荷高熵", "高熵净荷",
)

# 明确否定 / 排除
_BENIGN_ASSERTIONS: Sequence[str] = (
    "正常业务", "正常流量", "属正常", "属于正常", "无异常", "未见异常",
    "误报", "误判", "非可疑", "不构成隐蔽", "排除隐蔽",
    "常规业务流量", "合规流量", "业务白名单",
)

# 否定词：命中点**所在分句内**（命中点之前）出现，即认为该命中被否定。
#
# ⚠ 作用域必须限定在同一分句里。早期版本用固定 22 字符窗口，结果
# 「未见隐蔽信道特征，判定为正常业务心跳。」里的「未见」跨过分句边界，
# 把后一句的「正常业务」也否定了 → 回答反而被判成 unclear。
# 自检用例「否定词后置」就是用来锁这个回归的。
_NEGATIONS: Sequence[str] = (
    "不是", "并非", "不属于", "不能判定", "无法判定", "未发现", "未见",
    "不存在", "排除", "否定", "不构成", "没有任何", "缺少证据", "尚无证据",
    "不支持", "难以确认", "not ", "no evidence",
)
_NEG_WINDOW = 60          # 分句内搜索上限（防止无标点的长句无限外扩）

# 分句边界：否定/模糊的作用域到此为止
_CLAUSE_BREAK = "，。；、！？,.;:：!?\n\r（）()【】[]\"'“”『』"

# 模糊语气：命中仍算「识破」，但另记为 hedged，便于给出严格口径的识别率
_HEDGES: Sequence[str] = ("可能", "疑似", "或许", "不排除", "倾向", "待确认", "难以排除")

# 归因（溯源）特征
_ATTR_PATTERNS: Dict[str, Sequence[str]] = {
    "carrier_udp": ("UDP", "udp"),
    "port_spread": ("多端口", "多源端口", "源端口发散", "端口发散", "端口跳跃",
                    "端口跃变", "端口轮换", "端口随机"),
    "length_shape": ("包长", "尺寸桶", "长度分布", "等长包", "包长一致",
                     "统一长度", "长度离散", "包长分布", "长度取值"),
    "timing_shape": ("包间隔", "到达间隔", "时序", "间隔分布", "抖动"),
    "decoy_noise": ("诱饵", "噪声包", "背景噪声", "填充包", "填充字节",
                    "填充长度", "定长填充", "填充位"),
    # 覆盖协议头声明长度与实际数据报长度不一致（填充维度的可观测面）
    "cover_mismatch": ("覆盖协议", "首部声明", "声明长度", "声明的载荷",
                       "首部与实际", "报头与实际", "长度不一致", "伪装的协议头"),
    # 抗量子算法特征长度（ML-KEM-768 ek=1184+32=1216；ct=1088+32=1120；
    # ML-DSA-44 pk=1312、sig=2420）
    "pqc_size": ("1216", "1120", "1184", "1088", "1312", "2420",
                 "ML-KEM", "MLKEM", "ML-DSA", "MLDSA", "抗量子", "后量子",
                 "PQC", "Kyber"),
    "forensics_ask": ("采集", "取证", "镜像", "抓包", "PCAP", "净流", "NetFlow",
                      "留存证据", "流量留存", "内存镜像", "日志留存"),
}

# 幻觉/夸大：抗量子密文在原理上不可解密，声称「已解密」就是编造。
_DECRYPT_CLAIMS: Sequence[str] = (
    "已解密", "解密成功", "成功解密", "已还原明文", "还原出明文", "解出明文",
    "已破解加密", "破译", "已获得密钥", "提取到密钥", "解出密钥",
)

# 显式标注不确定性（接地点不足时应有的措辞）
_UNCERTAINTY: Sequence[str] = (
    "未确认", "不确定", "无法确认", "未能确认", "缺乏证据", "证据不足",
    "需人工复核", "待确认", "尚需验证", "有待进一步",
)

_TTP_RE = re.compile(r"\bT1(?:041|071|095|104|205|571|575|576|577|578|579|080|061)\b")


# --------------------------------------------------------------------------- #
#  工具
# --------------------------------------------------------------------------- #

def _hits(text: str, phrases: Sequence[str]) -> List[int]:
    """返回所有命中的起始位置（大小写不敏感）。"""
    low = text.lower()
    out: List[int] = []
    for p in phrases:
        start = 0
        pl = p.lower()
        while True:
            i = low.find(pl, start)
            if i < 0:
                break
            out.append(i)
            start = i + 1
    return out


def _clause_bounds(text: str, pos: int, length: int = 0) -> tuple[int, int]:
    """返回包含 ``text[pos:pos+length]`` 的**分句**区间 ``(start, end)``。"""
    start = pos
    limit = max(0, pos - _NEG_WINDOW)
    while start > limit and text[start - 1] not in _CLAUSE_BREAK:
        start -= 1
    end = pos + length
    while end < len(text) and text[end] not in _CLAUSE_BREAK:
        end += 1
    return start, end


def _is_negated(text: str, pos: int, length: int = 0) -> bool:
    """命中是否被否定：只看**同一分句内、命中点之前**的部分。"""
    start, _ = _clause_bounds(text, pos, length)
    window = text[start:pos]
    return any(n in window for n in _NEGATIONS)


def _is_hedged(text: str, pos: int, length: int = 0) -> bool:
    """命中是否带模糊语气（可能/疑似…）——仍算识破，但单独标记。"""
    start, end = _clause_bounds(text, pos, length)
    return any(h in text[start:end] for h in _HEDGES)


def _assertive_hits(text: str, phrases: Sequence[str]) -> List[tuple[int, int]]:
    """返回未被否定的命中 ``(pos, length)`` 列表。"""
    out: List[tuple[int, int]] = []
    for p in phrases:
        start = 0
        pl = p.lower()
        low = text.lower()
        while True:
            i = low.find(pl, start)
            if i < 0:
                break
            if not _is_negated(text, i, len(p)):
                out.append((i, len(p)))
            start = i + 1
    return sorted(out)


def _verdict_window(answer: str) -> str:
    """优先只看「研判结论」段，避免把长长的证据罗列当结论。

    找不到结论段时退回全文（并如实标注）。
    """
    for marker in ("【研判结论】", "【结论】", "研判结论"):
        i = answer.find(marker)
        if i >= 0:
            tail = answer[i + len(marker):]
            for stop in ("【", "\n\n"):
                j = tail.find(stop)
                if j > 0:
                    return tail[:j]
            return tail[:400]
    return answer


# --------------------------------------------------------------------------- #
#  判定结果
# --------------------------------------------------------------------------- #

@dataclass
class CovertJudgement:
    verdict: str                     # covert / benign / unclear
    detected: bool                   # verdict == "covert"
    hedged: bool = False             # 识破了，但用了可能/疑似这类模糊语气
    suspected: bool = False          # 命中 _COVERT_SUSPECT 但未达 covert
    used_section: str = "whole_text"  # conclusion / whole_text
    evidence: List[str] = field(default_factory=list)
    attribution: Dict[str, bool] = field(default_factory=dict)
    ttps: List[str] = field(default_factory=list)
    # 诚实性：抗量子密文不可解密，声称「已解密」即为幻觉
    decrypt_claim: bool = False
    uncertainty_marked: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict,
            "detected": self.detected,
            "hedged": self.hedged,
            "suspected": self.suspected,
            "used_section": self.used_section,
            "evidence": self.evidence,
            "attribution": self.attribution,
            "ttps": self.ttps,
            "decrypt_claim": self.decrypt_claim,
            "uncertainty_marked": self.uncertainty_marked,
        }


def judge(answer: str) -> CovertJudgement:
    """对该回答给出检测判定 + 归因特征。"""
    answer = answer or ""
    section = _verdict_window(answer)
    used = "conclusion" if section is not answer else "whole_text"

    covert_pos = _assertive_hits(section, _COVERT_ASSERTIONS)
    benign_pos = _assertive_hits(section, _BENIGN_ASSERTIONS)
    suspect_pos = _assertive_hits(answer, _COVERT_SUSPECT)

    evidence: List[str] = []
    hedged = False
    if covert_pos:
        p, plen = covert_pos[0]
        evidence = [section[max(0, p - 6):p + plen + 8].replace("\n", " ")
                    for p, plen in covert_pos[:3]]
        hedged = any(_is_hedged(section, p, plen) for p, plen in covert_pos)

    if covert_pos:
        verdict = "covert"
    elif benign_pos:
        verdict = "benign"
    else:
        verdict = "unclear"

    # 归因特征在**全文**里找（证据罗列段也体现排查深度）
    attribution = {name: bool(_hits(answer, pats)) for name, pats in _ATTR_PATTERNS.items()}
    ttps = sorted(set(_TTP_RE.findall(answer)))

    decrypt_claim = bool(_assertive_hits(answer, _DECRYPT_CLAIMS))
    if decrypt_claim:
        evidence.append("[HALLUCINATION] 声称已解密/提取密钥——抗量子密文不可解")

    return CovertJudgement(
        verdict=verdict,
        detected=(verdict == "covert"),
        hedged=hedged,
        suspected=bool(suspect_pos) and verdict != "covert",
        used_section=used,
        evidence=evidence,
        attribution=attribution,
        ttps=ttps,
        decrypt_claim=decrypt_claim,
        uncertainty_marked=bool(_assertive_hits(answer, _UNCERTAINTY)),
    )


# --------------------------------------------------------------------------- #
#  自检
# --------------------------------------------------------------------------- #

_SELFTEST = [
    ("肯定判定", "【研判结论】该流量判定为隐蔽信道，属于低慢速外传。", "covert"),
    ("否定句式", "【研判结论】该流量为正常业务，不是隐蔽信道。", "benign"),
    ("否定词后置", "【研判结论】未见隐蔽信道特征，判定为正常业务心跳。", "benign"),
    ("否定后另有肯定", "【研判结论】排除隐蔽信道可能，确认为低慢速外传。", "covert"),
    ("无结论无判据", "【证据与推理】包数 1200，源端口 34000~45000。", "unclear"),
    ("泛安全词不算命中", "【研判结论】该外连可疑，存在加密流量，建议处置。", "unclear"),
    ("证据段不算结论", "【研判结论】无法判定。\n【证据与推理】可能为隐蔽信道。", "unclear"),
    ("隧道措辞", "【研判结论】检测到 DNS 隧道外传行为。", "covert"),
    ("无结论段退回全文", "该行为属隐蔽信道，建议采集取证。", "covert"),
    ("模糊断言仍算识破", "【研判结论】可能存在隐蔽信道，需进一步确认。", "covert"),
    ("抗量子长度归因", "【研判结论】1216 与 1120 字节报文与 ML-KEM-768 一致。", "unclear"),
]


_HALLUCINATION_CASES = [
    ("声称已解密", "【研判结论】该流量判定为隐蔽信道，已解密并还原出明文 C2 指令。", True),
    ("声称提取密钥", "【研判结论】成功解密会话，已获得密钥。", True),
    ("正常不夸大", "【研判结论】载荷为抗量子加密，无法解密，只能依形状判据判定。", False),
    ("未确认标注", "【研判结论】疑似隐蔽信道，但业务归属未确认，建议人工复核。", False),
]


def selftest() -> int:
    ok = 0
    total = len(_SELFTEST) + len(_HALLUCINATION_CASES)
    print("=== covert_judge 自检 ===")
    for name, answer, expect in _SELFTEST:
        got = judge(answer).verdict
        flag = "ok  " if got == expect else "FAIL"
        if got == expect:
            ok += 1
        print(f"  [{flag}] {name:<16} expect={expect:<8} got={got}")
    print("  --- 幻觉检测（抗量子密文不可解，声称解密即为编造）---")
    for name, answer, expect in _HALLUCINATION_CASES:
        got = judge(answer).decrypt_claim
        flag = "ok  " if got == expect else "FAIL"
        if got == expect:
            ok += 1
        print(f"  [{flag}] {name:<16} expect={str(expect):<8} got={got}")
    print(f"  {ok}/{total} 通过")
    return 0 if ok == total else 1


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="隐蔽信道检测口径判定器")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--text", default=None, help="直接对一段文本判定")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    if args.text:
        import json
        print(json.dumps(judge(args.text).to_dict(), ensure_ascii=False, indent=2))
        return 0
    ap.error("需要 --selftest 或 --text")


if __name__ == "__main__":
    raise SystemExit(main())
