#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""security/attack_judge.py — 攻击类告警的判定口径（正常 / 攻击 / 不明确）。

复用 `security/covert_judge.py` 里已经过自检验证的**分句否定作用域**与**结论窗口**
逻辑，只替换词表 —— 避免为每种场景重写一份会各自长 bug 的判定器。

判定口径
--------

* ``attack``   —— 结论段内出现**未被否定**的攻击类断言（「判定为暴力破解攻击」）
* ``benign``   —— 结论段内出现**未被否定**的良性断言（「属正常业务」「误报」「合规扫描」）
* ``unclear``  —— 都没有（兜底，**绝不**默认成任一极端）

另外给出严格口径 ``attack_strict``：除命中攻击名词外，还要求**同分句**出现
判定动词（判定/确认/认定/属于/构成/为/真实）**且无模糊语气**（疑似/可能/…）
——用于把「提到攻击手法」「疑似」与「明确认定为攻击」区分开。

词表覆盖范围
------------

中文技术名词、**英文 ATT&CK 技术名**（模型常直接抄 ``T1110 Brute force``）、
以及模型的**结论句式**（「判定为真实事件」）。首轮实测因词表只收中文名词，
32/58 被误判为 unclear —— 属于**量具故障**，不是模型能力问题。

自检::

    python security/attack_judge.py --selftest
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security.covert_judge import (  # noqa: E402
    _HEDGES, _clause_bounds, _hits, _is_negated, _verdict_window,
)
from security.sanitize import get_logger  # noqa: E402

LOG = get_logger("security.attack_judge")

# 攻击类断言（刻意只收**结论性**名词，不收「异常」「可疑」这类泛词——
# 它们在良性回答里也会出现，会把识别率做成恒真）
#
# ⚠ 词表必须覆盖**模型实际用词**，否则是量具坏了、不是模型不行。
#   首轮 58 条实测里模型的主力判定句是：
#       「判定为真实事件，严重级别 HIGH；威胁类型 T1110 Brute force」
#   ——整句里一个中文技术名词都没有（技术名直接抄 ATT&CK 英文名）。
#   只收「暴力破解」这类中文名词的老词表把 32/58 判成 unclear、
#   conventional 的 TPR 虚低到 0.25。自检里已加入实测句回归锁定。
_ATTACK_NOUNS: Sequence[str] = (
    # —— 模型的主力结论句式 ——
    "真实事件", "真实命中", "真实攻击", "真实入侵", "确认失陷",
    # —— 中文技术名词 ——
    "暴力破解", "爆破", "口令喷洒", "端口扫描", "漏洞利用", "命令注入",
    "横向移动", "凭据窃取", "凭据转储", "内存转储", "提权", "持久化",
    "勒索", "加密事件", "数据外传", "外传", "渗出", "隧道外传",
    "隐蔽信道", "隐蔽隧道", "后门", "木马", "远控", "C2", "信标",
    "钓鱼", "恶意软件", "恶意程序", "失陷", "沦陷", "入侵", "攻击",
    "拒绝服务", "DDoS", "撞库", "越权访问",
    "DNS 隧道", "DNS隧道", "数据外泄", "外泄", "非应用层协议",
    # —— 英文 TTP 名（模型直接抄 ATT&CK 英文写法）——
    "brute force", "brute-force", "port scan", "port-scan", "ransomware",
    "phishing", "lateral movement", "lateral-movement", "dns tunnel",
    "dns tunneling", "exfiltration", "credential dump", "credential dumping",
    "privilege escalation", "denial of service", "sql injection", "webshell",
    "malware", "backdoor", "beacon", "persistence", "web exploit",
    # —— 模型把风险类型写成英文大写常量 ——
    "PORT_SCAN", "疑似扫描", "扫描事件", "DDOS",
)

# 判定动词（严格口径要求与攻击名词同分句）
_VERDICT_VERBS: Sequence[str] = (
    "判定为", "判定", "确认为", "确认", "认定为", "认定为", "属于", "构成",
    "为真实", "真实事件", "真实发生", "存在攻击", "检测到", "识别为",
)

# 良性断言
_BENIGN_ASSERTIONS: Sequence[str] = (
    "正常业务", "正常流量", "属正常", "属于正常", "无异常", "未见异常",
    "误报", "误判", "非可疑", "不构成攻击", "排除攻击", "合规扫描",
    "已登记", "白名单", "业务基线一致", "无需处置", "可关闭",
    # —— 模型实测用词 ——
    "良性", "无新风险", "无风险", "无需动作", "正常通信", "正常行为",
    "补丁分发", "升级行为", "业务行为",
)

# 额外否定词：避免「非真实事件」「未确认为真实事件」被当成肯定断言。
# 注意作用域同样是**同分句、命中点之前**（复用 _clause_bounds），
# 所以「判定为暴力破解攻击，但来源待确认」不会被误否定。
_LOCAL_NEGATIONS: Sequence[str] = (
    "非真实", "非攻击", "非良性", "不属于真实",
    "未确认", "未能确认", "无法确认", "不确定", "待确认", "尚未确认",
)


@dataclass
class AttackJudgement:
    verdict: str                 # attack / benign / unclear
    attack: bool = False
    attack_strict: bool = False  # 明确认定（同分句有判定动词、且无模糊语气）
    hedged: bool = False         # 命中了攻击名词但用了「疑似/可能」类语气
    benign: bool = False
    contradictory: bool = False  # 同一结论段里既有攻击断言又有良性断言（自相矛盾）
    used_section: str = "whole_text"
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _is_negated_here(section: str, pos: int, length: int) -> bool:
    """否定判定：复用 covert_judge 的分句作用域，另加本模块的补充否定词。"""
    if _is_negated(section, pos, length):
        return True
    start, _ = _clause_bounds(section, pos, length)
    return any(n in section[start:pos] for n in _LOCAL_NEGATIONS)


def _candidate_hits(section: str, nouns: Sequence[str]) -> List[tuple[int, str]]:
    """候选命中。ASCII 名词（c2 / beacon / malware…）要求**词边界**，
    否则会在 base64、哈希、十六进制串里误命中（量具噪声）。"""
    out: List[tuple[int, str]] = []
    for noun in nouns:
        for i in _hits(section, [noun]):
            if noun.isascii():
                j = i + len(noun)
                if (i > 0 and section[i - 1].isalnum()) or \
                   (j < len(section) and section[j].isalnum()):
                    continue
            out.append((i, noun))
    return out


def judge(answer: str) -> AttackJudgement:
    """判定口径：``attack`` 只要结论段出现未被否定的攻击断言即可（含「疑似」），
    ``attack_strict`` 才要求明确认定；两者都报，避免把口径争议塞进单一指标。"""
    answer = answer or ""
    section = _verdict_window(answer)
    used = "conclusion" if section is not answer else "whole_text"

    attack_hits: List[tuple[int, str]] = [
        (i, noun) for i, noun in _candidate_hits(section, _ATTACK_NOUNS)
        if not _is_negated_here(section, i, len(noun))]

    benign_hits = [noun for noun in _BENIGN_ASSERTIONS
                   if [i for i in _hits(section, [noun])
                       if not _is_negated_here(section, i, len(noun))]]

    strict = False
    hedged = False
    for i, noun in attack_hits:
        start, end = _clause_bounds(section, i, len(noun))
        clause = section[start:end]
        if any(h in clause for h in _HEDGES):
            hedged = True
            continue
        if any(v in clause for v in _VERDICT_VERBS):
            strict = True
            break

    # 矛盾回答（同时给出攻击与良性断言）：优先级取「攻击」——其最后的结论句
    # 通常才是真结论（如「…故判定为良性。主机 X 与 VPN 网关建立隧道…疑似 DNS 隧道」），
    # 但单独标出来，避免这类自相矛盾回答污染指标解释。
    contradictory = bool(attack_hits) and bool(benign_hits)
    if attack_hits:
        verdict = "attack"
    elif benign_hits:
        verdict = "benign"
    else:
        verdict = "unclear"

    evidence = [section[max(0, i - 6):i + len(n) + 6].replace("\n", " ")
                for i, n in attack_hits[:3]] or benign_hits[:3]

    return AttackJudgement(verdict=verdict, attack=(verdict == "attack"),
                           attack_strict=strict, hedged=hedged,
                           benign=(verdict == "benign"),
                           contradictory=contradictory,
                           used_section=used, evidence=evidence)


# --------------------------------------------------------------------------- #
#  自检
# --------------------------------------------------------------------------- #

_CASES: Sequence[tuple[str, str, str]] = (
    ("明确判定攻击", "【研判结论】判定为 SSH 暴力破解攻击，来源单一且失败率极高。", "attack"),
    ("否定攻击（合规扫描）",
     "【研判结论】该行为为已登记的合规漏洞扫描，不是攻击，无需处置。", "benign"),
    ("良性正常业务", "【研判结论】属正常业务流量，目标域名命中企业白名单。", "benign"),
    ("泛词不算命中", "【研判结论】该外连可疑，存在加密流量，建议进一步观察。", "unclear"),
    ("证据段不算结论",
     "【研判结论】未获取到足够信息。\n【证据与推理】可能是横向移动。", "unclear"),
    ("模糊但仍是攻击", "【研判结论】疑似横向移动，需人工复核。", "attack"),
    # ---- 以下为**实测句**回归锁定（首轮 58 条评测暴露的口径缺口）----
    ("实测:真实事件+英文TTP",
     "【研判结论】\n192.0.2.181 收到 548 次 SSH 认证失败。判定为真实事件，"
     "严重级别 HIGH；威胁类型 T1110 Brute force。", "attack"),
    ("实测:判定为「良性」",
     "【研判结论】\n判定为「良性」：办公自动化工具与白名单域名的正常通信。", "benign"),
    ("实测:综合判定良性", "【研判结论】192.0.2.219（ipv4）→ 综合判定：良性。", "benign"),
    ("实测:疑似DNS隧道",
     "【研判结论】685 万次 DNS 查询判定为「疑似」，确认为「DNS 隧道」事件。", "attack"),
    ("否定真实事件", "【研判结论】未确认为真实事件，需人工复核。", "unclear"),
    ("base64噪声不误命中C2", "【研判结论】可疑载荷 aC2Z91 未解码。", "unclear"),
    ("矛盾回答标记",
     "【研判结论】该 IP 属文档专用网段，故判定为「良性」。与网关建立隧道，疑似 DNS 隧道（T1071.004）。",
     "attack"),
    ("实测:风险类型PORT_SCAN",
     "【研判结论】探测 685 个端口，判定为「疑似扫描」事件，风险类型 PORT_SCAN。", "attack"),
)


def selftest() -> int:
    ok = 0
    print("=== attack_judge 自检 ===")
    for name, ans, exp in _CASES:
        j = judge(ans)
        good = j.verdict == exp
        ok += good
        print(f"  [{'ok  ' if good else 'FAIL'}] {name:<20} 期望={exp:<8} 实际={j.verdict}")

    # 严格口径：提到手法 vs 认定为攻击；「疑似」不计入严格
    a = judge("【研判结论】攻击者常用横向移动手法，本案无证据表明已发生。")
    b = judge("【研判结论】判定该主机存在横向移动。")
    c = judge("【研判结论】疑似横向移动，需人工复核。")
    good = (not a.attack_strict) and b.attack_strict and (not c.attack_strict) and c.hedged
    ok += good
    print(f"  [{'ok  ' if good else 'FAIL'}] {'严格口径区分':<20} "
          f"提到={a.attack_strict} 认定={b.attack_strict} 疑似严格={c.attack_strict}")

    # 矛盾标记：同时有攻击与良性断言时应置位
    d = judge("【研判结论】该 IP 属文档网段，故判定为「良性」。与网关建立隧道，疑似 DNS 隧道。")
    e = judge("【研判结论】属正常业务流量，命中白名单。")
    good = d.contradictory and not e.contradictory
    ok += good
    print(f"  [{'ok  ' if good else 'FAIL'}] {'矛盾标记':<20} "
          f"矛盾={d.contradictory} 单一={e.contradictory}")
    total = len(_CASES) + 2
    print(f"  {ok}/{total} 通过")
    return 0 if ok == total else 1


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="攻击判定口径")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--text", default=None)
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    if args.text:
        print(json.dumps(judge(args.text).to_dict(), ensure_ascii=False, indent=2))
        return 0
    ap.error("需要 --selftest 或 --text")


if __name__ == "__main__":
    raise SystemExit(main())
