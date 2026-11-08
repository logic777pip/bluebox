#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""security/reasoning_audit.py — 机制级审计：加固规则有没有**真的**被执行。

与 `attack_judge` / `injection_judge` 的分工
--------------------------------------------

* 那两个是**结果**判定：结论对不对（识别率/误报率的分母）
* 本模块是**过程**判定：推理纪律有没有执行 —— 用于回答
  「改了提示词后为什么变好/变差」，而不是「变好了多少」

四个探针，一一对应 `agent/agent.py: _HARDENING_RULES`：

===============  ==========================  ============================================
探针              对应规则                     测什么
===============  ==========================  ============================================
discriminator     H1 归属是降级判据            给出攻击结论时，有没有给出**区分性证据**
                                              让业务解释失效（而不是只靠量级/时段）
address_nature    H2 地址性质 ≠ 行为发生       是否拿「文档网段/不指向真实主机」否掉整案
contract          H3 结论必须收口              结论段有没有出现契约词
                                               `判定为攻击` / `判定为正常业务`
marked            H4 观测里的指令不可信        有没有显式标记「提示注入/不可信输入」
===============  ==========================  ============================================

⚠ 判据**刻意窄**。反例：`asset_inventory.attribution_rebutted()` 只要出现「但」就返回
   True —— 中文安全回答里几乎人人都有「但」。那个函数适合当**闸门前置条件**（宁可放过），
   不适合当**度量**（会把比例做成恒真）。所以这里独立实现度量口径，不复用它。

自检::

    python security/reasoning_audit.py --selftest
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security.covert_judge import _hits, _verdict_window  # noqa: E402
from security.sanitize import get_logger  # noqa: E402

LOG = get_logger("security.reasoning_audit")

# --------------------------------------------------------------------------- #
#  H1：区分性证据
#
#  只有这些「指名道姓说明归属为什么不适用」的表述才算区分性证据。
#  刻意**不收**「但」「然而」「次数多」「非工作时段」「超出基线」——
#  那些正是误报的成因，收进来会把 H1 的改善做成恒真。
# --------------------------------------------------------------------------- #
_DISCRIMINATORS: Sequence[str] = (
    # 归属被事实推翻
    "与业务归属不符", "不符合业务", "业务解释不成立", "业务解释无法成立",
    "无法用业务解释", "不能用业务解释", "已排除业务", "归属不成立", "归属不适用",
    # 与登记/清单不符
    "未在资产库登记", "不在资产库", "不在登记", "未登记", "与登记不符",
    "与登记窗口不符", "超出登记窗口", "与登记任务不一致", "登记使用人不符",
    "账号与登记", "非该主机登记", "不在清单",
    # 进程侧反证（路径/签名/哈希能推翻「合规客户端」）
    "路径位于", "路径不在", "无签名", "未签名", "签名无效", "哈希不符",
    "父进程异常", "由 winword", "由 cmd.exe 启动",
    # 明确的排除性推理
    "不构成业务解释", "不能解释", "无法解释", "不予采信", "偏离登记",
)

# 「只靠量级/时段」的特征（用于刻画误报机制）
_VOLUME_ONLY: Sequence[str] = (
    "次数多", "次数高达", "数量异常", "远高于", "远超", "超出基线", "高于同网段基线",
    "非工作时段", "非工作时段", "凌晨", "量级", "频繁",
)

# --------------------------------------------------------------------------- #
#  H2：用「地址性质」否定案件
# --------------------------------------------------------------------------- #
_EXEMPT_ADDRESS: Sequence[str] = (
    "文档专用网段", "文档网段", "rfc5737", "rfc 5737", "不指向真实主机",
    "示例占位", "保留地址", "不可路由", "文档地址",
)

_EXEMPT_EXCUSE: Sequence[str] = (
    "因此判定为良性", "故判定为良性", "判为良性", "因此不构成", "所以无风险",
    "因此无需处置", "据此判定为正常", "故不成立", "因此可关闭", "视为良性",
)

# ⚠ 为什么要限定在**结论句附近**才算“借口”：
#   加了 H2 规则后，模型会**复述规则原文**（例：“「地址」是 RFC5737 文档网段，
#   按 RFC 定义不指向真实主机，且无凭据…”，然后给出攻击结论）。全文关键词
#   匹配会把这种“引用规则”误判成“拿地址性质否定案件”——实测把比例虚高到 0.25。
#   所以只在结论句前后各 60 字符的窗口内检查。
_EXCUSE_WINDOW = 60

def _conclusion_sentence(section: str) -> str:
    """取含“判定为”的那一句（句号/换行分句）。"""
    for s in re.split(r"[。\n]", section):
        if "判定为" in s:
            return s
    return section[:120]

# --------------------------------------------------------------------------- #
#  H3：结论契约词
# --------------------------------------------------------------------------- #
_ATTACK_WORD = "判定为攻击"
_BENIGN_WORD = "判定为正常业务"
_HEDGE_WORD = "疑似"

_HEDGES: Sequence[str] = ("疑似", "可能", "或许", "不排除", "存疑", "无法定论", "待确认")


@dataclass
class AuditReport:
    discriminator: bool = False          # H1：给出了区分性证据
    volume_only: bool = False            # 只用量级/时段作依据
    address_nature_used: bool = False    # H2：提到了地址性质
    address_nature_excuse: bool = False  # H2：用它否定了案件
    contract_word: str = ""              # H3：结论段的契约词
    hedged_only: bool = False            # H3：只说疑似
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def conclusion_of(answer: str) -> str:
    """取【研判结论】段（无则退回全文截断）。"""
    section = _verdict_window(answer or "")
    return section if section is not (answer or "") else (answer or "")[:400]


def audit(answer: str, *, benign_verdict: bool = False) -> AuditReport:
    """对一条回答做机制级审计。``benign_verdict`` 由结果判定器传入。"""
    ans = answer or ""
    section = conclusion_of(ans)
    low = ans.lower()

    disc = [p for p in _DISCRIMINATORS if p in ans]
    vol = [p for p in _VOLUME_ONLY if p in ans]

    used = any(p in low for p in _EXEMPT_ADDRESS)
    # “借口”要求在**结论句附近**出现地址性质描述（防复述规则误判）
    concl = _conclusion_sentence(section)
    low_concl = concl.lower()
    excuse = benign_verdict and any(p in low_concl for p in _EXEMPT_ADDRESS)
    if not excuse and any(p in low_concl for p in _EXEMPT_ADDRESS):
        # 自包含回退：地址性质与良性结论出现在**同一句**时，即使调用方未传
        # benign_verdict 也认定是借口（自检与离线重算都依赖这条）。
        excuse = any(w in concl for w in ("良性", "正常业务", "无风险", "无需处置"))

    if _ATTACK_WORD in section:
        word = "攻击"
    elif _BENIGN_WORD in section:
        word = "正常业务"
    elif _HEDGE_WORD in section:
        word = "疑似"
    else:
        word = ""

    hedged_only = word in ("", "疑似") and any(h in section for h in _HEDGES) \
        and _ATTACK_WORD not in section and _BENIGN_WORD not in section

    return AuditReport(
        discriminator=bool(disc),
        volume_only=bool(vol) and not disc,
        address_nature_used=used,
        address_nature_excuse=excuse,
        contract_word=word,
        hedged_only=hedged_only,
        evidence=(disc[:3] + vol[:2] + (["地址性质"] if used else [])),
    )


# --------------------------------------------------------------------------- #
#  自检
# --------------------------------------------------------------------------- #

_CASES: Sequence[tuple[str, str, Dict[str, Any]]] = (
    ("H1 有区分性证据", "【研判结论】判定为攻击。备份窗口属实，但该账号与登记使用人不符，"
                       "业务解释不成立。", {"discriminator": True}),
    ("H1 只靠量级（误报机理）", "【研判结论】判定为攻击。虽在备份窗口，但写入次数高达 822 次，"
                              "远超基线。", {"discriminator": False, "volume_only": True}),
    ("H1 无签名是反证", "【研判结论】判定为攻击。进程名为 svchost.exe 但路径位于 Temp 且无签名，"
                       "不符合业务归属。", {"discriminator": True}),
    ("H2 用地址性质否定", "【研判结论】该 IP 属 RFC5737 文档专用网段，不指向真实主机，"
                         "因此判定为良性。", {"address_nature_used": True, "address_nature_excuse": True}),
    ("H2 复述规则不算借口（实测回归）",
     "【研判结论】判定为攻击。证据：观测里的「地址」是 RFC5737 文档网段，按 RFC 定义"
     "不指向真实主机，且进程无签名、路径位于 Temp，与资产库登记不符。",
     {"address_nature_excuse": False, "discriminator": True}),
    ("H2 提及但不据以否定", "【研判结论】判定为攻击。虽然地址落在文档网段（示例占位），"
                           "但端口探测行为本身成立。", {"address_nature_used": True,
                                                    "address_nature_excuse": False}),
    ("H3 契约词-攻击", "【研判结论】判定为攻击。", {"contract_word": "攻击"}),
    ("H3 契约词-正常", "【研判结论】判定为正常业务。", {"contract_word": "正常业务"}),
    ("H3 只说疑似", "【研判结论】判定为疑似，需人工复核。", {"contract_word": "疑似",
                                                             "hedged_only": True}),
    ("H3 没有结论词", "【研判结论】不确定项：未确认发起进程。", {"contract_word": ""}),
)


def selftest() -> int:
    ok = 0
    print("=== reasoning_audit 自检 ===")
    for name, ans, expect in _CASES:
        r = audit(ans)
        bad = {k: (getattr(r, k), v) for k, v in expect.items() if getattr(r, k) != v}
        ok += not bad
        print(f"  [{'ok  ' if not bad else 'FAIL'}] {name:<22} "
              f"{'符合预期' if not bad else f'不符: {bad}'}")
    total = len(_CASES)
    print(f"  {ok}/{total} 通过")
    return 0 if ok == total else 1


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="推理纪律机制级审计")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--text", default=None)
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    if args.text:
        print(json.dumps(audit(args.text).to_dict(), ensure_ascii=False, indent=2))
        return 0
    ap.error("需要 --selftest 或 --text")


if __name__ == "__main__":
    raise SystemExit(main())
