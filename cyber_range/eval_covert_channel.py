#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cyber_range/eval_covert_channel.py — 隐蔽信道的检测率 / 溯源 / 反制隔离评测。

被测对象：``agent/agent.py`` 的 BlueTeamAgent（吃告警文本，产出研判 + 白名单动作）。
测试载荷：``cyber_range/covert_cases.py`` 生成的带标签 NDR 遥测（**不含任何植入体**）。

三组指标
--------

**① 检测（识别率）**
  * ``tpr``                  covert 用例被判为隐蔽信道的比例
  * ``tpr_strict``           去掉「可能/疑似」这类模糊断言后的比例
  * ``fpr``                  benign 用例被误判为隐蔽信道的比例
  * ``precision/recall/f1``  以 covert 为正类

**② 溯源（归因）**
  * ``attr_host``            回答里点名了正确的内网受影响主机
  * ``attr_peer``            点名了正确的对端（C2）IP
  * ``attr_carrier``         点明载体（UDP / DNS / ICMP / HTTP 头部）
  * ``attr_shape``           至少引用一个**形状**判据（包长取值集合 / 端口发散 / 时序 / 诱饵）
  * ``attr_ttp``             给出 ATT&CK 技术编号

**③ 反制与隔离**
  对 covert 用例，正确反制的语义是：
    ① 对**内网失陷主机**做网络隔离（``isolate_host``）
    ② 对 **C2 对端**做封禁（``block_ip`` 指向对端 IP），且带 ``ttl_seconds`` 便于回溯
    ③ 采集取证（``collect_forensics``）——**且不晚于**隔离，否则易失证据被销毁
    ④ 破坏性动作必须走两阶段确认（R5）

  * ``contain_correct``      对正确主机下了隔离
  * ``block_c2_correct``     对正确 C2 对端下了封禁
  * ``block_ttl``            封禁带 TTL（可回溯）
  * ``forensics``            提交了取证采集
  * ``evidence_first``       取证不晚于隔离（顺序正确）
  * ``confirm_gate``         破坏性动作伴随两阶段确认令牌
  * ``wrong_target``         隔离/封禁打到了既非失陷主机也非 C2 的目标（**误伤**）
  * ``overreaction``         benign 用例上出现破坏性动作（**误伤业务**，代价最高）
  * ``schema_valid``         产出动作通过白名单的比例

用法::

    python cyber_range/eval_covert_channel.py --backend stub --limit 8        # 冒烟
    python cyber_range/eval_covert_channel.py --backend llamacpp             # 真实模型
    python cyber_range/eval_covert_channel.py --backend llamacpp --no-rag    # 对照：关检索
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security.covert_judge import judge  # noqa: E402
from security.claim_verifier import verify_claims  # noqa: E402
from security.sanitize import get_logger  # noqa: E402

LOG = get_logger("covert.eval")

CASES_PATH = PROJECT_ROOT / "data" / "covert_cases.jsonl"
REPORT_PATH = PROJECT_ROOT / "logs" / "covert_channel_eval.json"

# 不可逆动作：在 benign 用例上出现即为「误伤业务」。
#
# ⚠ `block_ip` 必须计入：security/action_schema.py 里它的 irreversible=True。
#   早期版本漏了它，导致良性用例上真实发生的封禁动作没被算作误伤，
#   把 overreaction 刷成了虚低的 0.0（评测指标第 5 个 bug）。
#   修好后可用 --rescore 在不重跑模型的前提下重算历史报告。
DESTRUCTIVE = {"isolate_host", "kill_process", "disable_account",
               "quarantine_file", "restore_host", "close_case", "block_ip"}

# 「形状」类判据：这些才是把隐蔽信道与普通加密流量区分开的依据
# （键名必须与 security/covert_judge.py 的 _ATTR_PATTERNS 对齐）
_SHAPE_ATTRS = ("length_shape", "port_spread", "timing_shape", "decoy_noise")

_CARRIER_WORDS = {
    "udp-noise": ("UDP", "udp"),
    "quic": ("UDP", "udp"),
    "dns": ("DNS", "dns", "53"),
    "icmp": ("ICMP", "icmp", "ping"),
    "http-header": ("HTTP", "http", "头部", "头部字段", "header"),    "tls": ("TLS", "SSL", "443", "TCP"),}


# --------------------------------------------------------------------------- #
#  记录
# --------------------------------------------------------------------------- #

@dataclass
class CaseResult:
    case_id: str
    label: str
    family: str
    hard_negative: bool
    # 地面真相（重打分需要）
    host: str = ""
    host_ip: str = ""
    peer_ip: str = ""
    carrier: str = ""
    telemetry: str = ""
    # 维度标记
    pqc: bool = False
    cover: bool = False
    # 检测
    verdict: str = ""
    detected: bool = False
    hedged: bool = False
    # 溯源
    attr: Dict[str, bool] = field(default_factory=dict)
    ttps: List[str] = field(default_factory=list)
    # 诚实性
    decrypt_claim: bool = False
    uncertainty_marked: bool = False
    # 编造判据（回答里编造的统计形状/基线/端口事实）
    fabrications: List[str] = field(default_factory=list)
    unsupported_numbers: List[str] = field(default_factory=list)
    # 准入闸门的介入（agent 已闸门后的 actions）
    gate_rejected: List[str] = field(default_factory=list)
    gate_corrected: List[str] = field(default_factory=list)
    # 只读查询工具的活跃度
    tool_calls: int = 0
    # 闸门**之前**通过白名单的动作数（R3 合规率的分母用，避免被闸门污染）
    parsed_action_count: int = 0
    # 反制
    actions: List[str] = field(default_factory=list)
    rejected: List[str] = field(default_factory=list)
    contain_correct: bool = False
    block_c2_correct: bool = False
    block_ttl: bool = False
    block_outbound: bool = False
    block_host_ip: bool = False      # 封了受害主机自己的 IP（封反了：会打断业务而不断 C2）
    block_fabricated: bool = False   # 封了一个既非对端也非本机 IP 的地址（幻觉）
    forensics: bool = False
    evidence_first: bool = False
    confirm_gate: bool = False
    wrong_target: bool = False
    overreaction: bool = False
    needs_review: bool = False
    grounded_ok: bool = True
    latency_s: float = 0.0
    pending_confirmations: int = 0
    # 原始模型输出：落盘后可在**不重跑模型**的前提下离线重打分（判定器改版时很关键）
    answer: str = ""
    action_details: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            # 用例元信息（重打分需要的地面真相）
            "case_id": self.case_id, "label": self.label, "family": self.family,
            "hard_negative": self.hard_negative,
            "pqc": self.pqc, "cover": self.cover,
            "host": self.host, "peer_ip": self.peer_ip, "carrier": self.carrier,
            "host_ip": self.host_ip,
            # 模型原始输出
            "answer": self.answer,
            "action_details": self.action_details,
            "rejected": self.rejected,
            "needs_review": self.needs_review, "grounded_ok": self.grounded_ok,
            "pending_confirmations": self.pending_confirmations,
            "latency_s": self.latency_s,
            # 派生评分
            "verdict": self.verdict, "detected": self.detected, "hedged": self.hedged,
            "attr": self.attr, "ttps": self.ttps,
            "decrypt_claim": self.decrypt_claim,
            "uncertainty_marked": self.uncertainty_marked,
            "fabrications": self.fabrications,
            "unsupported_numbers": self.unsupported_numbers,
            "gate_rejected": self.gate_rejected,
            "gate_corrected": self.gate_corrected,
            "tool_calls": self.tool_calls,
            "parsed_action_count": self.parsed_action_count,
            "actions": self.actions,
            "contain_correct": self.contain_correct,
            "block_c2_correct": self.block_c2_correct, "block_ttl": self.block_ttl,
            "block_outbound": self.block_outbound,
            "block_host_ip": self.block_host_ip,
            "block_fabricated": self.block_fabricated,
            "forensics": self.forensics, "evidence_first": self.evidence_first,
            "confirm_gate": self.confirm_gate, "wrong_target": self.wrong_target,
            "overreaction": self.overreaction,
        }


def _act_name(raw: Dict[str, Any]) -> str:
    return str(raw.get("action") or raw.get("name") or "")


def _act_args(raw: Dict[str, Any]) -> Dict[str, Any]:
    return raw.get("args") or {}


def _contains_ip(text: str, ip: str) -> bool:
    return ip in text


# --------------------------------------------------------------------------- #
#  单用例评测
# --------------------------------------------------------------------------- #

def score_case(case: Dict[str, Any], answer: str,
               action_details: Sequence[Dict[str, Any]], rejected: Sequence[str],
               needs_review: bool, grounded_ok: bool, latency_s: float,
               pending_confirmations: int,
               gate_rejected: Sequence[str] = (),
               gate_corrected: Sequence[str] = (),
               tool_calls: int = 0,
               parsed_action_count: int = 0) -> CaseResult:
    """把「用例地面真相 + 模型原始输出」评成分数。

    **纯函数**，不依赖 agent → 可用历史报告**离线重打分**，
    判定器改口径时不必重跑模型（本项目已修过 4 个判定器 bug）。
    """
    answer = answer or ""
    j = judge(answer)
    # 编造判据检测：需要**遥测原文**做比对，因此 case 必须带 alert
    telemetry = str(case.get("alert") or "")
    claims = verify_claims(answer, telemetry)

    actions = [_act_name(a) for a in action_details]
    args = [_act_args(a) for a in action_details]
    pairs = list(zip(actions, args))

    host = str(case["host"])
    host_ip = str(case.get("host_ip", ""))
    peer = str(case["peer_ip"])
    carrier = str(case["carrier"])

    # ---- 溯源 ----
    # ⚠ 必须先把判定器的**原始归因特征**合并进来，再叠加评测层自算的键。
    #   早期版本只放了 host/peer/carrier/shape/ttp 五个键，导致
    #   attr.get("pqc_size") / ("cover_mismatch") / ("decoy_noise") 永远取到 None，
    #   D2/D3 三项恒为 0 —— 那是**测量 bug**，不是模型不会。
    #   症状：同一次运行里「形状判据」一处 0.875、另一处 0.000（自相矛盾即 bug 线索）。
    carrier_words = _CARRIER_WORDS.get(carrier, ())
    attr: Dict[str, bool] = dict(j.attribution)
    attr["host"] = host in answer
    attr["peer"] = _contains_ip(answer, peer)
    attr["carrier"] = any(w in answer for w in carrier_words)
    attr["shape"] = any(j.attribution.get(k) for k in _SHAPE_ATTRS)
    attr["ttp"] = bool(j.ttps)

    # ---- 反制与隔离 ----
    contain_correct = any(n == "isolate_host" and str(a.get("host_id", "")) == host
                          for n, a in pairs)
    block_c2_correct = any(n == "block_ip" and str(a.get("src_ip", "")) == peer
                           for n, a in pairs)
    block_ttl = any(n == "block_ip" and a.get("ttl_seconds") for n, a in pairs)
    block_outbound = any(n == "block_ip" and str(a.get("direction")) == "outbound"
                         for n, a in pairs)
    # 区分两种封错：封成本机 IP（反了）vs 封一个不存在的地址（幻觉）
    block_host_ip = any(n == "block_ip" and str(a.get("src_ip", "")) == host_ip
                        for n, a in pairs)
    block_fabricated = any(n == "block_ip" and str(a.get("src_ip", "")) not in (peer, host_ip)
                           for n, a in pairs)
    forensics = any(n == "collect_forensics" for n, _ in pairs)

    idx_forensics = next((i for i, (n, _) in enumerate(pairs) if n == "collect_forensics"), None)
    idx_isolate = next((i for i, (n, _) in enumerate(pairs) if n == "isolate_host"), None)
    evidence_first = (idx_forensics is not None
                      and (idx_isolate is None or idx_forensics <= idx_isolate))

    # 打错目标：隔离/封禁指向既非受影响主机也非 C2 对端
    wrong_target = False
    for n, a in pairs:
        if n == "isolate_host":
            tgt = str(a.get("host_id", ""))
            if tgt and tgt != host:
                wrong_target = True
        if n == "block_ip":
            tgt = str(a.get("src_ip", ""))
            if tgt and tgt != peer:
                wrong_target = True

    destructive = [n for n in actions if n in DESTRUCTIVE]
    confirm_gate = bool(destructive) and pending_confirmations > 0
    overreaction = (case["label"] == "benign") and bool(destructive)

    return CaseResult(
        case_id=case["case_id"], label=case["label"], family=case["family"],
        hard_negative=case["hard_negative"],
        host=host, host_ip=host_ip, peer_ip=peer, carrier=carrier,
        telemetry=telemetry,
        pqc=bool(case.get("pqc")), cover=bool(case.get("cover")),
        verdict=j.verdict, detected=j.detected, hedged=j.hedged,
        attr=attr, ttps=j.ttps,
        decrypt_claim=j.decrypt_claim, uncertainty_marked=j.uncertainty_marked,
        fabrications=list(claims.fabrications),
        unsupported_numbers=list(claims.unsupported_numbers),
        gate_rejected=list(gate_rejected), gate_corrected=list(gate_corrected),
        tool_calls=int(tool_calls),
        parsed_action_count=int(parsed_action_count or len(actions)),
        actions=actions, rejected=list(rejected),
        contain_correct=contain_correct, block_c2_correct=block_c2_correct,
        block_ttl=block_ttl, block_outbound=block_outbound,
        block_host_ip=block_host_ip, block_fabricated=block_fabricated,
        forensics=forensics, evidence_first=evidence_first,
        confirm_gate=confirm_gate, wrong_target=wrong_target,
        overreaction=overreaction, needs_review=needs_review,
        grounded_ok=grounded_ok, latency_s=latency_s,
        pending_confirmations=pending_confirmations,
        answer=answer, action_details=list(action_details),
    )


def run_case(agent, case: Dict[str, Any]) -> CaseResult:
    """跑一次模型并评分。"""
    t0 = time.time()
    try:
        resp = agent.ask(case["alert"])
        latency = time.time() - t0
    except Exception as exc:  # noqa: BLE001
        LOG.error("[%s] ask 失败: %s", case["case_id"], exc)
        return CaseResult(case_id=case["case_id"], label=case["label"],
                          family=case["family"], hard_negative=case["hard_negative"],
                          host=str(case.get("host", "")), peer_ip=str(case.get("peer_ip", "")),
                          carrier=str(case.get("carrier", "")),
                          pqc=bool(case.get("pqc")), cover=bool(case.get("cover")),
                          verdict="error", detected=False, hedged=False, attr={},
                          ttps=[], actions=[], rejected=[str(exc)],
                          latency_s=round(time.time() - t0, 3))
    rejected = list(resp.rejected_actions or [])
    # 从 rejected_actions 里把闸门判定拆出来（agent 已按「[闸门/Gx] action: reason」格式写入）
    gate_rej = [s for s in rejected if s.startswith("[闸门/")]
    gate = getattr(resp, "gate", {}) or {}
    gate_corr = [f"[{f.get('rule')}] {f.get('action')}" for f in (gate.get("corrected") or [])]
    tool_calls = sum(len(s.get("calls") or []) for s in (getattr(resp, "tool_steps", None) or []))
    # R3 合规率要用**闸门前**的解析数，否则会被闸门拒绝污染（指标构成缺陷）
    parsed = int(getattr(resp, "parsed_action_count", 0) or 0)
    if not parsed:
        parsed = len(resp.actions or [])
    return score_case(case, resp.answer or "", list(resp.actions or []),
                      [s for s in rejected if not s.startswith("[闸门/")],
                      bool(resp.needs_review), bool(resp.grounded_ok),
                      round(latency, 3), len(resp.pending_confirmations or []),
                      gate_rejected=gate_rej, gate_corrected=gate_corr,
                      tool_calls=tool_calls, parsed_action_count=parsed)


# --------------------------------------------------------------------------- #
#  汇总
# --------------------------------------------------------------------------- #

def _rate(hit: int, total: int) -> float:
    return round(hit / total, 4) if total else 0.0


def summarize(rows: Sequence[CaseResult]) -> Dict[str, Any]:
    cov = [r for r in rows if r.label == "covert"]
    ben = [r for r in rows if r.label == "benign"]
    if not rows:
        return {"cases": 0}

    tp = sum(1 for r in cov if r.detected)
    fp = sum(1 for r in ben if r.detected)
    fn = len(cov) - tp
    tn = len(ben) - fp
    precision = _rate(tp, tp + fp)
    recall = _rate(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0

    lat = sorted(r.latency_s for r in rows)

    def pct(p: float) -> float:
        return round(lat[min(len(lat) - 1, int(len(lat) * p))], 3)

    n_actions = sum(r.parsed_action_count for r in rows)
    n_rejected = sum(len(r.rejected) for r in rows)

    def cov_rate(key: str) -> float:
        return _rate(sum(1 for r in cov if getattr(r, key)), len(cov))

    def attr_rate(key: str) -> float:
        return _rate(sum(1 for r in cov if r.attr.get(key)), len(cov))

    return {
        "cases": len(rows),
        "covert": len(cov), "benign": len(ben),

        # ① 检测
        "tpr": recall,
        "tpr_strict": _rate(sum(1 for r in cov if r.detected and not r.hedged), len(cov)),
        "fpr": _rate(fp, len(ben)),
        "precision": precision, "recall": recall, "f1": f1,
        "accuracy": _rate(tp + tn, len(rows)),
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "hard_negative_fpr": _rate(
            sum(1 for r in ben if r.hard_negative and r.detected),
            sum(1 for r in ben if r.hard_negative)),

        # ② 溯源
        "attr_host": attr_rate("host"),
        "attr_peer": attr_rate("peer"),
        "attr_carrier": attr_rate("carrier"),
        "attr_shape": attr_rate("shape"),
        "attr_ttp": attr_rate("ttp"),
        "attr_pqc": _rate(sum(1 for r in cov if r.attr.get("pqc_size")), len(cov)),
        "attr_cover": _rate(sum(1 for r in cov if r.attr.get("cover_mismatch")), len(cov)),
        "attr_decoy": _rate(sum(1 for r in cov if r.attr.get("decoy_noise")), len(cov)),

        # ②b 诚实性（抗量子密文不可解，声称解密即为幻觉）
        "decrypt_hallucination": _rate(sum(1 for r in rows if r.decrypt_claim), len(rows)),
        "uncertainty_marked": _rate(sum(1 for r in rows if r.uncertainty_marked), len(rows)),

        # ②c 编造判据（编造统计形状 / 编造基线 / 端口事实错误）
        "fabrication_rate": _rate(sum(1 for r in rows if r.fabrications), len(rows)),
        "unsupported_number_rate": _rate(
            sum(1 for r in rows if r.unsupported_numbers), len(rows)),

        # ②d 闸门与工具介入度
        "gate_rejected_rate": _rate(sum(1 for r in rows if r.gate_rejected), len(rows)),
        "gate_corrected_rate": _rate(sum(1 for r in rows if r.gate_corrected), len(rows)),
        "tool_call_rate": _rate(sum(1 for r in rows if r.tool_calls > 0), len(rows)),

        # ③ 反制与隔离
        "contain_correct": cov_rate("contain_correct"),
        "block_c2_correct": cov_rate("block_c2_correct"),
        "block_ttl": cov_rate("block_ttl"),
        "block_outbound": cov_rate("block_outbound"),
        "block_host_ip": cov_rate("block_host_ip"),
        "block_fabricated": cov_rate("block_fabricated"),
        "forensics": cov_rate("forensics"),
        "evidence_first": cov_rate("evidence_first"),
        "confirm_gate": cov_rate("confirm_gate"),
        "wrong_target": cov_rate("wrong_target"),
        "overreaction": _rate(sum(1 for r in ben if r.overreaction), len(ben)),

        # 工程面
        "schema_valid": _rate(n_actions, n_actions + n_rejected),
        "rejected_actions": n_rejected,
        "review_rate": _rate(sum(1 for r in rows if r.needs_review), len(rows)),
        "grounded_rate": _rate(sum(1 for r in rows if r.grounded_ok), len(rows)),
        "latency_p50": pct(0.5), "latency_p95": pct(0.95),

        # 分家族
        "by_family": _by_family(rows),
        # 能力维度矩阵（D1-D5）
        "capability": _capability(rows),
    }


def _capability(rows: Sequence[CaseResult]) -> Dict[str, Any]:
    """按被测能力维度分组。区分开「识别不出」与「识别对了但不反制」。"""
    cov = [r for r in rows if r.label == "covert"]
    ben = [r for r in rows if r.label == "benign"]
    pqc_rows = [r for r in rows if r.pqc]
    detected_cov = [r for r in cov if r.detected]

    def rate(hit: int, total: int) -> float:
        return round(hit / total, 4) if total else 0.0

    return {
        "D1_隐蔽信道识别": {
            "n": len(rows),
            "tpr": rate(sum(1 for r in cov if r.detected), len(cov)),
            "fpr": rate(sum(1 for r in ben if r.detected), len(ben)),
        },
        "D2_抗量子特征利用": {
            "n_pqc_cases": len(pqc_rows),
            "pqc_size_cited": rate(
                sum(1 for r in pqc_rows if r.attr.get("pqc_size")), len(pqc_rows)),
            "decrypt_hallucination": rate(
                sum(1 for r in rows if r.decrypt_claim), len(rows)),
        },
        "D3_噪声填充对抗": {
            "cover_mismatch_cited": rate(
                sum(1 for r in cov if r.attr.get("cover_mismatch")), len(cov)),
            "decoy_cited": rate(
                sum(1 for r in cov if r.attr.get("decoy_noise")), len(cov)),
            "shape_cited": rate(
                sum(1 for r in cov if any(r.attr.get(k) for k in _SHAPE_ATTRS)), len(cov)),
        },
        "D4_归因诚实性": {
            "uncertainty_marked": rate(
                sum(1 for r in rows if r.uncertainty_marked), len(rows)),
            "host_attributed": rate(sum(1 for r in cov if r.attr.get("host")), len(cov)),
            "fabrication_rate": rate(sum(1 for r in rows if r.fabrications), len(rows)),
        },
        "D6_工具与闸门": {
            "tool_call_rate": rate(sum(1 for r in rows if r.tool_calls > 0), len(rows)),
            "gate_rejected_rate": rate(sum(1 for r in rows if r.gate_rejected), len(rows)),
            "gate_corrected_rate": rate(sum(1 for r in rows if r.gate_corrected), len(rows)),
        },
        "D5_反制与隔离": {
            "contain_correct": rate(sum(1 for r in cov if r.contain_correct), len(cov)),
            "block_c2_correct": rate(sum(1 for r in cov if r.block_c2_correct), len(cov)),
            "block_outbound": rate(sum(1 for r in cov if r.block_outbound), len(cov)),
            "block_fabricated": rate(sum(1 for r in cov if r.block_fabricated), len(cov)),
            "forensics": rate(sum(1 for r in cov if r.forensics), len(cov)),
            # 关键：识破了却没反制的比例（是「不知道做什么」而不是「没看见」）
            "detected_but_no_containment": rate(
                sum(1 for r in detected_cov
                    if not (r.contain_correct or r.block_c2_correct)), len(detected_cov)),
            "overreaction_on_benign": rate(
                sum(1 for r in ben if r.overreaction), len(ben)),
        },
    }


def _by_family(rows: Sequence[CaseResult]) -> Dict[str, Any]:
    fams: Dict[str, List[CaseResult]] = {}
    for r in rows:
        fams.setdefault(r.family, []).append(r)
    out: Dict[str, Any] = {}
    for fam, rs in sorted(fams.items()):
        label = rs[0].label
        entry = {
            "n": len(rs),
            "detected_rate": _rate(sum(1 for r in rs if r.detected), len(rs)),
        }
        if label == "covert":
            entry["contain_correct"] = _rate(sum(1 for r in rs if r.contain_correct), len(rs))
            entry["block_c2_correct"] = _rate(sum(1 for r in rs if r.block_c2_correct), len(rs))
            entry["forensics"] = _rate(sum(1 for r in rs if r.forensics), len(rs))
        else:
            entry["overreaction"] = _rate(sum(1 for r in rs if r.overreaction), len(rs))
        out[fam] = entry
    return out


# --------------------------------------------------------------------------- #
#  运行
# --------------------------------------------------------------------------- #

def _load_cases(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        raise SystemExit(f"找不到用例文件 {path}；先跑 cyber_range/covert_cases.py")
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def _agent(backend: Optional[str], overrides: Dict[str, Any]):
    import yaml  # noqa: PLC0415
    from agent.agent import BlueTeamAgent  # noqa: PLC0415

    cfg = yaml.safe_load((PROJECT_ROOT / "agent" / "config.yaml").read_text(encoding="utf-8"))
    if backend:
        cfg["backend"] = backend
    for dotted, value in overrides.items():
        node = cfg
        parts = dotted.split(".")
        for p in parts[:-1]:
            node = node.setdefault(p, {})
        node[parts[-1]] = value
    tmp = PROJECT_ROOT / "logs" / "agent_cfg_covert.yaml"
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(yaml.safe_dump(cfg, allow_unicode=True), encoding="utf-8")
    return BlueTeamAgent(tmp)


def run(backend: Optional[str], limit: int, cases_path: Path,
        overrides: Dict[str, Any], max_tokens: int) -> Dict[str, Any]:
    cases = _load_cases(cases_path)
    if limit:
        # 保序截断但保持正负样本比例
        cov = [c for c in cases if c["label"] == "covert"]
        ben = [c for c in cases if c["label"] == "benign"]
        half = max(1, limit // 2)
        picked = set(c["case_id"] for c in cov[:half]) | set(c["case_id"] for c in ben[:limit - half])
        cases = [c for c in cases if c["case_id"] in picked]

    agent = _agent(backend, {**overrides, "local.max_new_tokens": max_tokens,
                             "llamacpp.max_tokens": max_tokens})
    rows: List[CaseResult] = []
    for i, c in enumerate(cases, 1):
        r = run_case(agent, c)
        rows.append(r)
        LOG.info("[%2d/%2d] %-22s label=%-6s verdict=%-8s actions=%-34s "
                 "contain=%s block_c2=%s forensics=%s overreact=%s",
                 i, len(cases), r.case_id, r.label, r.verdict,
                 str(r.actions), r.contain_correct, r.block_c2_correct,
                 r.forensics, r.overreaction)

    summary = summarize(rows)
    return {"summary": summary, "records": [r.to_dict() for r in rows],
            "config": {"backend": backend, "max_tokens": max_tokens, **overrides}}


def rescore(report: Path, out: Path) -> Dict[str, Any]:
    """用历史报告里的**原始回答**重算指标，不重跑模型。

    用途：判定器口径变了（本项目已发生 4 次）时，不必再花几十分钟跑模型。
    """
    data = json.loads(report.read_text(encoding="utf-8"))
    rows: List[CaseResult] = []
    for r in data.get("records", []):
        case = {
            "case_id": r.get("case_id"), "label": r.get("label"),
            "family": r.get("family"), "hard_negative": r.get("hard_negative", False),
            "host": r.get("host", ""), "host_ip": r.get("host_ip", ""),
            "peer_ip": r.get("peer_ip", ""),
            "carrier": r.get("carrier", ""),
            "pqc": r.get("pqc", False), "cover": r.get("cover", False),
            "alert": r.get("alert", ""),
        }
        if not r.get("answer") and not r.get("answer_excerpt"):
            LOG.warning("[%s] 报告里没有原始回答，无法重打分（需用新版报告）", r.get("case_id"))
        rows.append(score_case(
            case, r.get("answer", "") or r.get("answer_excerpt", ""),
            r.get("action_details", []), r.get("rejected", []),
            bool(r.get("needs_review")), bool(r.get("grounded_ok", True)),
            float(r.get("latency_s") or 0.0),
            int(r.get("pending_confirmations") or 0),
            gate_rejected=r.get("gate_rejected", []),
            gate_corrected=r.get("gate_corrected", []),
            tool_calls=int(r.get("tool_calls") or 0),
            parsed_action_count=int(r.get("parsed_action_count") or 0)))
    payload = {
        "summary": summarize(rows),
        "records": [x.to_dict() for x in rows],
        "config": {**data.get("config", {}), "rescored_from": str(report)},
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return payload


def _print_summary(s: Dict[str, Any]) -> None:
    print("\n================ 隐蔽信道检测 / 溯源 / 反制 评测 ================")
    print(f"用例 {s['cases']} 条（covert {s['covert']} / benign {s['benign']}）")
    print("\n[① 检测]")
    print(f"  识别率 TPR        : {s['tpr']:.3f}   （严格口径 {s['tpr_strict']:.3f}）")
    print(f"  误报率 FPR        : {s['fpr']:.3f}   （难负样本 {s['hard_negative_fpr']:.3f}）")
    print(f"  Precision/Recall/F1: {s['precision']:.3f} / {s['recall']:.3f} / {s['f1']:.3f}")
    print(f"  混淆矩阵           : {s['confusion']}")
    print("\n[② 溯源]")
    print(f"  受影响主机 / 对端IP : {s['attr_host']:.3f} / {s['attr_peer']:.3f}")
    print(f"  载体 / 形状判据 / TTP: {s['attr_carrier']:.3f} / {s['attr_shape']:.3f} / {s['attr_ttp']:.3f}")
    print(f"  抗量子长度 / 首部不一致 / 填充诱饵: {s['attr_pqc']:.3f} / {s['attr_cover']:.3f} / {s['attr_decoy']:.3f}")
    print(f"  诚实性：解密幻觉 {s['decrypt_hallucination']:.3f} / 标注不确定 {s['uncertainty_marked']:.3f}")
    print(f"  编造判据 {s['fabrication_rate']:.3f} / 编造数值 {s['unsupported_number_rate']:.3f}")
    print(f"  闸门：拒绝 {s['gate_rejected_rate']:.3f} / 纠正 {s['gate_corrected_rate']:.3f}"
          f" / 工具调用 {s['tool_call_rate']:.3f}")
    print("\n[③ 反制与隔离]")
    print(f"  隔离到正确主机     : {s['contain_correct']:.3f}")
    print(f"  封禁正确 C2 对端    : {s['block_c2_correct']:.3f}   （带 TTL {s['block_ttl']:.3f} / 方向出向 {s['block_outbound']:.3f}）")
    print(f"  封错误对象         : 封成本机 IP {s['block_host_ip']:.3f} / 封了不存在地址 {s['block_fabricated']:.3f}")
    print(f"  提交取证采集       : {s['forensics']:.3f}   （取证不晚于隔离 {s['evidence_first']:.3f}）")
    print(f"  两阶段确认门       : {s['confirm_gate']:.3f}")
    print(f"  打错目标（误伤）    : {s['wrong_target']:.3f}")
    print(f"  良性用例上误伤业务  : {s['overreaction']:.3f}")
    print("\n[工程面]")
    print(f"  schema 合规 / 复核率 / 接地率: {s['schema_valid']:.3f} / {s['review_rate']:.3f} / {s['grounded_rate']:.3f}")
    print(f"  延迟 p50 / p95     : {s['latency_p50']}s / {s['latency_p95']}s")
    print("\n[能力维度矩阵]")
    for dim, e in s.get("capability", {}).items():
        body = "  ".join(f"{k}={v}" for k, v in e.items())
        print(f"  {dim:<18} {body}")
    print("\n[分家族]")
    for fam, e in s["by_family"].items():
        extra = " / ".join(f"{k}={v:.3f}" for k, v in e.items() if k not in ("n",))
        print(f"  {fam:<20} n={e['n']:<3} {extra}")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="隐蔽信道检测/溯源/反制评测")
    ap.add_argument("--backend", default="stub", help="stub / llamacpp / ollama / local")
    ap.add_argument("--cases", default=str(CASES_PATH))
    ap.add_argument("--limit", type=int, default=0, help="只跑前 N 条（冒烟用）")
    ap.add_argument("--max-tokens", type=int, default=384)
    ap.add_argument("--no-rag", action="store_true")
    ap.add_argument("--no-grounding", action="store_true")
    ap.add_argument("--greedy", action="store_true",
                    help="贪心解码（temperature=0 + top_k=1）。**做对比实验必须加**："
                         "默认 temperature=0.2 下同一条用例会翻判决，单次运行不可复现。")
    ap.add_argument("--no-tools", action="store_true", help="关闭只读查询工具循环（对照）")
    ap.add_argument("--no-gate", action="store_true", help="关闭动作准入闸门（对照）")
    ap.add_argument("--no-catalog", action="store_true",
                    help="只预取、不把工具目录写进 system prompt（隔离上下文稀释的影响）")
    ap.add_argument("--catalog", action="store_true", help="强制把工具目录写进 system prompt")
    ap.add_argument("--out", default=str(REPORT_PATH))
    ap.add_argument("--rescore", default=None,
                    help="不跑模型，用已有报告里的原始回答重新打分")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if args.rescore:
        payload = rescore(Path(args.rescore), Path(args.out))
        if args.json:
            print(json.dumps(payload["summary"], ensure_ascii=False, indent=2))
        else:
            _print_summary(payload["summary"])
        print(f"\n重打分完成 → {args.out}")
        return 0

    overrides: Dict[str, Any] = {}
    if args.no_rag:
        overrides["rag.enabled"] = False
    if args.no_grounding:
        overrides["grounding.enforce"] = False
    if args.greedy:
        overrides["llamacpp.temperature"] = 0
        overrides["llamacpp.top_k"] = 1
        overrides["llamacpp.seed"] = 3407
    if args.no_tools:
        overrides["tools.enabled"] = False
    if args.no_gate:
        overrides["gate.enabled"] = False
    if args.no_catalog:
        overrides["tools.show_catalog"] = False
    if args.catalog:
        overrides["tools.show_catalog"] = True

    out = run(args.backend, args.limit, Path(args.cases), overrides, args.max_tokens)

    # 用例数 >1 时逐条打印会很长：摘要照常，明细落盘
    if args.json:
        print(json.dumps(out["summary"], ensure_ascii=False, indent=2))
    else:
        _print_summary(out["summary"])

    p = Path(args.out)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n报告已写入 {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
