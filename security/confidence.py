#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""security/confidence.py — 误报抑制：**多维置信度** + **数据驱动良性基线**。

设计依据（对应 `D:\\vvv.txt` 里的两类前沿方法）
------------------------------------------------

1. **OOD / 多维置信度评估**：不看单一「模型分数」，而是从多个独立维度算置信度，
   **只在落入高置信区间时才自动定性/告警**，中间区间交人，低区间静默留档。
   材料里的数据：真实 SQL 注入数据集上，高置信区间内准确率 0.973（覆盖 66% 样本）。

2. **无监督/半监督「正常基线」**：利用大量未标注的正常行为建立基线，
   无需攻击样本即可识别异常，把误报控制在 10% 以下。
   本模块把它做成**在线学习 + 落盘持久化**：传感器每轮把观测到的
   (进程, 目的端口, 协议) 模式累计计数，长期只出现过良性结论的模式自动升格为
   「已确立正常」，后续同类告警直接降权并**不弹通知**。

   为什么这条对**本项目**特别有效：22 小时实跑里 6/6 条告警都是误报，
   而它们反复命中同一批 (进程,端口) 组合（`BackgroundDownload.exe`+443、
   `msedge.exe`+53、`Code.exe`+3333）。基线一旦学成，这些会被自动降噪。

诚实边界
--------

* 良性基线是**学出来的白名单**，因此天然可被「长期低频、行为一致」的攻击者绕过
  （慢速渗透正好符合这个形状）。所以它只做**降权 + 不弹通知**，不删除记录，
  且带**衰减**：模式长时间不出现会掉出基线。
* 置信度是启发式加权，不是概率。它只用来说「够不够格自动定性」。

自检::

    python security/confidence.py --selftest
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security.sanitize import get_logger  # noqa: E402

LOG = get_logger("security.confidence")

DEFAULT_PROFILE = PROJECT_ROOT / "logs" / "benign_profile.json"

# --------------------------------------------------------------------------- #
#  一、数据驱动的良性基线
# --------------------------------------------------------------------------- #

# 一个模式要被认定为「已确立正常」的门槛。
# 取得比较保守：**至少见过 8 次、且从未被判为攻击**。
# 太松会把「攻击者低频试探」也学成正常；太紧则起不到降噪作用。
BASELINE_MIN_HITS = 8
BASELINE_MAX_ATTACK = 0          # 一旦出现过攻击结论，该模式永不升格
BASELINE_TTL_DAYS = 30           # 多久不出现就掉出基线（防陈旧白名单）
# 命中基线后的降权系数与上限：压到阈值以下，但不归零（仍留档可审计）
BASELINE_SCALE = 0.25
BASELINE_MAX_SCORE = 12


@dataclass
class PatternStat:
    hits: int = 0
    benign: int = 0
    attack: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    note: str = ""

    @property
    def established(self) -> bool:
        if self.attack > BASELINE_MAX_ATTACK:
            return False
        if self.hits < BASELINE_MIN_HITS:
            return False
        age_days = (time.time() - self.last_seen) / 86400 if self.last_seen else 999
        return age_days <= BASELINE_TTL_DAYS

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def pattern_key(proc: str, remote_port: int, proto: str = "TCP") -> str:
    """基线键：**只看 (进程, 目的端口, 协议)**，不看远端 IP。

    理由：远端 IP 会漂移（CDN、云服务、矿池轮换），而「哪个程序连哪个端口」
    才是稳定的行为指纹。把 IP 放进去会让基线永远学不到东西。
    """
    return f"{(proc or '?').lower()}|{int(remote_port)}|{(proto or 'TCP').upper()}"


class BenignProfile:
    """在线学习的良性基线（可落盘、可衰减、可审计）。"""

    def __init__(self, path: Path = DEFAULT_PROFILE, autosave: bool = True) -> None:
        self.path = Path(path)
        self.autosave = autosave
        self.stats: Dict[str, PatternStat] = {}
        self._dirty = 0
        self.load()

    # ------------------------------------------------------------ 持久化
    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            for k, v in (raw.get("patterns") or {}).items():
                self.stats[k] = PatternStat(**v)
            LOG.info("已加载良性基线：%d 个模式（其中已确立 %d 个）",
                     len(self.stats), sum(1 for s in self.stats.values() if s.established))
        except Exception as exc:  # noqa: BLE001
            LOG.warning("良性基线加载失败（按空基线继续）：%s", exc)

    def save(self, force: bool = False) -> None:
        if not self.autosave and not force:
            return
        if not force and self._dirty < 20:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps({
                "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
                "min_hits": BASELINE_MIN_HITS,
                "ttl_days": BASELINE_TTL_DAYS,
                "patterns": {k: s.to_dict() for k, s in self.stats.items()},
            }, ensure_ascii=False, indent=1), encoding="utf-8")
            self._dirty = 0
        except Exception as exc:  # noqa: BLE001
            LOG.warning("良性基线保存失败：%s", exc)

    # ------------------------------------------------------------ 学习
    def observe(self, proc: str, remote_port: int, proto: str,
                verdict: str = "") -> PatternStat:
        """记录一次观测。``verdict`` 为 ``attack``/``benign``/``""``（未知）。"""
        k = pattern_key(proc, remote_port, proto)
        s = self.stats.get(k)
        now = time.time()
        if s is None:
            s = PatternStat(first_seen=now, note=f"{proc} → :{remote_port}")
            self.stats[k] = s
        s.hits += 1
        s.last_seen = now
        if verdict == "attack":
            s.attack += 1
        elif verdict == "benign":
            s.benign += 1
        self._dirty += 1
        return s

    def established(self, proc: str, remote_port: int, proto: str) -> bool:
        s = self.stats.get(pattern_key(proc, remote_port, proto))
        return bool(s and s.established)

    def record_verdict(self, proc: str, remote_port: int, proto: str,
                       verdict: str) -> None:
        """只更新判定计数，**不增加 hits**。

        为什么要拆开：`observe()` 负责「这个模式出现过多少次」（频率），
        而判定是后来才拿到的。若把两者合在一起，同一次发现会被计两次，
        基线会过早升格。
        """
        if not verdict:
            return
        s = self.stats.get(pattern_key(proc, remote_port, proto))
        if s is None:
            return
        if verdict == "attack":
            s.attack += 1
        elif verdict == "benign":
            s.benign += 1
        s.last_seen = time.time()
        self._dirty += 1

    # ------------------------------------------------------------ 应用
    def dampen(self, score: int, proc: str, remote_port: int, proto: str
               ) -> Tuple[int, str]:
        """命中已确立基线则降权。返回 ``(新分值, 说明)``。"""
        s = self.stats.get(pattern_key(proc, remote_port, proto))
        if not (s and s.established):
            return score, ""
        new = min(int(score * BASELINE_SCALE), BASELINE_MAX_SCORE)
        note = (f"命中**已确立良性基线**（该“进程→端口”模式累计 {s.hits} 次、"
                f"从未判为攻击、近 {BASELINE_TTL_DAYS} 天仍活跃）→ 分值 {score}→{new}，不弹通知")
        return new, note

    def summary(self) -> Dict[str, int]:
        est = sum(1 for s in self.stats.values() if s.established)
        return {"patterns": len(self.stats), "established": est}


# --------------------------------------------------------------------------- #
#  二、多维置信度
# --------------------------------------------------------------------------- #

# 各维度的权重。刻意让「证据」与「反证」对称可抵消，
# 避免任何单一维度（尤其是模型自述）支配结果。
_W = {
    "rule_strength": 0.22,      # 本地规则分值（客观可复核）
    "signature": 0.16,          # 数字签名（可验证）
    "model_commit": 0.14,       # 模型是否明确表态（非骑墙）
    "grounded": 0.12,           # 接地校验（有无编造）
    "discriminator": 0.14,      # 是否给出区分性证据
    "consistency": 0.12,        # 与历史结论是否一致
    "injection_clean": 0.10,    # 自身未被注入带偏
}


@dataclass
class Confidence:
    score: float                     # 0..1
    band: str                        # high / mid / low
    route: str                       # auto_attack / auto_benign / review
    dims: Dict[str, float] = field(default_factory=dict)
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


def assess(*, rule_score: int, verdict: str, attack_strict: bool = False,
           hedged: bool = False, contradictory: bool = False,
           grounded_ok: bool = True, discriminator: bool = False,
           injection_flagged: bool = False, signature: str = "",
           prior_verdicts: Sequence[str] = (),
           baseline_hit: bool = False,
           high_band: float = 0.70, low_band: float = 0.40) -> Confidence:
    """多维度评估一条告警的可信度并给出路由建议。

    ``route`` 的含义（**关键：不是所有告警都值得打扰人**）：

    * ``auto_attack`` —— 高置信且证据齐备 → 弹通知（仍只读，不执行动作）
    * ``review``      —— 中间区间 → 只记录，标记需人工复核
    * ``auto_benign`` —— 低置信/有反证 → 静默留档，不打扰
    """
    dims: Dict[str, float] = {}
    reasons: List[str] = []

    # 1) 规则强度：40 分封顶（>=40 视为满档）
    dims["rule_strength"] = _clamp(rule_score / 40.0)

    # 2) 签名：Valid=良性倾向；NotSigned/HashMismatch=恶性倾向
    if signature == "Valid":
        dims["signature"] = 0.15
        reasons.append("数字签名有效（良性倾向）")
    elif signature in ("NotSigned", "HashMismatch", "NotTrusted"):
        dims["signature"] = 1.0
        reasons.append(f"数字签名异常（{signature}）")
    else:
        dims["signature"] = 0.5
        reasons.append("签名状态未知（不参与加权倾向）")

    # 3) 模型表态
    if verdict == "attack":
        dims["model_commit"] = 0.9 if attack_strict else (0.45 if hedged else 0.7)
    elif verdict == "benign":
        dims["model_commit"] = 0.1
    else:
        dims["model_commit"] = 0.5
        reasons.append("模型未明确表态")

    # 4) 接地
    dims["grounded"] = 1.0 if grounded_ok else 0.0
    if not grounded_ok:
        reasons.append("**接地校验未通过**（存在编造）")

    # 5) 区分性证据（能推翻业务解释的反证）
    dims["discriminator"] = 1.0 if discriminator else 0.25
    if not discriminator and verdict == "attack":
        reasons.append("给出攻击结论但**没有区分性证据**（只靠量级/时段是误报主因）")

    # 6) 历史一致性
    if prior_verdicts:
        na = sum(1 for v in prior_verdicts if v == "attack")
        nb = sum(1 for v in prior_verdicts if v == "benign")
        same = (na >= nb) if verdict == "attack" else (nb > na)
        dims["consistency"] = 1.0 if same else 0.2
        if not same:
            reasons.append(f"与历史结论不一致（历史 {dict.fromkeys(prior_verdicts)}）")
    else:
        dims["consistency"] = 0.5
        reasons.append("无历史结论可比（首次出现）")

    # 7) 自身是否被注入带偏
    dims["injection_clean"] = 0.3 if injection_flagged else 1.0

    if contradictory:
        reasons.append("同一结论段自相矛盾")
    if baseline_hit:
        reasons.append("命中已确立良性基线")

    score = sum(dims[k] * w for k, w in _W.items())
    if contradictory:
        score *= 0.7
    if baseline_hit:
        score *= 0.5
    score = round(_clamp(score), 4)

    # ---- 硬门槛（神经符号护栏思路）----
    #
    # 关键设计决定：**「能不能自动定性」不能由加权分数自由裁量**。
    # 实测教训：本项目误报的主因就是模型「只凭量级/时段就下攻击结论」——
    # 那种回答的加权分数很高（规则分满分、接地通过），只靠调权重拦不住
    # （自检里 0.713 就误进了 auto_attack）。所以这三条做成**一票否决**：
    #
    #   1. 无区分性证据 → 不能自动定性（H1：只靠次数多/非工作时段不构成判据）
    #   2. 接地校验未通过 → 不能自动定性（回答里有编造）
    #   3. 结论自相矛盾 → 不能自动定性
    #
    # ⚠ 刻意**不把「标记注入」设为门槛**：本项目实测该标记的误标率高达 52.7%
    #   （提示词加固 H4 的副作用），拿它当一票否决会把几乎所有告警都推进人工，
    #   使自动定性形同虚设。它只作为降权维度参与。
    gates: List[str] = []
    if verdict == "attack":
        if not discriminator:
            gates.append("缺少区分性证据（仅凭量级/时段不足以自动定性）")
        if not grounded_ok:
            gates.append("接地校验未通过（存在编造）")
        if contradictory:
            gates.append("结论自相矛盾")
    reasons.extend(f"硬门槛未过：{g}" for g in gates)

    if verdict == "benign" or score < low_band:
        band, route = "low", "auto_benign"
    elif score >= high_band and not gates:
        band, route = "high", "auto_attack"
    else:
        band, route = ("mid" if gates else "mid"), "review"
    return Confidence(score=score, band=band, route=route, dims=dims, reasons=reasons)


# --------------------------------------------------------------------------- #
#  自检
# --------------------------------------------------------------------------- #

def selftest() -> int:
    ok = total = 0

    def chk(name: str, cond: bool) -> None:
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  [{'ok  ' if cond else 'FAIL'}] {name}")

    print("=== confidence 自检 ===")

    # ---- 良性基线 ----
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        p = BenignProfile(Path(td) / "bp.json", autosave=False)
        for _ in range(BASELINE_MIN_HITS):
            p.observe("msedge.exe", 53, "UDP", "benign")
        chk("累计够次数后升格为已确立",
            p.established("msedge.exe", 53, "UDP"))
        chk("次数不够不算已确立", not p.established("msedge.exe", 443, "TCP"))
        s, note = p.dampen(40, "msedge.exe", 53, "UDP")
        chk("命中基线后降到阈值以下并给说明", s <= BASELINE_MAX_SCORE and "良性基线" in note)

        # 一旦出现过攻击结论就永不升格（防「低频慢速攻击被学成正常」）
        q = BenignProfile(Path(td) / "bp2.json", autosave=False)
        for _ in range(20):
            q.observe("evil.exe", 4444, "TCP", "benign")
        chk("纯良性可升格", q.established("evil.exe", 4444, "TCP"))
        q.observe("evil.exe", 4444, "TCP", "attack")
        chk("出现过攻击结论则永不升格", not q.established("evil.exe", 4444, "TCP"))

        # 落盘/回读
        r = BenignProfile(Path(td) / "bp3.json", autosave=False)
        for _ in range(BASELINE_MIN_HITS):
            r.observe("Code.exe", 3333, "TCP", "benign")
        r.save(force=True)
        r2 = BenignProfile(Path(td) / "bp3.json", autosave=False)
        chk("基线可落盘并回读", r2.established("Code.exe", 3333, "TCP"))

    # ---- 多维置信度 ----
    hi = assess(rule_score=60, verdict="attack", attack_strict=True,
                grounded_ok=True, discriminator=True,
                signature="NotSigned", prior_verdicts=["attack", "attack"])
    chk(f"证据齐备→高置信 auto_attack（{hi.score}）",
        hi.band == "high" and hi.route == "auto_attack")

    lo = assess(rule_score=15, verdict="attack", hedged=True, grounded_ok=True,
                discriminator=False, signature="Valid", prior_verdicts=["benign"])
    chk(f"弱证据+签名有效+历史良性→不打扰（{lo.score} / {lo.route}）",
        lo.route in ("auto_benign", "review") and lo.band != "high")

    mid = assess(rule_score=40, verdict="attack", attack_strict=False, grounded_ok=True,
                 discriminator=False, signature="")
    chk(f"无区分性证据→硬门槛拦住，不自动定性（{mid.score} / {mid.route}）",
        mid.route == "review" and any("区分性证据" in r for r in mid.reasons))
    chk("拦截后 band 不再标 high", mid.band != "high")

    ben = assess(rule_score=40, verdict="benign", grounded_ok=True)
    chk("模型判良性→auto_benign", ben.route == "auto_benign")

    ungr = assess(rule_score=60, verdict="attack", attack_strict=True, grounded_ok=False,
                  discriminator=True, signature="NotSigned")
    chk("接地失败会拉低置信", ungr.score < hi.score)

    contra = assess(rule_score=60, verdict="attack", attack_strict=True, grounded_ok=True,
                    discriminator=True, signature="NotSigned", contradictory=True)
    chk("自相矛盾会拉低置信", contra.score < hi.score)

    bl = assess(rule_score=40, verdict="attack", attack_strict=True, grounded_ok=True,
                discriminator=True, signature="NotSigned", baseline_hit=True)
    chk("命中良性基线会拉低置信", bl.score < assess(
        rule_score=40, verdict="attack", attack_strict=True, grounded_ok=True,
        discriminator=True, signature="NotSigned").score)

    chk("置信度在 0..1", all(0.0 <= c.score <= 1.0 for c in (hi, lo, mid, ben, ungr, contra)))
    chk("输出含维度明细与理由", len(hi.dims) == 7 and bool(hi.reasons))
    # 接地失败 / 自相矛盾 同样是一票否决
    chk("接地失败也不能自动定性",
        assess(rule_score=60, verdict="attack", attack_strict=True, grounded_ok=False,
               discriminator=True, signature="NotSigned").route == "review")
    chk("自相矛盾也不能自动定性",
        assess(rule_score=60, verdict="attack", attack_strict=True, grounded_ok=True,
               discriminator=True, signature="NotSigned", contradictory=True).route == "review")
    # 标记注入**不**作为一票否决（实测误标率 52.7%，当门槛会让自动定性失效）
    chk("标记注入只降权不否决",
        assess(rule_score=60, verdict="attack", attack_strict=True, grounded_ok=True,
               discriminator=True, signature="NotSigned",
               injection_flagged=True).route == "auto_attack")

    print(f"  {ok}/{total} 通过")
    return 0 if ok == total else 1


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="误报抑制：多维置信度 + 良性基线")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--show-baseline", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    if args.show_baseline:
        p = BenignProfile()
        print(json.dumps(p.summary(), ensure_ascii=False, indent=2))
        for k, s in sorted(p.stats.items(), key=lambda kv: -kv[1].hits)[:20]:
            print(f"  {k:<34} hits={s.hits:<5} benign={s.benign:<5} attack={s.attack:<3} "
                  f"{'已确立' if s.established else ''}")
        return 0
    ap.error("需要 --selftest 或 --show-baseline")


if __name__ == "__main__":
    raise SystemExit(main())
