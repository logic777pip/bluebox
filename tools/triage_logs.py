#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/triage_logs.py — 日志研判副驾（只读、不动手）。

定位（重要）
------------
本工具**不是杀毒软件，也不能替代杀毒软件**。它做的是：
把「已有安全软件/系统产生的告警日志」逐条送去本地模型研判，
给出「攻击 / 正常业务 / 不明确 + 建议动作 + 是否需人工复核」，供人决策。

**它不执行任何处置动作。** 这一点由三重设计保证：

1. 本工具**没有**开启动作执行的任何参数（不存在 `--execute`），
   加载配置时强制写死 `actions.enable_executor=false` / `auto_confirm=false` / `dry_run=true`；
2. 启动后回读自己写的配置并**断言**这三项，不符则直接退出；
3. 输出的「建议动作」只打印动作名与参数，永远标注「建议，未执行」。

已知能力边界（用本项目自己的实测数据说话）
------------------------------------------
* 240 条攻防评测：Accuracy 0.713、常规流量误报率 0.15、动作正确率 0.329；
* 提示词加固 H4 引入了「幻觉注入」（非注入用例 52.7% 也会声称发现注入）。

所以正确用法是：**把它当降噪/初筛工具**，`needs_review=True` 的条目交给人。
绝不能把它的输出直接接到自动处置链上。

用法::

    python tools/triage_logs.py --log C:\\logs\\huorong_export.txt
    python tools/triage_logs.py --demo                      # 用内置样例日志跑通
    python tools/triage_logs.py --log x.log --limit 20 --out reports/triage.md
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security.attack_judge import judge as attack_judge  # noqa: E402
from security.injection_judge import judge as injection_judge  # noqa: E402
from security.sanitize import get_logger  # noqa: E402

LOG = get_logger("tools.triage")

# 只读铁律：本工具加载配置时强制写死的三项
READONLY_PINS: Dict[str, Any] = {
    "actions.enable_executor": False,
    "actions.auto_confirm": False,
    "actions.dry_run": True,
    # 研判纪律加固（第二轮实测：误报率 0.417 → 0.15）
    "prompt.hardening": True,
}

# 日志分块默认口径：空行分段，或以时间戳/日期开头的行起新段
DEFAULT_SPLIT = r"\n\s*\n|(?=\n\s*\[?\d{4}[-/]\d{1,2}[-/]\d{1,2})"

_DEMO_LOG = """[2026-10-02 03:14:07] 火绒 自定义规则 主机 app-205(192.0.2.31) 进程 powershell.exe
命令行：powershell.exe -nop -w hidden -enc SQBFAF... 父进程 winword.exe
备注：父进程为 Office 应用，命令行含编码块

[2026-10-02 03:20:11] 火绒 网络防护 主机 ws-042(198.51.100.77) 向 203.0.113.9:8443 发起持续外连
每 60 秒一次，每次上行 512 字节，已持续 47 分钟；证书为自签名

[2026-10-02 09:02:44] 火绒 文件实时监控 主机 srv-014(192.0.2.114) 进程 veeamagent.exe 写入 411 个数据块到备份服务器 203.0.113.121
任务 ID 与昨日一致，处于登记的夜间备份窗口（02:00-04:00）

[2026-10-02 10:31:19] 火绒 端口扫描告警 主机 app-129(192.0.2.129) 对 212 个内网地址做端口探测
进程 nessusd.exe；该主机在资产库登记为合规扫描器，扫描窗口 周三 02:00
"""


@dataclass
class Alert:
    idx: int
    text: str
    head: str = ""
    verdict: str = "unclear"
    attack_strict: bool = False
    hedged: bool = False
    injection_flagged: bool = False
    needs_review: bool = True
    grounded_ok: bool = True
    actions: List[str] = field(default_factory=list)
    action_details: List[Dict[str, Any]] = field(default_factory=list)
    rejected: List[str] = field(default_factory=list)
    retries: int = 0
    latency_s: float = 0.0
    tokens: int = 0
    answer: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


def split_alerts(text: str, split_re: str, max_chars: int) -> List[Alert]:
    """把日志切成候选告警块。切不出多块时整份作为一块（不丢数据）。"""
    parts = [p.strip() for p in re.split(split_re, text) if p and p.strip()]
    if len(parts) <= 1:
        parts = [text.strip()]
    out: List[Alert] = []
    for i, p in enumerate(parts, 1):
        body = p[:max_chars]
        head = next((ln.strip() for ln in body.splitlines() if ln.strip()), "")[:110]
        out.append(Alert(idx=i, text=body, head=head))
    return out


def build_agent(backend: Optional[str] = None, extra_pins: Optional[Dict[str, Any]] = None):
    """构造**只读** Agent：强制写死只读三项并回读断言。

    ``extra_pins`` 可追加其他配置覆盖（例：net_sensor 的 --lean 档关掉 RAG/工具），
    但**不能**覆盖 ``READONLY_PINS`` 里的三项 —— 且会被回读断言拦下。
    """
    import yaml  # noqa: PLC0415
    from agent.agent import BlueTeamAgent  # noqa: PLC0415

    cfg = yaml.safe_load((PROJECT_ROOT / "agent" / "config.yaml").read_text(encoding="utf-8")) or {}
    if backend:
        cfg["backend"] = backend
    pins = dict(READONLY_PINS)
    for k, v in (extra_pins or {}).items():
        if k in READONLY_PINS:
            raise SystemExit(f"不允许覆盖只读铁律：{k}")
        pins[k] = v
    for dotted, value in pins.items():
        node, parts = cfg, dotted.split(".")
        for p in parts[:-1]:
            node = node.setdefault(p, {})
        node[parts[-1]] = value

    tmp = PROJECT_ROOT / "logs" / "agent_cfg_triage.yaml"
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(yaml.safe_dump(cfg, allow_unicode=True), encoding="utf-8")

    # 回读断言：确认只读铁律真的落到了盘上（防止键名写错却静默按默认执行）
    back = yaml.safe_load(tmp.read_text(encoding="utf-8"))
    for dotted, value in pins.items():
        node = back
        for p in dotted.split("."):
            node = node.get(p, {}) if isinstance(node, dict) else None
        if node != value:
            raise SystemExit(f"只读铁律校验失败：{dotted} 期望 {value!r}，实际 {node!r}")
    LOG.info("只读铁律已确认：动作执行器关闭、两阶段确认关闭、加固开启")
    return BlueTeamAgent(tmp)


def triage_one(agent, alert: Alert) -> Alert:
    usage = getattr(agent.backend, "usage_total", None)
    u0 = dict(usage) if usage else {}
    t0 = time.time()
    try:
        resp = agent.ask(alert.text)
    except Exception as exc:  # noqa: BLE001
        LOG.error("第 %d 条研判失败：%s", alert.idx, exc)
        alert.answer = f"<研判失败：{exc}>"
        alert.needs_review = True
        return alert
    alert.latency_s = round(time.time() - t0, 2)

    answer = resp.answer or ""
    aj = attack_judge(answer)
    ij = injection_judge(answer)

    alert.answer = answer
    alert.verdict = aj.verdict
    alert.attack_strict = aj.attack_strict
    alert.hedged = aj.hedged
    alert.injection_flagged = ij.injection_flagged
    alert.needs_review = bool(resp.needs_review) or aj.verdict == "unclear"
    alert.grounded_ok = bool(resp.grounded_ok)
    alert.action_details = list(resp.actions or [])
    alert.actions = [str(a.get("action") or a.get("name") or "") for a in alert.action_details]
    alert.rejected = list(resp.rejected_actions or [])
    alert.retries = int(getattr(resp, "retries", 0) or 0)
    if usage and u0:
        alert.tokens = (usage.get("total_tokens", 0) - u0.get("total_tokens", 0))
    return alert


_RANK = {"attack": 0, "unclear": 1, "benign": 2}


def render(alerts: Sequence[Alert], source: str) -> str:
    lines = [
        "# 日志研判副驾报告（只读）",
        "",
        f"- 来源：`{source}`",
        f"- 条数：{len(alerts)}",
        "- ⚠ 本报告**不含任何已执行的处置动作**；`建议动作` 一律需人工确认后由本人手动执行。",
        "- ⚠ 模型实测：常规流量误报率 0.15、动作正确率 0.329、存在「幻觉注入」"
        "（非注入用例 52.7% 会声称发现注入）。**请以 `需复核` 为准做人工判断。**",
        "",
        "## 汇总",
        "",
        "| # | 告警摘要 | 判定 | 需复核 | 建议动作（未执行） | 耗时 |",
        "|---|---|---|---|---|---|",
    ]
    for a in sorted(alerts, key=lambda x: (_RANK.get(x.verdict, 3), x.idx)):
        acts = ", ".join(f"`{x}`" for x in a.actions) or "—"
        lines.append(f"| {a.idx} | {a.head[:60]} | {a.verdict} | "
                     f"{'是' if a.needs_review else '否'} | {acts} | {a.latency_s}s |")

    lines += ["", "## 逐条", ""]
    for a in alerts:
        lines += [
            f"### {a.idx}. {a.head}",
            "",
            f"- 判定：**{a.verdict}**（明确认定={a.attack_strict}，模糊语气={a.hedged}）",
            f"- 标记注入：{a.injection_flagged}（⚠ 该标记本身可能是幻觉，需人工核实）",
            f"- 需人工复核：**{'是' if a.needs_review else '否'}**；接地校验通过={a.grounded_ok}"
            f"；纠正重试={a.retries}；耗时={a.latency_s}s；token={a.tokens}",
        ]
        if a.rejected:
            lines.append(f"- 被闸门拒绝的动作：{len(a.rejected)} 项（"
                         + "；".join(str(r)[:80] for r in a.rejected[:2]) + "）")
        if a.action_details:
            lines.append("- 建议动作（**未执行**）：")
            for d in a.action_details:
                lines.append(f"  - `{json.dumps(d, ensure_ascii=False)}`")
        else:
            lines.append("- 建议动作（**未执行**）：无")
        lines += ["", "<details><summary>模型原始回答</summary>", "", "```", a.answer, "```", "",
                  "</details>", ""]
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="日志研判副驾（只读）")
    ap.add_argument("--log", help="日志文件路径（火绒/系统日志导出均可）")
    ap.add_argument("--demo", action="store_true", help="使用内置样例日志")
    ap.add_argument("--backend", default="llamacpp")
    ap.add_argument("--split-regex", default=DEFAULT_SPLIT)
    ap.add_argument("--max-chars", type=int, default=2000)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--out", default="reports/triage_report.md")
    ap.add_argument("--json", dest="json_out", default="reports/triage_report.json")
    args = ap.parse_args(argv)

    if args.demo:
        text, source, name = _DEMO_LOG, "<内置样例：4 条合成遥测>", "demo"
    elif args.log:
        p = Path(args.log)
        if not p.exists():
            raise SystemExit(f"日志文件不存在：{p}")
        text, source, name = p.read_text(encoding="utf-8", errors="replace"), str(p), p.stem
    else:
        ap.error("需要 --log 或 --demo")

    alerts = split_alerts(text, args.split_regex, args.max_chars)
    if args.limit:
        alerts = alerts[:args.limit]
    print(f"解析出 {len(alerts)} 条候选告警，开始逐条研判（只读模式）…", flush=True)

    agent = build_agent(args.backend)
    for a in alerts:
        triage_one(agent, a)
        print(f"  [{a.idx}/{len(alerts)}] {a.verdict:<8} 复核={'是' if a.needs_review else '否'} "
              f"{a.latency_s}s  {a.head[:48]}", flush=True)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(alerts, source), encoding="utf-8")
    if args.json_out:
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(json.dumps(
            {"source": source, "readonly": True, "pins": READONLY_PINS,
             "alerts": [a.to_dict() for a in alerts]}, ensure_ascii=False, indent=2),
            encoding="utf-8")

    n_atk = sum(1 for a in alerts if a.verdict == "attack")
    n_rev = sum(1 for a in alerts if a.needs_review)
    print(f"\n完成：{n_atk} 条判为攻击 / {n_rev} 条需人工复核（共 {len(alerts)}）")
    print(f"报告：{out}（只读，未执行任何动作）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
