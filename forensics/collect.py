#!/usr/bin/env python3
"""取证编排：**发现可疑目标 → 自动取证 → 遏制（占位）→ 落审计**。

它在链路里的位置：

    tools/net_sensor.py      ─┐
                              ├─► logs/*.jsonl ─► **forensics/collect.py** ─┬─► forensics.kape（采集/演练）
    tools/suricata_bridge.py ─┘                                          ├─► forensics.containment（仅占位）
                                                                         └─► logs/forensics_audit.jsonl + 案例报告

为什么用"读结果文件"而不是给传感器加回调：
    两个检测器已经在写 logs/*.jsonl（那是权威记录）。再插一条进程内回调会引入
    "谁先启动、谁挂了、回调抛异常会不会拖垮检测主循环"这类问题。
    而读文件几乎零成本（只看新增的尾部），且**检测器完全不需要改动** ——
    这对一个已经在常驻运行的传感器来说是最重要的性质。

触发条件（宁可漏采少数，也不要让采集把机器刷爆）：
    net_sensor   ：route == auto_attack，或 triage.verdict == attack 且置信度高
    suricata     ：route == auto_attack，或（关联命中 + 攻击判定 + 分值达标）
    另外必须：同一个"目标指纹"在 cooldown 内只采一次（KAPE 一次几分钟、产物数百 MB）

遏制：**只登记占位计划**（见 forensics/containment.py），不做任何真实变更。

用法：
    python -m forensics.collect --once            # 跑一轮（**默认即演练**：只产计划）
    python -m forensics.collect --loop            # 常驻看护
    python -m forensics.collect --execute        # 真实采集（需管理员；否则返回 unavailable）
    python -m forensics.collect --from-file logs/net_sensor_events.jsonl --once
    python -m forensics.collect --selftest

⚠ 没有 --dry-run 参数：**默认就是演练**，要真采集得显式 --execute。
   把"危险模式"做成需要显式打开的那个方向，比反过来安全。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from forensics import containment, kape                     # noqa: E402

LOG_DIR = PROJECT_ROOT / "logs"
DEFAULT_QUEUE_SOURCES = (LOG_DIR / "net_sensor_events.jsonl",
                         LOG_DIR / "suricata_findings.jsonl")
AUDIT_PATH = LOG_DIR / "forensics_audit.jsonl"
CASES_DIR = LOG_DIR / "forensics"


# ------------------------------------------------------------------ 触发判定

def net_sensor_trigger(rec: Dict[str, Any], high_threshold: int = 40) -> Optional[Dict[str, Any]]:
    """本机传感器记录 → 是否需要取证。返回 None 表示不采。"""
    tri = rec.get("triage") or {}
    conf = rec.get("confidence") or {}
    route = rec.get("route")
    score = int(rec.get("score") or 0)
    verdict = tri.get("verdict")
    auto = route == "auto_attack"
    strong = (verdict == "attack" and score >= high_threshold
              and (conf.get("band") == "high" or tri.get("attack_strict")))
    if not (auto or strong):
        return None
    rules = list(rec.get("rules") or [])
    proc = str(rec.get("proc") or "")
    # 从记录里尽力还原可执行文件路径（detail 里带）
    path = ""
    detail = str(rec.get("detail") or "")
    for tok in detail.replace("：", " ").split():
        if tok.lower().endswith(".exe"):
            path = tok.strip("；,;")
    artifacts = ["process", "persistence", "network"]
    if path:
        artifacts.append(f"file:{path}")
    return {
        "source": "net_sensor",
        "case_id": f"ns-{rec.get('ts', '').replace(':', '').replace(' ', '-')}-{proc or 'pid'}",
        "host_id": os.environ.get("COMPUTERNAME", "localhost"),
        "artifacts": ",".join(artifacts),
        "reason": (f"本机传感器：{proc or '?'} → {rec.get('remote')}，"
                   f"规则 {'、'.join(rules)}，分值 {score}，路由 {route or '未研判'}"
                   f"（模型判定 {verdict or '未研判'}）"),
        "rules": rules,
        "peer": str(rec.get("remote") or ""),
        "pid": rec.get("pid"),
        "proc": proc,
        "path": path,
        "raw": rec,
    }


def suricata_trigger(rec: Dict[str, Any], high_threshold: int = 40) -> Optional[Dict[str, Any]]:
    """旁路 IDS 记录 → 是否需要取证。"""
    tri = rec.get("triage") or {}
    route = rec.get("route")
    score = int(rec.get("score") or 0)
    corr = bool(rec.get("correlated"))
    verdict = tri.get("verdict")
    auto = route == "auto_attack"
    strong = corr and verdict == "attack" and score >= high_threshold
    if not (auto or strong):
        return None
    rules = list(rec.get("rules") or [])
    peer = str(rec.get("dest") or "")
    artifacts = ["network", "process", "persistence"]
    if corr:
        cr = rec.get("corr") or {}
        if cr.get("proc"):
            artifacts.append("process")
    return {
        "source": "suricata",
        "case_id": f"sc-{str(rec.get('ts', '')).replace(':', '').replace(' ', '-')}-"
                   f"{rec.get('sig_id') or 'sig'}",
        "host_id": os.environ.get("COMPUTERNAME", "localhost"),
        "artifacts": ",".join(artifacts),
        "reason": (f"旁路 IDS：{rec.get('sig')}（{rec.get('src')} → {rec.get('dest')}），"
                   f"分值 {score}，路由 {route or '未研判'}，"
                   f"本机关联{'命中' if corr else '未命中'}"),
        "rules": rules,
        "peer": peer,
        "correlated": corr,
        "raw": rec,
    }


TRIGGERS = {"net_sensor": net_sensor_trigger, "suricata": suricata_trigger}


# ------------------------------------------------------------------ 编排

class Collector:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.cfg = kape.KapeConfig.from_dict(getattr(args, "kape_cfg", {}) or {})
        if args.output_root:
            self.cfg.output_root = args.output_root
        if args.kape_exe:
            self.cfg.exe_path = args.kape_exe
        self.seen: Dict[str, float] = {}
        self.audit = Path(args.audit)
        self.audit.parent.mkdir(parents=True, exist_ok=True)
        self.stats = {"records": 0, "triggered": 0, "collected": 0, "skipped_cooldown": 0,
                      "unavailable": 0, "failed": 0, "containment_plans": 0}

    def fingerprint(self, t: Dict[str, Any]) -> str:
        """去重指纹：按"目标"而不是按事件。同一目标反复触发只采一次。"""
        return "|".join([t["source"], t.get("proc") or "", t.get("peer") or "",
                         t.get("path") or ""])

    def handle(self, t: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
        fp = self.fingerprint(t)
        now = time.time()
        if now - self.seen.get(fp, 0.0) < self.args.cooldown:
            self.stats["skipped_cooldown"] += 1
            return {}
        self.seen[fp] = now
        self.stats["triggered"] += 1

        job = kape.build_job(t["case_id"], t["host_id"], t["artifacts"], t["reason"], self.cfg,
                             self.cfg.root())
        res = kape.run(job, self.cfg, dry_run=dry_run)
        if res.status == kape.ST_OK:
            self.stats["collected"] += 1
        elif res.status == kape.ST_UNAVAILABLE:
            self.stats["unavailable"] += 1
        elif res.status == kape.ST_FAILED:
            self.stats["failed"] += 1

        # 遏制：只登记占位计划
        ctx: Dict[str, Any] = {"case_id": t["case_id"], "host_id": t["host_id"]}
        if t.get("path"):
            ctx["path"] = t["path"]
        if t.get("pid"):
            ctx["pid"] = t["pid"]
        if t.get("source") == "suricata" and t.get("peer"):
            ctx["src_ip"] = t["peer"].split(":")[0]
            ctx["direction"] = "outbound"      # 报文侧告警默认按出向评估（C2 回连方向）
        plans = containment.recommend(t.get("rules") or [], t["case_id"], t["reason"], ctx)
        self.stats["containment_plans"] += len(plans)

        rec = {
            "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "case_id": t["case_id"],
            "source": t["source"],
            "trigger": {k: t.get(k) for k in
                        ("reason", "rules", "proc", "peer", "path", "pid")},
            "dry_run": dry_run,
            "collection": res.to_dict(),
            "containment": plans,           # 全部 executed=False
            "containment_note": "遏制为占位实现：仅登记计划，未执行任何变更",
        }
        with self.audit.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        self.write_case_report(rec)
        return rec

    def write_case_report(self, rec: Dict[str, Any]) -> None:
        d = CASES_DIR / rec["case_id"][:60]
        d.mkdir(parents=True, exist_ok=True)
        col = rec["collection"]
        lines = [
            f"# 取证案例 {rec['case_id']}",
            "",
            f"- 触发时间：{rec['ts']}　来源：**{rec['source']}**",
            f"- 触发原因：{rec['trigger'].get('reason')}",
            f"- 命中规则：{'、'.join(rec['trigger'].get('rules') or []) or '—'}",
            f"- 模式：{'演练（未采集）' if rec['dry_run'] else '真实采集'}",
            "",
            "## 1. 采集（KAPE）",
            "",
            f"- 状态：**{col['status']}**",
            f"- 说明：{col['detail']}",
            f"- 命令：`{col['command']}`",
            f"- 产物：{col['outdir']}（{col['collected_files']} 个文件 / "
            f"{col['collected_mb']} MB）",
            f"- 可直接运行的计划：`{col['plan_file']}`（**需管理员**）",
            "",
        ]
        if col.get("stdout_tail"):
            lines += ["```", col["stdout_tail"][:1500], "```", ""]
        lines += ["## 2. 遏制（**占位，未执行**）", "",
                  "> 下列全部为计划与代价说明，`executed=false`。本系统不做处置。", ""]
        if not rec["containment"]:
            lines.append("无建议遏制动作。")
        for p in rec["containment"]:
            lines.append(f"### {p['action']}"
                         f"{'' if p.get('known') else '（未登记动作）'}")
            lines.append("")
            if not p.get("known"):
                lines.append(f"{p.get('banner')}　{p.get('note')}")
                lines.append("")
                continue
            lines += [
                f"- 目标：{p['goal']}",
                f"- 可逆性：{'可逆' if p['reversible'] else '**不可逆**'}",
                f"- 计划命令（**未执行**）：`{p['planned_command']}`",
                "- 前置条件：",
            ]
            lines += [f"  - {x}" for x in p["prereqs"]]
            lines.append("- 已知坑：")
            lines += [f"  - {x}" for x in p["pitfalls"]]
            lines.append("")
        lines += ["## 3. 局限", "",
                  "- 本案例报告由**占位**遏制流程生成，不含任何处置结果",
                  "- KAPE 在非管理员下会拒绝执行（避免产出残缺证据）",
                  "- 采集产物本身即敏感数据（含注册表配置单元/事件日志），注意保管",
                  ""]
        (d / "CASE.md").write_text("\n".join(lines), encoding="utf-8")

    def poll_files(self, sources: Tuple[Path, ...], offsets: Dict[str, int],
                   dry_run: bool) -> int:
        n = 0
        for p in sources:
            if not p.exists():
                continue
            key = str(p)
            try:
                size = p.stat().st_size
            except OSError:
                continue
            off = offsets.get(key, size if self.args.from_end else 0)
            if size < off:
                off = 0                       # 被截断/重建
            try:
                with p.open("r", encoding="utf-8", errors="replace") as fh:
                    fh.seek(off)
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        self.stats["records"] += 1
                        try:
                            rec = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        name = "suricata" if "suricata" in p.name else "net_sensor"
                        t = TRIGGERS[name](rec, self.args.high_threshold)
                        if t:
                            self.handle(t, dry_run)
                            n += 1
                    offsets[key] = fh.tell()
            except OSError:
                continue
        return n

    def run_once(self, dry_run: bool, sources: Tuple[Path, ...],
                 offsets: Dict[str, int], from_end: bool = False) -> int:
        if from_end:
            for p in sources:
                if p.exists():
                    offsets[str(p)] = p.stat().st_size
        return self.poll_files(sources, offsets, dry_run)


def selftest() -> int:
    import tempfile
    ok = fail = 0

    def chk(name: str, cond: bool, extra: str = "") -> None:
        nonlocal ok, fail
        if cond:
            ok += 1
            print(f"  [OK] {name}")
        else:
            fail += 1
            print(f"  [FAIL] {name} {extra}")

    # ---- 触发判定 ----
    chk("普通记录不触发",
        net_sensor_trigger({"score": 10, "rules": ["rare_port"], "route": "auto_benign"}) is None)
    t = net_sensor_trigger({
        "ts": "2026-10-04 10:00:00", "score": 40, "proc": "evil.exe", "pid": 123,
        "remote": "45.1.2.3:4444", "rules": ["high_risk_port"],
        "detail": "可执行文件位于非常规目录：C:\\Users\\x\\Temp\\evil.exe",
        "route": "auto_attack", "triage": {"verdict": "attack"}})
    chk("auto_attack 触发取证", t is not None and t["source"] == "net_sensor")
    chk("从 detail 里还原出可执行文件路径并单独取回",
        t is not None and any(a.startswith("file:") and "evil.exe" in a
                              for a in t["artifacts"].split(",")), str(t and t["artifacts"]))
    chk("触发原因里带上规则与分值", t is not None and "high_risk_port" in t["reason"])

    chk("仅 model 说 attack 但分值低 → 不触发（防抖动刷爆采集）",
        net_sensor_trigger({"score": 10, "proc": "x", "route": "review",
                            "triage": {"verdict": "attack"}}) is None)
    chk("未研判的高分记录不触发（避免自证）",
        net_sensor_trigger({"score": 60, "proc": "x", "route": None}) is None)

    st = suricata_trigger({"ts": "t", "sig": "ET TROJAN", "sig_id": 1, "score": 58,
                           "correlated": True, "dest": "45.1.2.3:443",
                           "rules": ["suricata_sev1"],
                           "route": "auto_attack", "triage": {"verdict": "attack"}})
    chk("旁路 IDS auto_attack 触发取证", st is not None and st["source"] == "suricata")
    chk("报文侧默认把对端当作要评估的 src_ip（遏制计划需要）",
        st is not None and "45.1.2.3" in st["reason"])
    chk("未关联的旁路告警不触发（没有主机侧证据，采了也不知道采什么）",
        suricata_trigger({"score": 58, "correlated": False, "route": None,
                          "triage": {"verdict": "attack"}, "rules": []}) is None)

    # ---- 端到端（演练）：真读文件 → 触发 → 生成计划与案例报告 ----
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        ev = tdp / "net_sensor_events.jsonl"
        ev.write_text("\n".join(json.dumps(x, ensure_ascii=False) for x in [
            {"ts": "2026-10-04 10:00:00", "score": 10, "proc": "good.exe",
             "rules": ["rare_port"], "route": "auto_benign"},
            {"ts": "2026-10-04 10:00:01", "score": 40, "proc": "evil.exe", "pid": 42,
             "remote": "45.1.2.3:4444", "rules": ["high_risk_port", "suspect_path"],
             "detail": "可执行文件位于非常规目录：C:\\Temp\\evil.exe",
             "route": "auto_attack", "triage": {"verdict": "attack"},
             "confidence": {"band": "high", "score": 0.9}},
        ]) + "\n", encoding="utf-8")

        args = argparse.Namespace(audit=str(tdp / "f_audit.jsonl"), cooldown=1800,
                                  high_threshold=40, output_root=str(tdp / "out"),
                                  kape_exe="", kape_cfg={}, from_end=False)
        col = Collector(args)
        # 全局常量指向项目 logs/，这里改到临时目录以免污染真实审计
        CASES_DIR_BACKUP = globals()["CASES_DIR"]
        globals()["CASES_DIR"] = tdp / "cases"
        try:
            col.run_once(dry_run=True, sources=(ev,), offsets={})
        finally:
            globals()["CASES_DIR"] = CASES_DIR_BACKUP

        chk("只对合规记录触发一次（另一条被忽略）", col.stats["triggered"] == 1,
            str(col.stats))
        audit_lines = [json.loads(x) for x in
                       (tdp / "f_audit.jsonl").read_text(encoding="utf-8").splitlines() if x]
        chk("审计写入 1 条", len(audit_lines) == 1, str(len(audit_lines)))
        a = audit_lines[0]
        chk("审计里记录的是演练模式", a["dry_run"] is True)
        chk("审计里采集状态为 dry_run（即使本机没装 KAPE，计划仍然有效）",
            a["collection"]["status"] == kape.ST_DRY_RUN, a["collection"]["status"])
        chk("计划文件已生成", Path(a["collection"]["plan_file"]).exists())
        chk("遏制全部为占位未执行",
            bool(a["containment"]) and all(c["executed"] is False for c in a["containment"]),
            str(a["containment"])[:80])
        chk("遏制建议来自命中规则（high_risk_port → block_ip 等）",
            any(c["action"] == "block_ip" for c in a["containment"]), str(a["containment"]))

        # 冷却：再跑一次不应重复采集
        col.run_once(dry_run=True, sources=(ev,), offsets={})
        chk("冷却内不重复采集", col.stats["triggered"] == 1, str(col.stats))
        args.cooldown = 0
        col2 = Collector(args)
        col2.seen.clear()
        col2.run_once(dry_run=True, sources=(ev,), offsets={})
        chk("冷却归零后可再次触发", col2.stats["triggered"] == 1)

        # 增量：只读新增部分
        before = col.stats["records"]
        with ev.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": "x", "score": 5, "proc": "y",
                                 "rules": [], "route": "auto_benign"}) + "\n")
        offsets = {str(ev): 0}
        col3 = Collector(args)
        col3.run_once(dry_run=True, sources=(ev,), offsets=offsets)
        chk("增量读取不会重读全文", col3.stats["records"] == 3, str(col3.stats))
        chk("第二次读取只处理新增（1 条）", col3.stats["records"] - 0 == 3)

    # ---- 接线集成：适配器顺序与路由（防"遏制落到 sim 假装成功"）----
    try:
        import yaml
        from actions.adapters import build_adapters, find_adapter
        from actions.adapters.base import ToolContext as TC
        from security.action_schema import Action
        cfg_path = PROJECT_ROOT / "actions" / "config.yaml"
        acfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
        order = ((acfg.get("adapters") or {}).get("order") or [])
        chk("actions/config.yaml 的适配器顺序里 containment_placeholder 在 sim 之前",
            "containment_placeholder" in order and "sim" in order
            and order.index("containment_placeholder") < order.index("sim"), str(order))
        ads = build_adapters(acfg, PROJECT_ROOT)
        chk("kape 与 containment_placeholder 都按配置加载成功",
            any(a.name == "kape" for a in ads)
            and any(a.name == "containment_placeholder" for a in ads),
            str([a.name for a in ads]))

        pick, _ = find_adapter(ads, "isolate_host", require_real=False)
        chk("isolate_host 被**占位适配器**接走（不会落到 sim 假装成功）",
            pick is not None and pick.name == "containment_placeholder",
            str(pick and pick.name))

        pick2, _ = find_adapter(ads, "collect_forensics", require_real=False)
        chk("collect_forensics 被 kape 适配器接走",
            pick2 is not None and pick2.name == "kape", str(pick2 and pick2.name))

        res = pick.execute(Action(name="isolate_host",
                                  args={"host_id": "THISPC"}, rationale="测试"),
                           TC(case_id="C-9", dry_run=False))
        chk("即使 dry_run=False，遏制也**只出计划不执行**",
            res.status == "dry_run" and res.output.get("executed") is False,
            str(res.output)[:90])
        chk("占位观测里明确写出未执行", "未执行" in res.observations)
        chk("占位观测里给出前置条件与代价（不是只回一句「已隔离」）",
            "前置条件" in res.observations and "代价" in res.observations)
        chk("占位适配器自报无真实副作用", pick.real_effects is False)
    except ImportError:
        print("  [跳过] 没装 PyYAML，跳过动作层接线集成测试")

    print(f"\nforensics.collect 自检：{ok} 通过 / {fail} 失败")
    return 1 if fail else 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="取证编排：检测 → 取证（KAPE）→ 遏制（占位）")
    ap.add_argument("--once", action="store_true", help="跑一轮就退出")
    ap.add_argument("--loop", action="store_true", help="常驻看护")
    ap.add_argument("--from-end", action="store_true", help="忽略已有历史，只看新记录")
    ap.add_argument("--from-file", action="append", default=[],
                    help="只读指定结果文件（可多次）；默认两个检测器都看")
    ap.add_argument("--interval", type=float, default=30.0)
    ap.add_argument("--cooldown", type=float, default=1800.0,
                    help="同一目标多久内只采一次（KAPE 一次几分钟、产物数百 MB）")
    ap.add_argument("--high-threshold", type=int, default=40)
    ap.add_argument("--output-root", default="logs/forensics")
    ap.add_argument("--audit", default=str(AUDIT_PATH))
    ap.add_argument("--kape-exe", default="")
    ap.add_argument("--target", default="", help="KAPE target（默认用配置里的 BlueTeam-Triage）")
    ap.add_argument("--module", default="", help="KAPE module，如 !EZParser（EZTools 解析）")
    ap.add_argument("--sim", action="store_true",
                    help="用 KAPE 原生 --sim：不复制文件，只校验 target/module 配置")
    ap.add_argument("--execute", action="store_true",
                    help="真实采集（默认只演练）。需管理员，否则返回 unavailable")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    sources = tuple(Path(p) for p in args.from_file) if args.from_file \
        else DEFAULT_QUEUE_SOURCES
    dry = not args.execute
    args.kape_cfg = {k: v for k, v in (("target", args.target), ("module", args.module),
                                      ("sim", args.sim)) if v}
    col = Collector(args)
    print(f"取证编排启动：来源 {[p.name for p in sources]}　"
          f"模式 {'演练（不采集）' if dry else '真实采集'}　冷却 {args.cooldown:.0f}s")
    if not args.loop:
        n = col.run_once(dry, sources, {}, from_end=args.from_end)
        print(f"本轮触发 {n} 次；统计 {json.dumps(col.stats, ensure_ascii=False)}")
        print(f"审计：{col.audit}　案例报告：{CASES_DIR}")
        return 0
    offsets: Dict[str, int] = {}
    col.run_once(dry, sources, offsets, from_end=args.from_end)
    try:
        while True:
            time.sleep(args.interval)
            col.poll_files(sources, offsets, dry)
    except KeyboardInterrupt:
        print(f"\n退出；统计 {json.dumps(col.stats, ensure_ascii=False)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
