#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cyber_range/eval_cyborg.py — 用 CybORG 对 Agent 做测试与调优。

在被测 Agent 与靶场之间做一层薄封装：

    观测(Observation) → BlueTeamAgent.ask() → 动作(schema 校验后) → 环境 step → 指标

指标（比单一 reward 更能定位问题）:
  * `mean_reward`            平均回报
  * `schema_valid_rate`      产出动作中通过白名单的比例（R3 是否真的落地）
  * `containment_step`       首次对「当步受害主机」执行隔离的步序（越小越快）
  * `false_isolation_rate`   隔离了非受害主机的比例（误伤度量）
  * `review_rate`            需要人工复核的回合比例（接地校验/无动作）
  * `latency_p50/p95`        单次 ask 的延迟
  * `actions_per_step`       处置强度（过高说明过度处置）

调优（`--sweep`）：对 RAG top_k / 接地校验开关 / 提示温度做网格搜索，
按 `mean_reward` 主排序、`false_isolation_rate` 次排序，输出推荐组合并落盘。

用法:
    python cyber_range/eval_cyborg.py --episodes 4 --steps 8                 # 离线(stub)
    python cyber_range/eval_cyborg.py --episodes 4 --backend ollama           # 真实模型
    python cyber_range/eval_cyborg.py --sweep                                 # 网格搜索
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "training"))

from security.action_schema import Action, SchemaError, validate_action  # noqa: E402
from security.sanitize import get_logger  # noqa: E402

LOG = get_logger("cyborg.eval")

REPORT_PATH = PROJECT_ROOT / "logs" / "cyborg_eval.json"


# --------------------------------------------------------------------------- #
#  策略封装
# --------------------------------------------------------------------------- #

def _obs_to_alert(obs) -> str:
    """把靶场观测渲染成 Agent 能吃的告警文本。"""
    host_lines = "；".join(
        f"{h} 健康度 {v:.2f}{'（疑似失陷）' if v < 0.7 else ''}"
        for h, v in sorted(obs.hosts.items())
    )
    alerts = "；".join(
        f"[{a['severity']}] {a['host']} 命中 {a.get('ttp', 'n/a')}：{a['signature']}"
        for a in obs.alerts[-3:]
    ) or "无"
    return (f"靶场态势（step {obs.step}）：主机状态 {host_lines}。"
            f"近期告警：{alerts}。")


def _to_actions(resp_actions: List[Dict[str, Any]]) -> Tuple[List[Action], List[str]]:
    """把 Agent 输出的动作字典重新过一遍 schema（双重保险）。"""
    good: List[Action] = []
    bad: List[str] = []
    for raw in resp_actions:
        try:
            good.append(validate_action({"action": raw.get("action"), "args": raw.get("args", {}),
                                         "rationale": raw.get("rationale", "")}))
        except SchemaError as exc:
            bad.append(str(exc))
    return good, bad


@dataclass
class StepRecord:
    episode: int
    step: int
    actions: List[str]
    reward: float
    avg_health: float
    victim: Optional[str]
    isolated: List[str]
    needs_review: bool
    grounded_ok: bool
    latency_s: float
    rejected: List[str] = field(default_factory=list)


def run_episodes(agent, env, episodes: int, steps: int, seed: int = 3407) -> List[StepRecord]:
    records: List[StepRecord] = []
    for ep in range(episodes):
        obs = env.reset()
        if hasattr(env, "rng"):
            env.rng.seed(seed + ep)
        for _ in range(steps):
            red = env.red_step() if hasattr(env, "red_step") else None
            if red is not None:
                obs.red_ttp = red

            alert = _obs_to_alert(obs)
            t0 = time.time()
            resp = agent.ask(alert)
            latency = time.time() - t0

            actions, bad = _to_actions(resp.actions)
            obs_next, reward, details = env.step(
                red or {"id": "n/a", "name": "n/a", "intent": "无"}, actions)
            obs = obs_next

            isolated = [a.args.get("host_id") for a in actions if a.name == "isolate_host"]
            records.append(StepRecord(
                episode=ep, step=obs.step,
                actions=[a.name for a in actions],
                reward=reward,
                avg_health=float(details.get("avg_health", 0.0)),
                victim=details.get("victim"),
                isolated=[h for h in isolated if h],
                needs_review=resp.needs_review,
                grounded_ok=resp.grounded_ok,
                latency_s=round(latency, 3),
                rejected=bad + resp.rejected_actions,
            ))
            LOG.info("[ep %d step %d] actions=%-38s reward=%+.3f health=%.2f review=%s",
                     ep, obs.step, str([a.name for a in actions]), reward,
                     details.get("avg_health", 0.0), resp.needs_review)
    return records


def summarize(records: List[StepRecord]) -> Dict[str, Any]:
    if not records:
        return {"steps": 0}
    total = len(records)
    with_actions = [r for r in records if r.actions]
    n_actions = sum(len(r.actions) for r in with_actions)
    n_rejected = sum(len(r.rejected) for r in records)

    containment = None
    for r in records:
        if r.victim and r.victim in r.isolated:
            containment = r.step
            break
    iso_total = sum(len(r.isolated) for r in records)
    iso_wrong = sum(1 for r in records for h in r.isolated if h != r.victim)

    lat = sorted(r.latency_s for r in records)

    def pct(p: float) -> float:
        return round(lat[min(len(lat) - 1, int(len(lat) * p))], 3)

    return {
        "steps": total,
        "mean_reward": round(statistics.fmean(r.reward for r in records), 4),
        "final_avg_health": records[-1].avg_health,
        "schema_valid_rate": round(n_actions / max(1, n_actions + n_rejected), 4),
        "rejected_actions": n_rejected,
        "containment_step": containment,
        "isolations": iso_total,
        "false_isolation_rate": round(iso_wrong / max(1, iso_total), 4),
        "review_rate": round(sum(1 for r in records if r.needs_review) / total, 4),
        "grounded_rate": round(sum(1 for r in records if r.grounded_ok) / total, 4),
        "actions_per_step": round(n_actions / total, 3),
        "latency_p50": pct(0.5),
        "latency_p95": pct(0.95),
    }


# --------------------------------------------------------------------------- #
#  环境
# --------------------------------------------------------------------------- #

def make_env(seed: int = 3407):
    try:
        import CybORG  # noqa: F401,PLC0415
        LOG.warning("检测到 CybORG，但本脚本使用统一抽象接口；如需原生接口请扩展 make_env()。")
    except ImportError:
        LOG.info("使用内置 MockRangeEnv（离线确定性靶场）")
    from red_blue_loop import MockRangeEnv  # noqa: PLC0415
    return MockRangeEnv(seed=seed)


# --------------------------------------------------------------------------- #
#  调优
# --------------------------------------------------------------------------- #

def _agent_with_overrides(overrides: Dict[str, Any], backend: Optional[str]):
    import yaml  # noqa: PLC0415

    cfg = yaml.safe_load((PROJECT_ROOT / "agent" / "config.yaml").read_text(encoding="utf-8"))
    if backend:
        cfg["backend"] = backend
    for dotted, value in overrides.items():
        node = cfg
        parts = dotted.split(".")
        for p in parts[:-1]:
            node = node.setdefault(p, {})
        node[parts[-1]] = value
    tmp = PROJECT_ROOT / "logs" / "agent_cfg_sweep.yaml"
    tmp.write_text(yaml.safe_dump(cfg, allow_unicode=True), encoding="utf-8")
    return tmp


def sweep(episodes: int, steps: int, backend: Optional[str]) -> Dict[str, Any]:
    from agent.agent import BlueTeamAgent  # noqa: PLC0415

    if (backend or "stub") == "stub":
        LOG.warning("当前后端是 stub：它不消费 RAG/情报上下文（只用正则取主机名与地址），"
                    "因此各配置的指标会**完全相同**、无法用于调参。"
                    "要做真实调优请加 --backend ollama（或 local）。")

    # 网格：RAG 开关/top_k 与接地校验的交互。真实模型下每次生成 10~20s，
    # 因此统一把生成长度压到 256 tokens 控制总耗时。
    grid = [
        {"local.max_new_tokens": 256, "rag.enabled": True, "grounding.enforce": True, "rag.top_k": 5},
        {"local.max_new_tokens": 256, "rag.enabled": True, "grounding.enforce": True, "rag.top_k": 3},
        {"local.max_new_tokens": 256, "rag.enabled": True, "grounding.enforce": False, "rag.top_k": 5},
        {"local.max_new_tokens": 256, "rag.enabled": False, "grounding.enforce": False},
    ]
    results: List[Dict[str, Any]] = []
    for overrides in grid:
        cfg_path = _agent_with_overrides(overrides, backend)
        agent = BlueTeamAgent(cfg_path)
        env = make_env()
        summary = summarize(run_episodes(agent, env, episodes, steps))
        results.append({"overrides": overrides, **summary})
        LOG.info("[sweep] %s -> reward=%.4f 误隔离=%.2f 复核率=%.2f",
                 overrides, summary["mean_reward"],
                 summary["false_isolation_rate"], summary["review_rate"])

    ranked = sorted(results, key=lambda r: (-r["mean_reward"], r["false_isolation_rate"]))
    return {"grid": results, "best": ranked[0] if ranked else None}


# --------------------------------------------------------------------------- #
#  main
# --------------------------------------------------------------------------- #

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="CybORG 上的 Agent 测试与调优")
    ap.add_argument("--episodes", type=int, default=4)
    ap.add_argument("--steps", type=int, default=8)
    ap.add_argument("--seed", type=int, default=3407)
    ap.add_argument("--backend", default=None, help="覆盖 agent 后端: stub/ollama/local")
    ap.add_argument("--sweep", action="store_true", help="对 RAG/接地做网格搜索")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if args.sweep:
        out = sweep(args.episodes, args.steps, args.backend)
        REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        REPORT_PATH.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps({"best": out["best"]}, ensure_ascii=False, indent=2))
        return 0

    from agent.agent import BlueTeamAgent  # noqa: PLC0415

    cfg_path = _agent_with_overrides({}, args.backend)
    agent = BlueTeamAgent(cfg_path)
    env = make_env(args.seed)
    records = run_episodes(agent, env, args.episodes, args.steps, args.seed)
    summary = summarize(records)

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(
        {"summary": summary, "records": [r.__dict__ for r in records]},
        ensure_ascii=False, indent=2), encoding="utf-8")

    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print("=== CybORG 评测 ===")
        for k, v in summary.items():
            print(f"  {k:<22} {v}")
        print(f"\n详细记录: {REPORT_PATH.relative_to(PROJECT_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
