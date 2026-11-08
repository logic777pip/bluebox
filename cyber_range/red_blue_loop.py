#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cyber_range/red_blue_loop.py — 红蓝对抗自博弈训练闭环（本地隔离沙箱）。

流程（每个 episode 的每个 step）:
    1. 环境给出观测（日志/告警摘要）
    2. 红队策略从【本地 TTP 目录】采样一个战术动作，只改变环境状态
    3. 蓝队 Agent（Qwen2.5-3B + LoRA，经 Ollama 推理）产出动作提案
    4. R3: security.action_schema.validate_action 校验，非法即拒绝并记罚
    5. R5: 不可逆动作走 TwoPhaseGuard 两阶段确认
    6. 执行（默认 --dry-run，打印不落地）→ 计算奖励 → 写入轨迹
    7. 轨迹落盘 data/rl_trajectories.jsonl，供后续 DPO/RLVR 复用

安全设计:
    * 红队仅使用【抽象战术标签】（ATT&CK 技术 ID + 自然语言意图），
      不包含任何漏洞利用、免杀、持久化载荷。
    * 默认 dry-run；真实执行需显式 --execute，且仍受白名单与确认门约束。
    * 所有日志经 security.sanitize 脱敏；网络请求带超时 + 重试上限。

用法:
    python cyber_range/red_blue_loop.py --model blue-team-agent --episodes 5 --dry-run
    python cyber_range/red_blue_loop.py --offline --episodes 3          # 不调用 LLM，用启发式蓝队
    python cyber_range/red_blue_loop.py --model blue-team-agent --execute
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security.action_schema import (  # noqa: E402
    Action,
    ConfirmationError,
    SchemaError,
    TwoPhaseGuard,
    parse_actions,
    validate_action,
)
from security.sanitize import get_logger, mask_text  # noqa: E402

LOG = get_logger("red_blue_loop")

PENDING_DIR = PROJECT_ROOT / "logs" / "pending"
TRAJ_PATH = PROJECT_ROOT / "data" / "rl_trajectories.jsonl"
REPORT_PATH = PROJECT_ROOT / "logs" / "red_blue_report.json"

NET_TIMEOUT = 60      # R2
NET_RETRIES = 3       # R2

# --------------------------------------------------------------------------- #
#  红队战术目录（仅抽象标签，用于驱动蓝队观测；不含任何攻击实现）
# --------------------------------------------------------------------------- #

RED_TTPS: List[Dict[str, str]] = [
    {"id": "T1110", "name": "Brute Force", "intent": "对某主机发起认证暴力尝试"},
    {"id": "T1078", "name": "Valid Accounts", "intent": "使用有效账号在异常时段登录"},
    {"id": "T1059", "name": "Command and Scripting Interpreter", "intent": "在主机上执行脚本"},
    {"id": "T1055", "name": "Process Injection", "intent": "把代码注入到正常进程"},
    {"id": "T1041", "name": "Exfiltration Over C2 Channel", "intent": "向内网外目标外传数据"},
    {"id": "T1486", "name": "Data Encrypted for Impact", "intent": "批量加密文件"},
    {"id": "T1566", "name": "Phishing", "intent": "向员工投递钓中邮件"},
    {"id": "T1021", "name": "Remote Services", "intent": "通过远程服务横向移动"},
    {"id": "T1053", "name": "Scheduled Task/Job", "intent": "注册计划任务保持驻留"},
    {"id": "T1071", "name": "Application Layer Protocol", "intent": "使用常见协议做 C2 通信"},
]


# --------------------------------------------------------------------------- #
#  环境：优先 CybORG，缺失时退化为本地轻量仿真
# --------------------------------------------------------------------------- #

@dataclass
class Observation:
    step: int
    hosts: Dict[str, float]          # host -> 健康度 0..1
    alerts: List[Dict[str, Any]] = field(default_factory=list)
    red_ttp: Optional[Dict[str, str]] = None

    def to_prompt_text(self) -> str:
        host_lines = "\n".join(
            f"- {h}: 健康度 {v:.2f}, {'疑似失陷' if v < 0.7 else '正常'}"
            for h, v in sorted(self.hosts.items())
        )
        alert_lines = "\n".join(
            f"- [{a['severity']}] {a['host']} | {a['signature']} | 命中 {a.get('ttp', 'n/a')}"
            for a in self.alerts
        ) or "- 无"
        red = self.red_ttp
        red_line = f"{red['name']} ({red['id']})" if red else "无"
        return (
            f"【当前态势 · step {self.step}】\n"
            f"主机状态:\n{host_lines}\n"
            f"告警:\n{alert_lines}\n"
            f"近期红队活动（已观测到）: {red_line}\n"
            f"请基于以上证据给出下一步防御动作。"
        )


class MockRangeEnv:
    """本地轻量仿真：无需 CybORG 即可跑通红蓝闭环（用于开发与冒烟）。"""

    HOSTS = ["host_a", "host_b", "host_c", "host_d"]

    def __init__(self, seed: int = 3407) -> None:
        self.rng = random.Random(seed)
        self.step_idx = 0
        self.hosts: Dict[str, float] = {h: 1.0 for h in self.HOSTS}
        self.alerts: List[Dict[str, Any]] = []

    def reset(self) -> Observation:
        self.step_idx = 0
        self.hosts = {h: 1.0 for h in self.HOSTS}
        self.alerts = []
        return self._obs(None)

    def red_step(self) -> Dict[str, str]:
        return dict(self.rng.choice(RED_TTPS))

    def _obs(self, red: Optional[Dict[str, str]]) -> Observation:
        return Observation(self.step_idx, dict(self.hosts), list(self.alerts[-5:]), red)

    def step(self, red_ttp: Dict[str, str], blue_actions: List[Action]) -> Tuple[Observation, float, Dict[str, Any]]:
        """推进一个红蓝同时刻。返回 (观测, 蓝队奖励, 详情)。"""
        self.step_idx += 1

        # --- 红队影响（抽象：仅降低健康度并产生告警） ---
        victim = self.rng.choice(list(self.hosts))
        self.hosts[victim] = max(0.0, self.hosts[victim] - self.rng.uniform(0.10, 0.30))
        self.alerts.append({
            "severity": self.rng.choice(["MEDIUM", "HIGH", "CRITICAL"]),
            "host": victim,
            "signature": red_ttp["intent"],
            "ttp": red_ttp["id"],
        })

        # --- 蓝队效果 ---
        reward = 0.0
        details: Dict[str, Any] = {"effects": []}
        for act in blue_actions:
            if act.name == "isolate_host" and act.args.get("host_id") in self.hosts:
                h = act.args["host_id"]
                self.hosts[h] = min(1.0, self.hosts[h] + 0.15)
                reward += 0.3 if h == victim else -0.1     # 隔离对目标加分，误伤扣分
                details["effects"].append(f"isolation:{h}")
            elif act.name == "block_ip":
                reward += 0.2
                details["effects"].append("firewall:block")
            elif act.name == "query_logs":
                reward += 0.1
                details["effects"].append("visibility+")
            elif act.name == "collect_forensics":
                reward += 0.15
                details["effects"].append("evidence+")
            elif act.name == "notify_analyst":
                reward += 0.05
            elif act.name == "kill_process":
                h = act.args.get("host_id")
                if h == victim:
                    self.hosts[h] = min(1.0, self.hosts[h] + 0.10)
                    reward += 0.2
                else:
                    reward -= 0.2
            elif act.name == "close_case":
                reward -= 0.3 if self.hosts[victim] < 0.7 else 0.0   # 过早结案扣分

        # 全局态势奖励
        avg = sum(self.hosts.values()) / len(self.hosts)
        reward += (avg - 0.8) * 0.5
        details["avg_health"] = round(avg, 3)
        details["victim"] = victim
        return self._obs(red_ttp), round(reward, 4), details

    def score(self) -> float:
        return round(sum(self.hosts.values()) / len(self.hosts), 4)


def make_env(seed: int):
    """优先使用 CybORG（若已按 deploy_cyborg.sh 部署），否则回退 MockRangeEnv。"""
    try:
        import CybORG  # noqa: F401
        LOG.info("检测到 CybORG，但本脚本仅使用其抽象观测接口；如需原生接口请扩展 make_env()。")
    except ImportError:
        LOG.warning("未检测到 CybORG，使用内置 MockRangeEnv（仅用于闭环联调）。")
    return MockRangeEnv(seed=seed)


# --------------------------------------------------------------------------- #
#  LLM 客户端（Ollama）—— R2 超时 + 重试上限
# --------------------------------------------------------------------------- #

class OllamaClient:
    def __init__(self, model: str, host: Optional[str] = None, temperature: float = 0.2) -> None:
        self.model = model
        # R4: 不硬编码任何凭据；host 从参数或环境变量读取
        self.host = (host or os.environ.get("OLLAMA_HOST") or "http://127.0.0.1:11434").rstrip("/")
        self.temperature = temperature
        self.token = os.environ.get("OLLAMA_API_TOKEN")  # 本地 Ollama 通常无需

    def chat(self, system: str, user: str) -> str:
        url = f"{self.host}/api/chat"
        payload = json.dumps({
            "model": self.model,
            "stream": False,
            "options": {"temperature": self.temperature, "num_ctx": 4096},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }).encode("utf-8")

        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        last_exc: Optional[Exception] = None
        for attempt in range(1, NET_RETRIES + 1):
            req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=NET_TIMEOUT) as resp:
                    body = json.loads(resp.read().decode("utf-8"))
                return str(body.get("message", {}).get("content", ""))
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                last_exc = exc
                if attempt == NET_RETRIES:
                    break
                backoff = 2 ** (attempt - 1)
                LOG.warning("Ollama 请求失败 (%d/%d): %s — %ds 后重试",
                            attempt, NET_RETRIES, mask_text(str(exc)), backoff)
                time.sleep(backoff)
        raise RuntimeError(f"Ollama 调用失败: {mask_text(str(last_exc))}")

    def healthy(self) -> bool:
        try:
            req = urllib.request.Request(f"{self.host}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except Exception:  # noqa: BLE001
            return False


# --------------------------------------------------------------------------- #
#  蓝队策略：LLM 提案 + 启发式回退
# --------------------------------------------------------------------------- #

BLUE_SYSTEM_PROMPT = (
    "你是蓝队应急响应 Agent。基于观测输出 1-2 个防御动作，每个动作单独一行 JSON，"
    '格式 {"action": "<白名单动作>", "args": {...}, "rationale": "<理由>"}。'
    "白名单: query_logs, collect_forensics, notify_analyst, block_ip, isolate_host, "
    "kill_process, quarantine_file, disable_account, restore_host, close_case。"
    "禁止输出白名单外的动作或额外字段。只需输出 JSON，不要解释。"
)


def blue_propose_llm(client: OllamaClient, obs: Observation) -> Tuple[List[Action], List[str]]:
    text = client.chat(BLUE_SYSTEM_PROMPT, obs.to_prompt_text())
    raw_actions = parse_actions(text)
    rejected: List[str] = []
    valid: List[Action] = []
    for act in raw_actions:
        valid.append(act)          # parse_actions 内部已做 schema 校验
    if not raw_actions:
        rejected.append("模型未产出合法动作（schema 校验失败）")
    return valid, rejected


def blue_propose_heuristic(obs: Observation) -> Tuple[List[Action], List[str]]:
    """离线回退策略：按「遏制 > 取证 > 可见性」优先级给出至多 2 个动作。

    仅做防御动作，保证闭环可在无 LLM 环境下跑通与回归。
    """
    worst_host = min(obs.hosts, key=obs.hosts.get) if obs.hosts else None
    worst_health = obs.hosts.get(worst_host, 1.0) if worst_host else 1.0
    has_critical = any(a["severity"] == "CRITICAL" for a in obs.alerts)

    candidates: List[Tuple[str, Dict[str, Any], str]] = []
    if worst_host and worst_health < 0.6:
        candidates.append(("isolate_host", {"host_id": worst_host, "mode": "soft"},
                           "健康度低于 0.6，优先软隔离阻断扩散"))
    if worst_host and worst_health < 0.8:
        candidates.append(("collect_forensics", {"host_id": worst_host, "artifacts": ["memory", "autoruns"]},
                           "固定易失性证据"))
    if has_critical:
        candidates.append(("notify_analyst", {"summary": "出现 CRITICAL 告警", "severity": "CRITICAL"},
                           "升级到值班分析员"))
    if obs.red_ttp is not None:
        candidates.append(("query_logs", {"host_id": sorted(obs.hosts)[0], "query": "auth,failed_login"},
                           "补充可见性以确认红队战术"))

    out: List[Action] = []
    rejected: List[str] = []
    for name, aargs, why in candidates[:2]:
        try:
            out.append(validate_action({"action": name, "args": aargs, "rationale": why}))
        except SchemaError as exc:
            rejected.append(f"{name}: {exc}")
            LOG.warning("启发式动作被 schema 拒绝: %s", exc)
    return out, rejected


# --------------------------------------------------------------------------- #
#  执行器（R5：不可逆动作两阶段确认；默认 dry-run）
# --------------------------------------------------------------------------- #

class Executor:
    def __init__(self, execute: bool, auto_confirm: bool, ttl: int = 300) -> None:
        self.execute = execute
        self.auto_confirm = auto_confirm
        self.guard = TwoPhaseGuard(PENDING_DIR, ttl_seconds=ttl)
        self.stats = {"proposed": 0, "confirmed": 0, "denied": 0, "dry_run": 0}

    def apply(self, act: Action, case_id: str) -> Dict[str, Any]:
        if not act.irreversible:
            self.stats["proposed"] += 1
            return self._run(act)

        proposal_id, _record = self.guard.propose(act, case_id=case_id)
        if not self.auto_confirm:
            LOG.warning("不可逆动作待人工确认: id=%s action=%s args=%s",
                        proposal_id, act.name, mask_text(json.dumps(act.args, ensure_ascii=False)))
            self.stats["denied"] += 1
            return {"status": "pending_confirmation", "proposal_id": proposal_id}

        signature = self.guard.expected_signature(proposal_id, act)
        try:
            self.guard.confirm(proposal_id, signature, act)
            self.stats["confirmed"] += 1
            LOG.info("两阶段确认通过: id=%s action=%s", proposal_id, act.name)
            return self._run(act)
        except ConfirmationError as exc:
            self.stats["denied"] += 1
            LOG.error("确认失败，动作丢弃: %s", exc)
            return {"status": "confirmation_failed", "reason": str(exc)}

    def _run(self, act: Action) -> Dict[str, Any]:
        if not self.execute:
            self.stats["dry_run"] += 1
            LOG.info("[dry-run] 跳过执行: %s %s", act.name,
                     mask_text(json.dumps(act.args, ensure_ascii=False)))
            return {"status": "dry_run", "action": act.name}
        # 真实执行点：此处对接 SOAR / EDR / 防火墙 API（部署时按环境实现）
        LOG.warning("[execute] 调用后端执行 %s（需在目标环境接入实际 SOAR/EDR 适配器）", act.name)
        return {"status": "executed", "action": act.name}


# --------------------------------------------------------------------------- #
#  主循环
# --------------------------------------------------------------------------- #

def run_loop(args: argparse.Namespace) -> int:
    env = make_env(seed=args.seed)
    client: Optional[OllamaClient] = None
    if not args.offline:
        client = OllamaClient(args.model, host=args.ollama_host, temperature=args.temperature)
        if not client.healthy():
            LOG.error("Ollama 不可达 (%s)。请先 `ollama serve` 并用 deployment/serve.sh 部署模型；"
                      "或改用 --offline 走启发式策略。", client.host)
            return 3
        LOG.info("已连接 Ollama: %s | model=%s", client.host, args.model)

    executor = Executor(execute=args.execute, auto_confirm=args.auto_confirm)
    TRAJ_PATH.parent.mkdir(parents=True, exist_ok=True)
    trajectories: List[Dict[str, Any]] = []
    episode_rewards: List[float] = []
    invalid_total = 0

    with TRAJ_PATH.open("w", encoding="utf-8", newline="\n") as fh:
        for ep in range(args.episodes):
            obs = env.reset()
            ep_reward = 0.0
            LOG.info("=== Episode %d/%d 开始 ===", ep + 1, args.episodes)

            for _ in range(args.steps):
                red = env.red_step() if hasattr(env, "red_step") else None
                obs = Observation(obs.step, obs.hosts, obs.alerts, red)
                prompt = obs.to_prompt_text()

                if client is not None:
                    try:
                        actions, rejected = blue_propose_llm(client, obs)
                    except RuntimeError as exc:
                        LOG.error("LLM 失败，回退启发式: %s", exc)
                        actions, rejected = blue_propose_heuristic(obs)
                else:
                    actions, rejected = blue_propose_heuristic(obs)

                invalid_total += len(rejected)
                results = [executor.apply(a, case_id=f"ep{ep}-step{obs.step}") for a in actions]

                obs_next, reward, details = env.step(red or {"id": "n/a", "name": "n/a", "intent": "无"},
                                                     actions)
                ep_reward += reward
                obs = obs_next

                record = {
                    "episode": ep,
                    "step": obs.step,
                    "observation": prompt,
                    "red_ttp": red,
                    "blue_actions": [a.to_dict() for a in actions],
                    "rejected": rejected,
                    "execution": results,
                    "reward": reward,
                    "details": details,
                }
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
                trajectories.append(record)

                LOG.info("step %d | actions=%s | reward=%.3f | avg_health=%.2f",
                         obs.step, [a.name for a in actions], reward, details.get("avg_health", 0.0))

            episode_rewards.append(round(ep_reward, 4))
            LOG.info("=== Episode %d 结束: 累计奖励 %.3f, 终局健康度 %.3f ===",
                     ep + 1, ep_reward, env.score())

    report = {
        "model": args.model,
        "offline": args.offline,
        "episodes": args.episodes,
        "steps_per_episode": args.steps,
        "execute": args.execute,
        "episode_rewards": episode_rewards,
        "mean_reward": round(sum(episode_rewards) / max(1, len(episode_rewards)), 4),
        "schema_rejections": invalid_total,
        "executor_stats": executor.stats,
        "trajectory_file": str(TRAJ_PATH.relative_to(PROJECT_ROOT)),
        "samples": len(trajectories),
    }
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    LOG.info("闭环结束: mean_reward=%.3f, schema 拒绝=%d, 轨迹 %d 条 → %s",
             report["mean_reward"], invalid_total, len(trajectories),
             TRAJ_PATH.relative_to(PROJECT_ROOT))
    LOG.info("报告: %s", REPORT_PATH.relative_to(PROJECT_ROOT))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="红蓝对抗自博弈闭环（蓝队训练用）")
    ap.add_argument("--model", default="blue-team-agent", help="Ollama 中的模型名")
    ap.add_argument("--ollama-host", default=None, help="覆盖 OLLAMA_HOST（默认 http://127.0.0.1:11434）")
    ap.add_argument("--episodes", type=int, default=3)
    ap.add_argument("--steps", type=int, default=8)
    ap.add_argument("--temperature", type=float, default=0.2)
    ap.add_argument("--seed", type=int, default=3407)
    ap.add_argument("--offline", action="store_true", help="不调用 LLM，使用启发式蓝队策略")
    ap.add_argument("--execute", action="store_true",
                    help="真实执行动作（默认 dry-run；需要接入 SOAR/EDR 适配器）")
    ap.add_argument("--auto-confirm", action="store_true",
                    help="自动完成两阶段确认（仅限隔离沙箱；生产环境请勿开启）")
    args = ap.parse_args(argv)

    if args.execute and not args.auto_confirm:
        LOG.warning("--execute 已开启但未开 --auto-confirm：所有不可逆动作将停在待确认状态。")
    return run_loop(args)


if __name__ == "__main__":
    raise SystemExit(main())
