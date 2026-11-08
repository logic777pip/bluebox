#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""training/data_prep.py — 蓝队 SFT 数据集下载 / 清洗 / 脱敏 / 切分。

产物（相对项目根）:
    data/sft_dataset.jsonl      训练集 {"messages":[{role,content},...]}
    data/eval_dataset.jsonl     验证集（同格式）
    logs/data_prep_report.json  统计报告（已脱敏）

安全规则落实:
    R1 脱敏      : security.sanitize.mask_text —— 凭据/邮箱强制脱敏，IP 可开关
    R2 超时重试  : HF_HUB_DOWNLOAD_TIMEOUT + 指数退避重试（上限 3 次）
    R4 无硬编码  : HF Token 只从环境变量 HF_TOKEN 读取
    R5 两阶段确认: 覆盖已存在的数据文件需 --yes（不可逆写入）

用法:
    python training/data_prep.py --sources all --max-samples 2000 --yes
    python training/data_prep.py --sources local --yes           # 仅清洗 data/raw/*.jsonl
    python training/data_prep.py --sources fenrir,attackqa --no-mask-ip
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

# --- 路径与包导入 -----------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security.action_schema import SchemaError, validate_action  # noqa: E402
from security.sanitize import get_logger, mask_text  # noqa: E402

LOG = get_logger("data_prep")

DATA_DIR = PROJECT_ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
LOG_DIR = PROJECT_ROOT / "logs"

# 国内网络加速（可在外部覆盖，勿写死 token）
os.environ.setdefault("HF_ENDPOINT", "https://hf-mirror.com")
os.environ.setdefault("HF_HUB_DOWNLOAD_TIMEOUT", "30")   # R2: 单次请求超时
os.environ.setdefault("HF_HUB_ETAG_TIMEOUT", "30")

MAX_RETRIES = 3          # R2: 重试上限
BACKOFF_BASE = 1.0       # 指数退避 1s / 2s / 4s

# --- 数据源清单（仅保留经实测可用的源；--sources all 只跑这些） -------------
# 本仓库自产的「行为对齐」合成数据（由 make_synth_sft.py 生成，非下载）
SYNTH_FILE = "data/synth_sft.jsonl"

SOURCES: Dict[str, Dict[str, str]] = {
    "synth": {
        "hf_id": f"local:{SYNTH_FILE}",
        "domain": "behavior_alignment",
        "note": "本仓库模板生成的蓝队行为对齐样本（动作 JSON / 拒绝 / 良性研判）",
    },
    "fenrir": {
        "hf_id": "AlicanKiraz0/Cybersecurity-Dataset-Fenrir-v2.1",
        "domain": "sft_general",
        "note": "99,869 条 system/user/assistant 三元组 (Apache-2.0)",
    },
    "kimicot": {
        "hf_id": "echel0nn1881/kimi-cyber-reasoning",
        "domain": "cot_reasoning",
        "note": "997 条英文思维链（含 <think> 与工具调用）",
    },
    "cti": {
        "hf_id": "reloading0101/threat-intelligence-dataset",
        "domain": "cti",
        "note": "约 100,000 条 CTI 指令-响应对，42 个类别，事实校验",
    },
    "blackbox_cot": {
        "hf_id": "blackboxanalytics/BlackBox-CyberSec-CoT-v1",
        "domain": "incident_response",
        "note": "约 580 条事件日志 + 逐步推理 + 修复命令",
    },
    "phishing_soc": {
        "hf_id": "Ellbendls/phishing-email-soc-agent",
        "domain": "soc_agent",
        "note": "504 条邮件分析样本，含真实工具调用（Apache-2.0）",
    },
}

# 不在 SFT 范围内、仅供后续 IDS 评测的数据集（体积大，见 README）
IDS_ONLY = ["rdpahalavan/CIC-IDS2017", "rdpahalavan/UNSW-NB15"]

# 2026-09 实测被排除的数据源（保留说明，避免每次重跑都白下载）
#   --sources all 会跳过它们；显式指定 --sources <name> 仍可加载（用于复核）。
EXCLUDED_SOURCES: Dict[str, Dict[str, str]] = {
    "attackqa": {
        "hf_id": "gagan3012/AttackQA",
        "reason": "名字有误导：该 repo 实为 TruthfulQA 类幻觉题（question + mc1_targets/labels，"
                  "内容为 5G/新冠/见鬼等），与 MITRE ATT&CK 无关，混入会污染蓝队领域身份。",
    },
    "incident_response": {
        "hf_id": "AYI-NEDJIMI/incident-response-en",
        "reason": "hf-mirror 返回 401 RepositoryNotFound（repo 不可访问或未镜像）；"
                  "如需使用请设置 HF_TOKEN 或直连 huggingface.co。",
    },
    "cybersec100k": {
        "hf_id": "stindardlogic/cybersecurity-sft-100k",
        "reason": "数据退化：100000 行中仅 11 条唯一内容（其余为重复填充），"
                  "流式/非流式均确认。对训练无增益，已从默认数据源移除。",
    },
}

# 可加载的全部源（含已知有问题的）；--sources <name> 可显式指定以便复核
ALL_SOURCES: Dict[str, Dict[str, str]] = {**SOURCES, **EXCLUDED_SOURCES}

# --- 蓝队系统提示词（训练时统一注入，保证行为一致） --------------------------
BLUE_TEAM_SYSTEM_PROMPT = (
    "你是蓝队应急响应分析助手。你的职责是：告警研判、日志与流量分析、"
    "MITRE ATT&CK 技术映射、事件时间线还原、遏制与恢复建议。\n"
    "行为约束：\n"
    "1. 先取证后结论；证据不足时明确说明不确定性，禁止臆造 IOC。\n"
    "2. 所有可执行动作必须输出为 JSON，形如 "
    '{"action": "<动作名>", "args": {...}, "rationale": "<理由>"}，'
    "动作名只能取自防御动作白名单（query_logs/collect_forensics/block_ip/"
    "isolate_host/kill_process/quarantine_file/disable_account/notify_analyst/"
    "restore_host/close_case）。\n"
    "3. 不可逆动作（隔离/封禁/杀进程/隔离文件/禁用账号/恢复主机）必须先提出方案，"
    "经人工两阶段确认后方可执行。\n"
    "4. 输出中不得包含真实凭据；需要引用 IP 时使用占位符。"
)

# =========================================================================== #
#  工具函数
# =========================================================================== #

def retry(fn, *, what: str, retries: int = MAX_RETRIES):
    """R2：带超时语义的指数退避重试。仅用于幂等读取操作。"""
    last: Optional[Exception] = None
    for attempt in range(1, retries + 1):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 — 上游 HF 异常类型繁多
            last = exc
            if attempt == retries:
                break
            delay = BACKOFF_BASE * (2 ** (attempt - 1))
            LOG.warning("[%s] 第 %d/%d 次失败: %s — %.1fs 后重试",
                        what, attempt, retries, mask_text(str(exc)), delay)
            time.sleep(delay)
    raise RuntimeError(f"[{what}] 重试 {retries} 次后仍然失败: {mask_text(str(last))}")


def _first_str(row: Dict[str, Any], keys: Iterable[str]) -> Optional[str]:
    for k in keys:
        v = row.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def normalize_row(row: Dict[str, Any]) -> Optional[List[Dict[str, str]]]:
    """把各种上游 schema 归一到 messages 列表。无法识别则返回 None。"""
    # 1) 已是 messages / conversation 列表
    for key in ("messages", "conversation", "conversations", "dialog"):
        seq = row.get(key)
        if isinstance(seq, list) and seq:
            msgs: List[Dict[str, str]] = []
            for turn in seq:
                if not isinstance(turn, dict):
                    continue
                role = str(turn.get("role") or turn.get("from") or turn.get("sender") or "").lower()
                content = turn.get("content") or turn.get("value") or turn.get("text") or ""
                role = {"human": "user", "gpt": "assistant", "system": "system",
                        "user": "user", "assistant": "assistant"}.get(role, role)
                if role in ("user", "assistant", "system") and str(content).strip():
                    msgs.append({"role": role, "content": str(content).strip()})
            if any(m["role"] == "assistant" for m in msgs):
                return msgs

    # 2) BlackBox-CyberSec-CoT: log + reasoning[] + remediation[]
    log = _first_str(row, ("log", "event_log", "raw_log"))
    if log and (row.get("reasoning") or row.get("remediation")):
        steps: List[str] = []
        for field in ("reasoning",):
            val = row.get(field)
            if isinstance(val, (list, tuple)):
                steps += [f"{i + 1}. {str(s).strip()}" for i, s in enumerate(val) if str(s).strip()]
            elif isinstance(val, str) and val.strip():
                steps.append(val.strip())
        fixes: List[str] = []
        val = row.get("remediation")
        if isinstance(val, (list, tuple)):
            fixes += [f"- {str(s).strip()}" for s in val if str(s).strip()]
        elif isinstance(val, str) and val.strip():
            fixes.append(f"- {val.strip()}")

        assistant = "【逐步推理】\n" + ("\n".join(steps) if steps else "（无）")
        if fixes:
            assistant += "\n\n【修复建议】\n" + "\n".join(fixes)
        return [
            {"role": "user",
             "content": f"请分析以下安全事件日志，给出逐步推理过程与修复建议：\n{log}"},
            {"role": "assistant", "content": assistant},
        ]

    # 3) system / user / assistant 三列（Fenrir 等）
    u = _first_str(row, ("user", "instruction", "question", "query", "prompt", "input"))
    a = _first_str(row, ("assistant", "output", "response", "answer", "completion", "gpt"))
    if u and a:
        s = _first_str(row, ("system", "system_prompt"))
        msgs = ([{"role": "system", "content": s}] if s else [])
        msgs += [{"role": "user", "content": u}, {"role": "assistant", "content": a}]
        return msgs

    # 3) instruction + input 组合（Alpaca 风格）
    inst = _first_str(row, ("instruction",))
    extra = _first_str(row, ("input", "context"))
    out = _first_str(row, ("output", "response"))
    if inst and out and extra:
        return [
            {"role": "user", "content": f"{inst}\n\n[上下文]\n{extra}"},
            {"role": "assistant", "content": out},
        ]
    return None


def scrub_messages(msgs: List[Dict[str, str]], mask_ip: bool) -> List[Dict[str, str]]:
    """R1：对每条消息内容脱敏。"""
    return [{"role": m["role"], "content": mask_text(m["content"], mask_ip=mask_ip)} for m in msgs]


def find_bad_actions(msgs: List[Dict[str, str]]) -> List[str]:
    """R3 左移到数据层：找出 assistant 输出中不符合动作白名单的动作。

    上游数据里混入了 `shell`、`http_smuggling_lab_probe` 等白名单外动作名。
    这类样本会直接教模型输出不可执行/越权的动作，必须在入训前剔除。
    返回错误描述列表（空表示全部合规）。
    """
    bad: List[str] = []
    for m in msgs:
        if m.get("role") != "assistant":
            continue
        for line in str(m.get("content", "")).splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue                      # 代码片段，不是动作
            if not isinstance(obj, dict) or not ("action" in obj or "name" in obj):
                continue                      # JSON 示例（日志/配置），不是动作
            try:
                validate_action(obj)
            except SchemaError as exc:
                bad.append(str(exc))
    return bad


def ensure_system(msgs: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """统一注入蓝队 system prompt，保证 3B 小模型角色稳定。"""
    body = [m for m in msgs if m["role"] != "system"]
    return [{"role": "system", "content": BLUE_TEAM_SYSTEM_PROMPT}] + body


def iter_local_raw() -> Iterator[Tuple[str, Dict[str, Any]]]:
    """读取 data/raw/*.jsonl —— 离线模式。"""
    if not RAW_DIR.exists():
        return
    for path in sorted(RAW_DIR.glob("*.jsonl")):
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield path.stem, json.loads(line)
                except json.JSONDecodeError:
                    continue


def iter_synth() -> Iterator[Tuple[str, Dict[str, Any]]]:
    """读取本仓库生成的合成行为对齐样本。

    这些样本用于「校正输出格式分布」——上游数据（尤其是 cti）风格极强，
    会把 3B 小模型带成只会输出英文情报卡片的复读机，而不输出可执行的动作 JSON。
    """
    path = PROJECT_ROOT / SYNTH_FILE
    if not path.exists():
        LOG.warning("未找到合成数据 %s（先运行 training/make_synth_sft.py）", SYNTH_FILE)
        return
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield "synth", json.loads(line)
            except json.JSONDecodeError:
                continue


def iter_hf(name: str, max_samples: int, stream: bool = True) -> Iterator[Tuple[str, Dict[str, Any]]]:
    """加载指定 HF 数据集。

    stream=True : 流式读取（省磁盘，但若镜像站异常可能循环吐同一批行）
    stream=False: 完整下载后随机抽样（更可靠，代价是带宽）
    """
    from datasets import load_dataset  # 延迟导入，便于无依赖时跑 --help

    spec = ALL_SOURCES[name]
    hf_id = spec["hf_id"]
    LOG.info("加载数据集 %s (%s, stream=%s) — %s", name, hf_id, stream, spec.get("note") or spec["reason"])

    if not stream:
        def _load_full():
            try:
                return load_dataset(hf_id, split="train")
            except Exception:  # noqa: BLE001 — 部分数据集无 train split
                return load_dataset(hf_id)

        ds = retry(_load_full, what=f"load_dataset:{name}")
        if hasattr(ds, "keys") and not hasattr(ds, "features"):   # DatasetDict
            ds = ds[list(ds.keys())[0]]
        total = len(ds)
        if max_samples and total > max_samples:
            ds = ds.shuffle(seed=3407).select(range(max_samples))
        LOG.info("  %s: 全量 %d 条 -> 抽样 %d 条", name, total, len(ds))
        for row in ds:
            yield name, dict(row)
        return

    def _load() -> Any:
        try:
            return load_dataset(hf_id, split="train", streaming=True)
        except Exception:  # noqa: BLE001 — 部分数据集无 train split
            return load_dataset(hf_id, streaming=True)

    ds = retry(_load, what=f"load_dataset:{name}")
    if hasattr(ds, "keys") and not hasattr(ds, "features"):        # DatasetDict
        ds = ds[list(ds.keys())[0]]

    for i, row in enumerate(ds):
        if max_samples and i >= max_samples:
            break
        yield name, dict(row)


# =========================================================================== #
#  主流程
# =========================================================================== #

MAX_CONSECUTIVE_DUPES = 200   # 连续重复超过此值 → 判定为镜像站流式循环，提前中止该源


def build_dataset(
    sources: List[str],
    max_samples: int,
    mask_ip: bool,
    min_chars: int = 40,
    stream: bool = True,
    max_consecutive_dupes: int = MAX_CONSECUTIVE_DUPES,
    per_source_limits: Optional[Dict[str, int]] = None,
) -> Tuple[List[Dict[str, Any]], Counter]:
    """返回 (去重后的样本列表, 统计计数)。

    逐源处理并做两件事：
      1. 单源异常只影响该源（不再让一个源的中断吃掉后续所有源）；
      2. 连续重复超过阈值即判定为「镜像站流式迭代循环」并中止该源
         （hf-mirror 上曾观察到同一 shard 被反复吐出的情况，
          会让 skip_duplicate 虚高而实际样本极少）。
    """
    seen: set[str] = set()
    samples: List[Dict[str, Any]] = []
    stats: Counter = Counter()

    for name in sources:
        stats[f"raw:{name}"] += 0          # 即使加载失败也在报告里留位
        consecutive_dupes = 0
        limit = (per_source_limits or {}).get(name, max_samples)
        if name == "local":
            records: Iterator[Tuple[str, Dict[str, Any]]] = iter_local_raw()
        elif name == "synth":
            records = iter_synth()
        else:
            records = iter_hf(name, limit, stream=stream)
        try:
            for src, row in records:
                stats[f"raw:{src}"] += 1

                msgs = normalize_row(row)
                if not msgs:
                    stats["skip_schema"] += 1
                    continue

                msgs = ensure_system(scrub_messages(msgs, mask_ip=mask_ip))

                # R3 前置：assistant 输出里出现白名单外动作的样本直接丢弃
                bad_actions = find_bad_actions(msgs)
                if bad_actions:
                    stats["skip_bad_action"] += 1
                    LOG.warning("丢弃样本（动作不合规）: %s", mask_text("; ".join(bad_actions[:2])))
                    continue

                if sum(len(m["content"]) for m in msgs) < min_chars:
                    stats["skip_too_short"] += 1
                    continue

                key = "\x1f".join(m["content"] for m in msgs)
                if key in seen:
                    stats["skip_duplicate"] += 1
                    consecutive_dupes += 1
                    if consecutive_dupes >= max_consecutive_dupes:
                        stats[f"cycle_abort:{src}"] += 1
                        LOG.warning(
                            "数据源 %s 连续 %d 条重复 —— 判定为镜像站流式迭代循环，提前终止该源；"
                            "重跑时请加 --no-stream（整份下载后抽样）。",
                            src, consecutive_dupes,
                        )
                        break
                    continue

                consecutive_dupes = 0
                seen.add(key)
                samples.append({"messages": msgs, "source": src})
                stats["kept"] += 1
        except Exception as exc:  # noqa: BLE001
            stats["source_failed"] += 1
            LOG.error("数据源 %s 中断（当前累计保留 %d 条）: %s",
                      name, stats["kept"], mask_text(str(exc)))

    return samples, stats


def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            n += 1
    return n


def parse_limits(spec: str) -> Dict[str, int]:
    """解析 --per-source-limits "cti=400,fenrir=1200"。"""
    out: Dict[str, int] = {}
    for part in (spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise SystemExit(f"--per-source-limits 格式错误: {part!r}（应为 name=N）")
        k, v = part.split("=", 1)
        out[k.strip()] = int(v)
    return out


def confirm_overwrite(paths: List[Path], assume_yes: bool) -> None:
    """R5：覆盖已存在的数据文件属于不可逆写入，需两阶段确认。"""
    existing = [p for p in paths if p.exists()]
    if not existing:
        return
    if assume_yes:
        LOG.warning("已确认（--yes）覆盖 %d 个已存在文件", len(existing))
        return
    print("以下文件已存在，继续将【覆盖】它们：")
    for p in existing:
        print(f"  - {p.relative_to(PROJECT_ROOT)} ({p.stat().st_size / 1e6:.1f} MB)")
    answer = input("阶段一确认：输入 yes 覆盖，输入其他任意内容中止 > ").strip().lower()
    if answer != "yes":
        raise SystemExit("已中止，未修改任何文件。")
    answer2 = input("阶段二确认：再次输入 yes 执行 > ").strip().lower()
    if answer2 != "yes":
        raise SystemExit("已中止，未修改任何文件。")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="蓝队 SFT 数据集准备")
    parser.add_argument(
        "--sources",
        default="all",
        help="all | local | 逗号分隔的源名。可用: %s；已知有问题（需显式指定才会跑）: %s"
             % (",".join(SOURCES), ",".join(EXCLUDED_SOURCES)),
    )
    parser.add_argument("--max-samples", type=int, default=0, help="每个源最多取多少条（0=全部）")
    parser.add_argument("--eval-ratio", type=float, default=0.02, help="验证集比例")
    parser.add_argument("--no-mask-ip", action="store_true", help="保留 IP（凭据/邮箱仍脱敏）")
    parser.add_argument(
        "--no-stream",
        action="store_true",
        help="不用流式：整份下载后随机抽样（镜像站流式循环时更可靠，代价是带宽）",
    )
    parser.add_argument("--yes", action="store_true", help="跳过交互确认（CI 环境）")
    parser.add_argument(
        "--per-source-limits",
        default="",
        help="按源覆盖采样上限，如 cti=400,fenrir=1200；未列出的源用 --max-samples",
    )
    args = parser.parse_args(argv)

    if args.sources == "all":
        sources = list(SOURCES)
    elif args.sources == "local":
        sources = ["local"]
    else:
        sources = [s.strip() for s in args.sources.split(",") if s.strip()]
        unknown = [s for s in sources if s not in ALL_SOURCES]
        if unknown:
            parser.error(f"未知数据源: {unknown}；可选: {list(ALL_SOURCES)} 或 all/local")
        for s in sources:
            if s in EXCLUDED_SOURCES:
                LOG.warning("数据源 %s 已被标记为有问题：%s", s, EXCLUDED_SOURCES[s]["reason"])

    train_path = DATA_DIR / "sft_dataset.jsonl"
    eval_path = DATA_DIR / "eval_dataset.jsonl"
    confirm_overwrite([train_path, eval_path], args.yes)

    samples, stats = build_dataset(
        sources=sources,
        max_samples=args.max_samples,
        mask_ip=not args.no_mask_ip,
        stream=not args.no_stream,
        per_source_limits=parse_limits(args.per_source_limits),
    )
    if not samples:
        LOG.error("没有可用样本，未写入任何文件。统计: %s", dict(stats))
        return 2

    rng = random.Random(3407)
    rng.shuffle(samples)
    n_eval = max(1, int(len(samples) * args.eval_ratio))
    eval_rows, train_rows = samples[:n_eval], samples[n_eval:]

    n_train = write_jsonl(train_path, train_rows)
    n_eval = write_jsonl(eval_path, eval_rows)

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    report = {
        "sources": sources,
        "mask_ip": not args.no_mask_ip,
        "stream": not args.no_stream,
        "counts": {"train": n_train, "eval": n_eval, "total": len(samples)},
        "stats": dict(stats),
        "domain_mix": dict(Counter(s["source"] for s in samples)),
        "avg_turns": round(sum(len(s["messages"]) for s in samples) / len(samples), 2),
        "excluded_sources": {k: v["reason"] for k, v in EXCLUDED_SOURCES.items() if k not in sources},
    }
    (LOG_DIR / "data_prep_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    LOG.info("完成: train=%d eval=%d → %s",
             n_train, n_eval, train_path.relative_to(PROJECT_ROOT))
    LOG.info("报告: %s", (LOG_DIR / "data_prep_report.json").relative_to(PROJECT_ROOT))
    LOG.info("提示: IDS 评测数据集（%s）体积大，按需单独下载。", ", ".join(IDS_ONLY))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
