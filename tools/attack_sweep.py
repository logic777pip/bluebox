#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/attack_sweep.py — 大样本攻防评测的 A/B/C 扫描驱动。

为什么要单独写一个驱动
----------------------

1. **每组之间必须重启 llama-server**。上一轮实测发现 llama-server 的工作集随请求数
   单调增长（2.28GB → 6.21GB）。若三组共用同一进程，后一组会带着前一组的内存状态
   起跑，「资源占用」这一项就不可比。
2. 重启顺便构成**内存增长的压测证据**：每组前后各采样一次，就能判断
   「同一负载下工作集是否回到起点」——这是上一轮报告里列为「待验证」的问题。
3. 长任务要能断点续跑：`--resume` 会跳过已有输出文件的分组。

用法::

    python tools/attack_sweep.py --cases data/attack_cases_big.jsonl
    python tools/attack_sweep.py --resume          # 中断后续跑
    python tools/attack_sweep.py --only C_harden_k3
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.resource_probe import sample as probe  # noqa: E402

PY = sys.executable
DEPLOY = PROJECT_ROOT / "deployment" / "llamacpp" / "deploy_llamacpp.py"
EVAL = PROJECT_ROOT / "cyber_range" / "eval_attack_matrix.py"
LOGS = PROJECT_ROOT / "logs"

# (名称, 说明, 评测附加参数)  —— 按“先单独变量、后叠加”的顺序做消融
RUNS: Sequence[tuple[str, str, List[str]]] = (
    ("A_base", "基线：加固关 + top_k=5", ["--no-harden", "--top-k", "5"]),
    ("B_harden", "仅加固（H1-H4）+ top_k=5", ["--harden", "--top-k", "5"]),
    ("C_harden_k3", "加固 + top_k=3", ["--harden", "--top-k", "3"]),
)


@dataclass
class RunRecord:
    name: str
    desc: str
    out_json: str = ""
    exit_code: int = -1
    seconds: float = 0.0
    # 服务端资源（重启后基线 / 跑完之后）
    vram_idle_mb: float = 0.0        # **启动本服务之前**的整卡占用（剥离其他进程，如 Ollama）
    rss_after_start_mb: float = 0.0
    vram_after_start_mb: float = 0.0
    rss_after_run_mb: float = 0.0
    vram_after_run_mb: float = 0.0
    processes: int = 0
    server_tokens_predicted: int = 0
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _run(cmd: Sequence[str], log: Optional[Path] = None) -> int:
    if log is None:
        return subprocess.run(cmd, cwd=str(PROJECT_ROOT)).returncode
    with log.open("w", encoding="utf-8") as fh:
        return subprocess.run(cmd, cwd=str(PROJECT_ROOT), stdout=fh,
                              stderr=subprocess.STDOUT).returncode


def restart_server(port: int, ctx: int, ngl: int) -> Dict[str, float]:
    """停止 → 启动 → 等健康，返回就绪后的资源基线。

    启动**之前**先采一次整卡显存：显存是整卡口径，若机器上还有别的推理进程
    （实测：Ollama 自带的 llama-server.exe），只有减去空载基线才能得到
    「本服务自己占了多少」。
    """
    _run([PY, str(DEPLOY), "stop"], LOGS / "sweep_server_stop.log")
    time.sleep(2)
    idle = probe(name="llama-server", port=port, path_contains=str(PROJECT_ROOT),
                 with_vram=True)
    _run([PY, str(DEPLOY), "serve", "--port", str(port), "--ctx", str(ctx),
          "--ngl", str(ngl)], LOGS / "sweep_server_serve.log")
    rc = _run([PY, str(DEPLOY), "wait", "--timeout", "240"], LOGS / "sweep_server_wait.log")
    if rc != 0:
        raise RuntimeError(f"llama-server 未就绪（wait 退出码 {rc}）")
    s = probe(name="llama-server", port=port, path_contains=str(PROJECT_ROOT))
    return {"rss_mb": s.rss_mb, "vram_mb": s.vram_mb, "processes": s.processes,
            "vram_idle_mb": idle.vram_mb}


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="攻防评测 A/B/C 扫描")
    ap.add_argument("--cases", default=str(PROJECT_ROOT / "data" / "attack_cases_big.jsonl"))
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--ctx", type=int, default=4096)
    ap.add_argument("--ngl", type=int, default=99)
    ap.add_argument("--max-tokens", type=int, default=320)
    ap.add_argument("--out-dir", default=str(LOGS))
    ap.add_argument("--only", default=None, help="只跑某一组（名称）")
    ap.add_argument("--resume", action="store_true", help="跳过已完成的组")
    ap.add_argument("--no-restart", action="store_true", help="不重启服务（调试用）")
    args = ap.parse_args(argv)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    records: List[RunRecord] = []
    for name, desc, extra in RUNS:
        if args.only and name != args.only:
            continue
        out_json = out_dir / f"attack_big_{name}.json"
        rec = RunRecord(name=name, desc=desc, out_json=str(out_json))
        if args.resume and out_json.exists():
            print(f"[skip] {name} 已存在 {out_json.name}")
            continue

        try:
            if not args.no_restart:
                print(f"[{name}] 重启 llama-server …", flush=True)
                base = restart_server(args.port, args.ctx, args.ngl)
                rec.rss_after_start_mb = base["rss_mb"]
                rec.vram_after_start_mb = base["vram_mb"]
                rec.vram_idle_mb = base["vram_idle_mb"]
                rec.processes = int(base["processes"])
                print(f"[{name}] 就绪：仅统计本项目进程 {base['processes']} 个，"
                      f"RSS {base['rss_mb']} MB | 整卡显存 {base['vram_mb']} MB"
                      f"（空载 {base['vram_idle_mb']} → 本服务净占 "
                      f"{base['vram_mb'] - base['vram_idle_mb']:.0f} MB）", flush=True)
        except Exception as exc:  # noqa: BLE001
            rec.error = f"服务启动失败: {exc}"
            records.append(rec)
            print(f"[{name}] {rec.error}", flush=True)
            continue

        cmd = [PY, str(EVAL), "--backend", "llamacpp", "--cases", args.cases,
               "--greedy", "--max-tokens", str(args.max_tokens),
               "--out", str(out_json), *extra]
        t0 = time.time()
        print(f"[{name}] 开跑 {desc} …", flush=True)
        rec.exit_code = _run(cmd, out_dir / f"attack_big_{name}.txt")
        rec.seconds = round(time.time() - t0, 1)

        s = probe(name="llama-server", port=args.port, path_contains=str(PROJECT_ROOT))
        rec.rss_after_run_mb = s.rss_mb
        rec.vram_after_run_mb = s.vram_mb
        rec.server_tokens_predicted = s.tokens_predicted
        print(f"[{name}] 完成 rc={rec.exit_code} 耗时 {rec.seconds}s "
              f"RSS {rec.rss_after_run_mb} MB VRAM {rec.vram_after_run_mb} MB", flush=True)
        records.append(rec)

        (out_dir / "attack_sweep_runs.json").write_text(
            json.dumps([r.to_dict() for r in records], ensure_ascii=False, indent=2),
            encoding="utf-8")

    # 停止服务（用户约束：随手清理）
    if not args.no_restart:
        _run([PY, str(DEPLOY), "stop"], LOGS / "sweep_server_stop.log")

    print("\n== 扫描汇总 ==")
    for r in records:
        print(f"  {r.name:<14} rc={r.exit_code} {r.seconds:>7.1f}s "
              f"RSS {r.rss_after_start_mb:.0f}→{r.rss_after_run_mb:.0f} MB | "
              f"整卡显存 {r.vram_idle_mb:.0f}(空载)/{r.vram_after_start_mb:.0f}→"
              f"{r.vram_after_run_mb:.0f} MB | 进程 {r.processes} {r.error}")
    return 0 if all(r.exit_code == 0 for r in records) else 1


if __name__ == "__main__":
    raise SystemExit(main())
