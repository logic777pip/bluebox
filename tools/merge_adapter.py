#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/merge_adapter.py — 把 LoRA adapter 合并进基座，导出 16bit 全权重。

为什么需要它：
    对抗后训练（`train_adversarial.py`）如果直接从**基座**训一个新 LoRA，
    等于把已学到的蓝队任务能力丢掉重来 —— 实测 v3/v4 的动作合规率
    从 v2 的 3/3 掉到 1/3，根因就是「任务曝光量」从 7944 降到 490/624，
    属于欠训而非被对抗数据污染。

    正确做法是把上一版 adapter 合并成全权重，再在其上做后训练
    （`train_qlora.py` 用 merged 目录作为 base_model）。

用法:
    python tools/merge_adapter.py \
        --adapter outputs/qwen2.5-3b-blue-team-lora-v2/lora_adapter \
        --out     outputs/qwen2.5-3b-blue-team-merged-v2
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

os.environ.setdefault("HF_HUB_DISABLE_SYMLINKS_WARNING", "1")
os.environ.setdefault("HF_ENDPOINT", "https://hf-mirror.com")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from security.sanitize import get_logger  # noqa: E402

LOG = get_logger("tools.merge")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="合并 LoRA adapter 为 16bit 全权重")
    ap.add_argument("--adapter", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--base-model", default="Qwen/Qwen2.5-3B-Instruct")
    ap.add_argument("--device", choices=["cpu", "cuda"], default="cpu",
                    help="合并设备。默认 cpu：3B bf16 全权重约 6.2GB，"
                         "放 8GB 显存里合并风险高；CPU 合并慢一些但稳。")
    ap.add_argument("--dtype", default="bfloat16", choices=["bfloat16", "float16", "float32"])
    ap.add_argument("--overwrite", action="store_true",
                    help="目标目录已存在时是否覆盖（不可逆写入，需显式指定）")
    args = ap.parse_args(argv)

    adapter = Path(args.adapter)
    if not adapter.is_absolute():
        adapter = PROJECT_ROOT / adapter
    out = Path(args.out)
    if not out.is_absolute():
        out = PROJECT_ROOT / out
    if not (adapter / "adapter_config.json").exists():
        raise SystemExit(f"不是有效的 LoRA adapter 目录: {adapter}")
    if out.exists() and any(out.iterdir()) and not args.overwrite:
        raise SystemExit(f"目标目录非空: {out}（确认要覆盖请加 --overwrite）")

    import torch  # noqa: PLC0415
    from transformers import AutoModelForCausalLM, AutoTokenizer  # noqa: PLC0415

    dtype = {"bfloat16": torch.bfloat16, "float16": torch.float16,
             "float32": torch.float32}[args.dtype]

    # ⚠ 必须在**未量化**的模型上合并：
    #   在 4-bit bnb 模型上 merge_and_unload()，得到的仍被标记为 bnb 模型，
    #   随后 `.to(bfloat16)` 会抛
    #   "You cannot cast a bitsandbytes model in a new dtype"；
    #   而且 peft 会警告「Merge lora module to 4-bit linear may get different
    #   generations due to rounding errors」—— 量化模型上合并在原理上就是错的。
    LOG.info("加载基座 %s（%s / %s，未量化）", args.base_model, args.dtype, args.device)
    base = AutoModelForCausalLM.from_pretrained(
        args.base_model, torch_dtype=dtype, device_map=args.device,
        attn_implementation="sdpa", trust_remote_code=False)

    from peft import PeftModel  # noqa: PLC0415
    LOG.info("挂载 adapter %s", adapter.name)
    model = PeftModel.from_pretrained(base, str(adapter))

    LOG.info("合并权重（merge_and_unload）…")
    merged = model.merge_and_unload()
    if args.dtype != "float32":
        merged = merged.to(dtype)

    out.mkdir(parents=True, exist_ok=True)
    LOG.info("保存到 %s", out)
    merged.save_pretrained(str(out), safe_serialization=True)
    AutoTokenizer.from_pretrained(str(adapter)).save_pretrained(str(out))

    total = sum(f.stat().st_size for f in out.glob("*.safetensors"))
    LOG.info("完成：%s（%.1f GB）", out, total / 1024 ** 3)
    print(f"merged -> {out}  ({total / 1024 ** 3:.2f} GB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
