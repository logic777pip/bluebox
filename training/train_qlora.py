#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""training/train_qlora.py — 蓝队应急响应 Agent 的 QLoRA 4-bit 微调入口。

基座: Qwen/Qwen2.5-3B-Instruct      硬件: RTX 5060 8GB / 32GB RAM / 单卡
量化: 4-bit NF4 + double quant      框架: Unsloth（首选）

强制约束（见 .github/copilot-instructions.md）:
  * gradient_checkpointing + bf16 混合精度
  * 每步打印 loss / learning_rate / GPU 显存占用
  * 峰值显存 > 7.5GB 告警并给出降 batch_size 建议
  * 禁用 flash-attn / deepspeed
  * 日志全部脱敏（security.sanitize）

用法:
  python training/train_qlora.py --config training/config.yaml
  python training/train_qlora.py --config training/config.yaml --smoke     # 3 步冒烟
  python training/train_qlora.py --config training/config.yaml --max-steps 20
  python training/train_qlora.py --config training/config.yaml --export-gguf --no-merge
"""

from __future__ import annotations

import argparse
import inspect
import json
import os
import platform
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# --- 环境变量必须在 import torch 之前设置 ------------------------------------
os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("HF_ENDPOINT", "https://hf-mirror.com")
os.environ.setdefault("HF_HUB_DOWNLOAD_TIMEOUT", "30")
os.environ.setdefault("WANDB_DISABLED", "true")
# Windows 未开“开发者模式”时 HF 缓存无法建符号链接（WinError 1314），
# huggingface_hub 会自动回退为复制文件（能用，但会重复占盘）；这里只关掉噪声告警。
os.environ.setdefault("HF_HUB_DISABLE_SYMLINKS_WARNING", "1")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security.sanitize import get_logger, mask_obj, mask_text  # noqa: E402

try:  # 允许在未安装依赖时仍可 --help
    from transformers import TrainerCallback as _TrainerCallbackBase
    _HAS_TRANSFORMERS = True
except ImportError:  # pragma: no cover
    class _TrainerCallbackBase:  # type: ignore[no-redef]
        """占位基类：仅用于未安装 transformers 时导入本模块。"""
    _HAS_TRANSFORMERS = False

LOG = get_logger("train_qlora")

# 训练期禁用实验性可选项，避免 5060 上的未知算子
os.environ.setdefault("UNSLOTH_DISABLE_STATISTICS", "1")


# =========================================================================== #
#  配置
# =========================================================================== #

REQUIRED_KEYS = ("model", "lora", "data", "training")


def load_config(path: Path) -> Dict[str, Any]:
    import yaml

    if not path.exists():
        raise SystemExit(f"配置文件不存在: {path}")
    with path.open("r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    missing = [k for k in REQUIRED_KEYS if k not in cfg]
    if missing:
        raise SystemExit(f"config.yaml 缺少必需小节: {missing}")
    cfg.setdefault("project", {})
    cfg.setdefault("memory", {"vram_warn_gb": 7.5, "vram_total_gb": 8.0})
    cfg.setdefault("export", {})
    return cfg


def resolve(p: str | Path) -> Path:
    """所有 config 路径按【项目根】解析（相对路径约定）。"""
    p = Path(p)
    return p if p.is_absolute() else (PROJECT_ROOT / p)


# =========================================================================== #
#  显存监控（约束：每步打印 + 7.5GB 红线）
# =========================================================================== #

def vram_peak_gb() -> float:
    try:
        import torch
        if not torch.cuda.is_available():
            return 0.0
        return torch.cuda.max_memory_reserved() / 1024 ** 3
    except Exception:  # noqa: BLE001
        return 0.0


def vram_now_gb() -> float:
    try:
        import torch
        if not torch.cuda.is_available():
            return 0.0
        return torch.cuda.memory_allocated() / 1024 ** 3
    except Exception:  # noqa: BLE001
        return 0.0


class VramGuardCallback(_TrainerCallbackBase):
    """训练显存守卫 + 步级日志回调。

    职责:
      1. 每步打印 loss / learning_rate / GPU 显存
      2. 峰值显存 > vram_warn_gb 时告警，并输出可执行的降显存建议
      3. 记录峰值与超限次数，写入训练报告
    """

    def __init__(
        self,
        warn_gb: float = 7.5,
        total_gb: float = 8.0,
        fallback_seq_len: int = 1024,
        log_every_step: bool = True,
    ) -> None:
        super().__init__()
        self.warn_gb = float(warn_gb)
        self.total_gb = float(total_gb)
        self.fallback_seq_len = int(fallback_seq_len)
        self.log_every_step = log_every_step
        self.peak_gb = 0.0
        self.warn_count = 0
        self.history: List[Dict[str, Any]] = []
        self._t0 = time.time()

    # -- 内部 -- #
    def _sample(self, tag: str, step: int, loss: Optional[float], lr: Optional[float]) -> None:
        peak = vram_peak_gb()
        now = vram_now_gb()
        self.peak_gb = max(self.peak_gb, peak)
        row = {"step": step, "tag": tag, "loss": loss, "lr": lr, "vram_peak_gb": round(peak, 3)}
        self.history.append(row)

        loss_s = f"{loss:.4f}" if isinstance(loss, (int, float)) else "n/a"
        lr_s = f"{lr:.3e}" if isinstance(lr, (int, float)) else "n/a"
        LOG.info(
            "[step %-6d] loss=%s  lr=%s  vram_now=%.2fGB  vram_peak=%.2fGB  (%.0fs)",
            step, loss_s, lr_s, now, peak, time.time() - self._t0,
        )

        if peak > self.warn_gb:
            self.warn_count += 1
            LOG.warning(
                "显存告警: 峰值 %.2fGB 超过红线 %.2fGB（总量 %.1fGB）。"
                "建议依次尝试: 1) per_device_train_batch_size 降为 1；"
                "2) model.max_seq_length 降为 %d；3) gradient_accumulation_steps 提到 16；"
                "4) 关闭 packing；5) 若仍 OOM，改用 DeepSeek-R1-Distill-Qwen-1.5B 基座。",
                peak, self.warn_gb, self.total_gb, self.fallback_seq_len,
            )

    # -- TrainerCallback 钩子 -- #
    def on_log(self, args, state, control, logs=None, **kwargs):  # noqa: ANN001
        if not getattr(state, "is_world_process_zero", True):
            return
        logs = logs or {}
        if self.log_every_step:
            self._sample("log", int(state.global_step), logs.get("loss"), logs.get("learning_rate"))

    def on_step_end(self, args, state, control, **kwargs):  # noqa: ANN001
        if not getattr(state, "is_world_process_zero", True):
            return
        self._sample("step", int(state.global_step), None, None)

    def on_train_end(self, args, state, control, **kwargs):  # noqa: ANN001
        LOG.info("训练结束: 峰值显存 %.2fGB，告警次数 %d", self.peak_gb, self.warn_count)


# =========================================================================== #
#  训练
# =========================================================================== #

def check_hardware() -> Dict[str, Any]:
    """启动前自检：CUDA / 显卡型号 / 显存 / flash-attn 误装检查。"""
    info: Dict[str, Any] = {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "torch": None,
        "cuda": None,
        "gpu": None,
        "vram_gb": None,
    }
    import torch

    info["torch"] = torch.__version__
    info["cuda"] = torch.version.cuda
    if not torch.cuda.is_available():
        LOG.error("CUDA 不可用！本项目要求 NVIDIA GPU + CUDA 12.4+。")
        raise SystemExit(3)

    props = torch.cuda.get_device_properties(0)
    info["gpu"] = props.name
    info["vram_gb"] = round(props.total_memory / 1024 ** 3, 2)
    LOG.info("硬件自检: %s | VRAM %.2fGB | torch %s | CUDA %s",
             info["gpu"], info["vram_gb"], info["torch"], info["cuda"])

    try:
        import flash_attn  # noqa: F401
        LOG.error("检测到已安装 flash-attn —— 本项目禁用（RTX 5060 兼容性未验证）。"
                  "请执行: pip uninstall -y flash-attn，并将 attn_implementation 设为 sdpa。")
        raise SystemExit(4)
    except ImportError:
        pass

    if "deepspeed" in sys.modules:
        LOG.warning("检测到 deepspeed 已导入；单卡训练不需要，配置中已禁用。")
    return info


def _to_torch_dtype(name: Any):
    """字符串 -> torch.dtype。unsloth 的 dtype/bnb_4bit_compute_dtype 只认 torch.dtype 或 None。"""
    import torch

    if name is None or str(name).lower() == "auto":
        return None
    if isinstance(name, torch.dtype):
        return name
    table = {
        "bfloat16": torch.bfloat16, "bf16": torch.bfloat16,
        "float16": torch.float16, "fp16": torch.float16, "half": torch.float16,
        "float32": torch.float32, "fp32": torch.float32,
    }
    resolved = table.get(str(name).lower())
    if resolved is None:
        LOG.warning("未知 dtype=%r，回退为 bfloat16", name)
        resolved = torch.bfloat16
    return resolved


def load_model_and_tokenizer(cfg: Dict[str, Any]):
    from unsloth import FastLanguageModel

    m = cfg["model"]
    attn = m.get("attn_implementation") or "sdpa"
    LOG.info("加载基座模型 %s（4-bit NF4 + double quant, seq=%d, attn=%s）",
             m["base_model"], m["max_seq_length"], attn)

    kwargs: Dict[str, Any] = {
        "model_name": m["base_model"],
        "max_seq_length": int(m["max_seq_length"]),
        "dtype": _to_torch_dtype(m.get("dtype", "bfloat16")),
        "load_in_4bit": bool(m.get("load_in_4bit", True)),
        "trust_remote_code": bool(m.get("trust_remote_code", True)),
    }

    # 关键坑：unsloth 的 from_pretrained 会把未知 kwarg 透传给 AutoModelForCausalLM，
    # 于是 bnb_4bit_quant_type 会以
    #   Qwen2ForCausalLM.__init__() got an unexpected keyword argument 'bnb_4bit_quant_type'
    # 报 TypeError。unsloth 内部默认已是 4-bit NF4 + double quant，因此只在签名
    # 显式声明时才传这些 bnb_* 参数。
    sig = inspect.signature(FastLanguageModel.from_pretrained).parameters
    optional_bnb: Dict[str, Any] = {
        "bnb_4bit_quant_type": m.get("bnb_4bit_quant_type", "nf4"),
        "bnb_4bit_use_double_quant": bool(m.get("bnb_4bit_use_double_quant", True)),
        "bnb_4bit_compute_dtype": _to_torch_dtype(m.get("bnb_4bit_compute_dtype", "bfloat16")),
    }
    dropped = [k for k in optional_bnb if k not in sig]
    kwargs.update({k: v for k, v in optional_bnb.items() if k in sig})
    if dropped:
        LOG.info("unsloth 未声明 %s，已省略（其内部默认即 4-bit NF4 + double quant）；"
                 "dtype 仍由 config.model.dtype 控制。", ", ".join(dropped))
    else:
        LOG.info("已将 bnb 量化参数（NF4 + double quant）显式传给 unsloth。")

    # attn_implementation 在某些 unsloth 版本不被接受 —— 显式传，失败则降级重试。
    # 注意：flash-attn 已在 check_hardware() 中确认未安装，所以降级不会偷偷用上它。
    try:
        model, tokenizer = FastLanguageModel.from_pretrained(attn_implementation=attn, **kwargs)
    except (TypeError, ValueError) as exc:
        LOG.warning("attn_implementation=%s 未被当前 unsloth 接受（%s），改用默认实现重试",
                    attn, mask_text(str(exc)))
        model, tokenizer = FastLanguageModel.from_pretrained(**kwargs)

    return model, tokenizer


def attach_lora(model, cfg: Dict[str, Any]):
    from unsloth import FastLanguageModel

    l = cfg["lora"]
    model = FastLanguageModel.get_peft_model(
        model,
        r=int(l.get("r", 16)),
        target_modules=list(l.get("target_modules", [])),
        lora_alpha=int(l.get("lora_alpha", 32)),
        lora_dropout=float(l.get("lora_dropout", 0.0)),
        bias=str(l.get("bias", "none")),
        use_gradient_checkpointing=l.get("use_gradient_checkpointing", "unsloth"),
        random_state=int(l.get("random_state", 3407)),
        use_rslora=bool(l.get("use_rslora", False)),
    )
    LOG.info("LoRA 注入完成: r=%s alpha=%s dropout=%s gc=%s",
             l.get("r"), l.get("lora_alpha"), l.get("lora_dropout"),
             l.get("use_gradient_checkpointing"))
    return model


def load_jsonl_dataset(path: Path, tokenizer, max_seq_length: int, limit: int = 0):
    """读取 {"messages":[...]} 的 jsonl，用 chat template 渲染到 text 字段。"""
    from datasets import Dataset

    if not path.exists():
        raise SystemExit(f"数据文件不存在: {path}（先运行 training/data_prep.py）")

    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
            if limit and len(rows) >= limit:
                break
    if not rows:
        raise SystemExit(f"数据文件为空: {path}")

    def render(row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "text": tokenizer.apply_chat_template(
                row["messages"], tokenize=False, add_generation_prompt=False
            ),
            "source": row.get("source", "unknown"),
        }

    drop_cols = sorted({k for row in rows[:64] for k in row.keys()})
    ds = Dataset.from_list(rows).map(render, remove_columns=drop_cols)
    LOG.info("数据集 %s: %d 条 -> 渲染完成（max_seq_length=%d）",
             path.relative_to(PROJECT_ROOT), len(ds), max_seq_length)
    return ds


def build_trainer(model, tokenizer, train_ds, eval_ds, cfg: Dict[str, Any], callbacks):
    """按已安装 TRL 版本的签名自适应构造 SFTTrainer（避免版本漂移报错）。"""
    from trl import SFTTrainer
    from transformers import TrainingArguments

    t = cfg["training"]
    # 相对项目根解析（相对路径约定）
    out_dir = resolve(t.get("output_dir") or (Path(cfg["project"].get("output_dir", "outputs")) / "run"))
    out_dir.mkdir(parents=True, exist_ok=True)

    ta_kwargs: Dict[str, Any] = {
        "output_dir": str(out_dir),
        "per_device_train_batch_size": int(t["per_device_train_batch_size"]),
        "per_device_eval_batch_size": int(t.get("per_device_eval_batch_size", 1)),
        "gradient_accumulation_steps": int(t["gradient_accumulation_steps"]),
        "num_train_epochs": float(t["num_train_epochs"]),
        "learning_rate": float(t["learning_rate"]),
        "lr_scheduler_type": t.get("lr_scheduler_type", "cosine"),
        "warmup_ratio": float(t.get("warmup_ratio", 0.03)),
        "weight_decay": float(t.get("weight_decay", 0.01)),
        "max_grad_norm": float(t.get("max_grad_norm", 1.0)),
        "optim": t.get("optim", "adamw_8bit"),
        "fp16": bool(t.get("fp16", False)),
        "bf16": bool(t.get("bf16", True)),
        "logging_steps": int(t.get("logging_steps", 1)),
        "save_strategy": t.get("save_strategy", "steps"),
        "save_steps": int(t.get("save_steps", 100)),
        "save_total_limit": int(t.get("save_total_limit", 2)),
        "group_by_length": bool(t.get("group_by_length", True)),
        "dataloader_num_workers": int(t.get("dataloader_num_workers", 2)),
        "dataloader_pin_memory": bool(t.get("dataloader_pin_memory", True)),
        "seed": int(t.get("seed", 3407)),
        "report_to": t.get("report_to", "none"),
        "gradient_checkpointing": True,               # 强制约束
        "gradient_checkpointing_kwargs": t.get("gradient_checkpointing_kwargs", {"use_reentrant": False}),
    }
    if int(t.get("max_steps", -1)) > 0:
        ta_kwargs["max_steps"] = int(t["max_steps"])
    if t.get("eval_strategy") and eval_ds is not None:
        ta_kwargs["eval_strategy"] = t["eval_strategy"]
        ta_kwargs["eval_steps"] = int(t.get("eval_steps", 50))

    # Windows 兜底：多进程 DataLoader 会在 pickle unsloth 注入的闭包时炸掉
    #   AttributeError: Can't pickle local object
    #     'enable_padding_free_metadata.<locals>.torch_call_with_padding_free_metadata'
    if sys.platform == "win32" and int(ta_kwargs.get("dataloader_num_workers", 0)) != 0:
        LOG.warning("Windows 平台下强制 dataloader_num_workers=0（原值 %s）：unsloth 注入的闭包无法 pickle。",
                    ta_kwargs["dataloader_num_workers"])
        ta_kwargs["dataloader_num_workers"] = 0

    # --- SFT 专属参数：新旧 TRL 的落点不同 ---
    # trl >= 0.16: max_length / packing / dataset_text_field 必须放进 SFTConfig，
    #              直接传给 SFTTrainer 会被 **静默忽略**（max_length 退回默认 1024）。
    # trl <  0.16: 这些参数由 SFTTrainer 直接接收，长度键名为 max_seq_length。
    seq_len = int(cfg["model"]["max_seq_length"])
    sft_only: Dict[str, Any] = {
        "dataset_text_field": cfg["data"].get("dataset_text_field", "text"),
        "packing": bool(cfg["data"].get("packing", False)),
    }

    args_is_sft_config = False
    try:
        from trl import SFTConfig
        sig_sft = inspect.signature(SFTConfig.__init__).parameters
        merged = dict(ta_kwargs)
        merged.update(sft_only)
        if "max_length" in sig_sft:
            merged["max_length"] = seq_len
        elif "max_seq_length" in sig_sft:
            merged["max_seq_length"] = seq_len
        args = SFTConfig(**{k: v for k, v in merged.items() if k in sig_sft})
        args_is_sft_config = True
        LOG.info("使用 SFTConfig（trl 新版）: max_length=%d packing=%s dataset_text_field=%s",
                 seq_len, sft_only["packing"], sft_only["dataset_text_field"])
    except ImportError:
        ta_sig = inspect.signature(TrainingArguments.__init__).parameters
        args = TrainingArguments(**{k: v for k, v in ta_kwargs.items() if k in ta_sig})
        sft_only["max_seq_length"] = seq_len
        LOG.info("使用 TrainingArguments（trl 旧版）: max_seq_length=%d", seq_len)

    sft_kwargs: Dict[str, Any] = {
        "model": model,
        "train_dataset": train_ds,
        "eval_dataset": eval_ds,
        "args": args,
        "callbacks": callbacks,
    }
    if not args_is_sft_config:
        sft_kwargs.update(sft_only)          # 旧 TRL：由 SFTTrainer 直接接收

    sft_sig = inspect.signature(SFTTrainer.__init__).parameters
    sft_kwargs = {k: v for k, v in sft_kwargs.items() if k in sft_sig}
    # tokenizer / processing_class 按签名二选一（同时传会被新版拒绝）
    if "processing_class" in sft_sig:
        sft_kwargs["processing_class"] = tokenizer
    elif "tokenizer" in sft_sig:
        sft_kwargs["tokenizer"] = tokenizer
    trainer = SFTTrainer(**sft_kwargs)

    # 只在 assistant 片段上计算 loss（提升小模型指令遵循质量）
    if cfg["training"].get("train_on_responses_only", True):
        try:
            from unsloth.chat_templates import train_on_responses_only
            trainer = train_on_responses_only(
                trainer,
                instruction_part=cfg["training"].get("instruction_template", "<|im_start|>user\n"),
                response_part=cfg["training"].get("response_template", "<|im_start|>assistant\n"),
            )
            LOG.info("已启用 train_on_responses_only（仅 assistant token 计入 loss）")
        except Exception as exc:  # noqa: BLE001
            LOG.warning("train_on_responses_only 不可用，回退为全序列 loss: %s", exc)

    return trainer, out_dir


def export_gguf(model, tokenizer, cfg: Dict[str, Any]) -> Optional[str]:
    """导出 GGUF（Q4_K_M）供 Ollama 使用。需要本地 llama.cpp。"""
    ex = cfg.get("export", {})
    gguf_dir = resolve(ex.get("gguf_dir", "deployment/gguf"))
    gguf_dir.mkdir(parents=True, exist_ok=True)
    try:
        model.save_pretrained_gguf(
            str(gguf_dir), tokenizer, quantization_method=ex.get("gguf_quant", "q4_k_m")
        )
    except Exception as exc:  # noqa: BLE001
        LOG.error("GGUF 导出失败（通常因为缺少 llama.cpp / 编译工具链）: %s", exc)
        LOG.error("替代方案: 1) 先 --merge 生成 16bit 全权重；"
                  "2) 在 llama.cpp 目录执行 convert_hf_to_gguf.py + llama-quantize；"
                  "3) 或用 deployment/serve.sh 的 Ollama 导入路径。")
        return None
    LOG.info("GGUF 已导出到 %s", gguf_dir.relative_to(PROJECT_ROOT))
    return str(gguf_dir)


# =========================================================================== #
#  main
# =========================================================================== #

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Qwen2.5-3B 蓝队 Agent QLoRA 微调")
    ap.add_argument("--config", default="training/config.yaml", help="YAML 配置路径")
    ap.add_argument("--smoke", action="store_true", help="冒烟测试：3 步、极小样本、不保存")
    ap.add_argument("--max-steps", type=int, default=None, help="覆盖 config 中的 max_steps")
    ap.add_argument("--max-samples", type=int, default=0, help="限制训练样本数（调试用）")
    ap.add_argument("--merge", action="store_true", help="额外合并导出 16bit 全权重")
    ap.add_argument("--no-merge", action="store_true", help="即使 config 要求也不合并")
    ap.add_argument("--export-gguf", action="store_true", help="训练结束后导出 GGUF Q4_K_M")
    ap.add_argument("--resume", default=None, help="从 checkpoint 恢复（路径或 True）")
    args = ap.parse_args(argv)

    cfg_path = resolve(args.config)
    cfg = load_config(cfg_path)

    if args.smoke:
        cfg["training"]["max_steps"] = 3
        cfg["training"]["num_train_epochs"] = 1
        cfg["data"]["max_samples"] = 64
        cfg["export"]["merge_16bit"] = False
        LOG.warning("冒烟模式：max_steps=3, samples<=64, 不导出 GGUF")
    if args.max_steps is not None:
        cfg["training"]["max_steps"] = int(args.max_steps)

    hw = check_hardware()

    # --- 数据 ---
    limit = int(cfg["data"].get("max_samples", 0)) or args.max_samples
    train_path = resolve(cfg["data"]["train_file"])
    eval_path = resolve(cfg["data"].get("eval_file", "")) if cfg["data"].get("eval_file") else None

    # --- 模型 ---
    model, tokenizer = load_model_and_tokenizer(cfg)
    model = attach_lora(model, cfg)

    train_ds = load_jsonl_dataset(train_path, tokenizer, int(cfg["model"]["max_seq_length"]), limit)
    eval_ds = (
        load_jsonl_dataset(eval_path, tokenizer, int(cfg["model"]["max_seq_length"]), 200)
        if eval_path and eval_path.exists() else None
    )
    if eval_ds is None:
        LOG.warning("未找到验证集 %s，跳过 eval。", eval_path)

    guard = VramGuardCallback(
        warn_gb=float(cfg["memory"].get("vram_warn_gb", 7.5)),
        total_gb=float(cfg["memory"].get("vram_total_gb", 8.0)),
        fallback_seq_len=int(cfg["memory"].get("fallback_max_seq_length", 1024)),
    )
    trainer, out_dir = build_trainer(model, tokenizer, train_ds, eval_ds, cfg, [guard])

    LOG.info("开始训练: epochs=%s max_steps=%s bs=%sx%s lr=%s",
             cfg["training"]["num_train_epochs"], cfg["training"].get("max_steps", -1),
             cfg["training"]["per_device_train_batch_size"],
             cfg["training"]["gradient_accumulation_steps"],
             cfg["training"]["learning_rate"])

    t0 = time.time()
    train_result = trainer.train(resume_from_checkpoint=args.resume)
    elapsed = time.time() - t0

    # --- 保存 LoRA adapter ---
    lora_dir = out_dir / "lora_adapter"
    model.save_pretrained(str(lora_dir))
    tokenizer.save_pretrained(str(lora_dir))
    LOG.info("LoRA adapter 已保存: %s", lora_dir.relative_to(PROJECT_ROOT))

    # --- 可选合并 ---
    merged_dir = resolve(cfg["export"].get("merged_dir", "outputs/merged"))
    do_merge = (args.merge or bool(cfg["export"].get("merge_16bit", False))) and not args.no_merge
    if do_merge:
        try:
            merged_dir.mkdir(parents=True, exist_ok=True)
            model.save_pretrained_merged(str(merged_dir), tokenizer, save_method="merged_16bit")
            LOG.info("已合并 16bit 全权重: %s", merged_dir.relative_to(PROJECT_ROOT))
        except Exception as exc:  # noqa: BLE001
            LOG.error("合并失败: %s", exc)

    # --- 可选 GGUF ---
    if args.export_gguf:
        export_gguf(model, tokenizer, cfg)

    # --- 训练报告（脱敏） ---
    report = {
        "base_model": cfg["model"]["base_model"],
        "hardware": mask_obj(hw),
        "elapsed_seconds": round(elapsed, 1),
        "train_samples": len(train_ds),
        "eval_samples": len(eval_ds) if eval_ds is not None else 0,
        "metrics": {k: (round(v, 6) if isinstance(v, float) else v)
                    for k, v in (train_result.metrics or {}).items()},
        "vram": {
            "peak_gb": round(guard.peak_gb, 3),
            "warn_threshold_gb": guard.warn_gb,
            "warn_count": guard.warn_count,
        },
        "config_snapshot": mask_obj(cfg),
        "lora_dir": str(lora_dir.relative_to(PROJECT_ROOT)),
        "log_tail": guard.history[-20:],
    }
    log_dir = resolve(cfg["project"].get("log_dir", "logs"))
    log_dir.mkdir(parents=True, exist_ok=True)
    report_path = resolve(cfg["project"].get("report_file", "logs/train_report.json"))
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    LOG.info("训练完成，用时 %.0fs；峰值显存 %.2fGB；报告: %s",
             elapsed, guard.peak_gb, report_path.relative_to(PROJECT_ROOT))
    if guard.peak_gb > guard.warn_gb:
        LOG.warning("本次训练峰值显存超红线，建议把 config.yaml 中 "
                    "per_device_train_batch_size 保持 1、max_seq_length 降到 %d 后重跑。",
                    cfg["memory"].get("fallback_max_seq_length", 1024))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
