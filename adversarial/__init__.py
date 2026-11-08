"""adversarial 包：对抗数据构建与鲁棒性训练（仅用于加固本项目防御模型）。"""
from .wildjailbreak import (  # noqa: F401
    REFUSAL_TEMPLATES,
    RefusalPair,
    build_refusal,
    categorize,
    load_pairs,
    to_sft_rows,
)

__all__ = [
    "RefusalPair",
    "REFUSAL_TEMPLATES",
    "build_refusal",
    "categorize",
    "load_pairs",
    "to_sft_rows",
]
