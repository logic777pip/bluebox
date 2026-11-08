#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""rag/embed.py — 可插拔嵌入后端。

本机实测可用依赖只有 numpy（无 sklearn / faiss / sentence-transformers），因此默认
后端是**自带的 Hashing TF-IDF**：

  * 特征 = 词元（含 CJK 单字/双字）+ 字符 2/3-gram
  * 哈希用 blake2b（**不是** Python 内置 hash，后者有随机盐，跨进程不稳定 → 无法持久化）
  * sublinear TF + 语料 IDF + L2 归一化
  * IOC / ATT&CK ID 类词元加权，保证精确匹配（IP、哈希、T15xx）能命中

它本质是**词法**检索：同义改写召回弱于神经网络嵌入。要更好的语义召回时安装
`sentence-transformers` 并把 config 的 backend 改成 `st`——本模块会自动切换。

⚠ 这是「抗幻觉」的第一道闸：检索结果会作为唯一事实来源注入上下文，
   并配合 retrieve.grounding_check() 校验答案里的 IOC 是否真的来自上下文。
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence

import numpy as np

# --------------------------------------------------------------------------- #
#  词法切分
# --------------------------------------------------------------------------- #

_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_\-.]*|\d[\d.]*|[\u4e00-\u9fff]")
# 需要精确命中的高价值词元（IOC / 技术编号 / 事件 ID）
_HIGH_VALUE_RE = re.compile(
    r"\b(?:[Tt]\d{4}(?:\.\d{3})?|CVE-\d{4}-\d{4,7}|[0-9a-fA-F]{32,64}|[A-Za-z0-9.\-]+\.(?:com|net|org|io|cn)|"
    r"(?:\d{1,3}\.){3}\d{1,3})\b"
)


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip().lower())


def _hash_idx(token: str, dim: int) -> int:
    """blake2b -> 桶索引。跨进程/跨平台稳定，可安全持久化。"""
    digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, "big") % dim


def _features(text: str) -> List[tuple[str, float]]:
    """返回 [(特征名, 权重)]。"""
    t = _norm(text)
    out: List[tuple[str, float]] = []

    for tok in _TOKEN_RE.findall(t):
        out.append((f"w:{tok}", 1.0))

    # CJK 双字（提升中文短语区分度）
    cjk = "".join(ch for ch in t if "\u4e00" <= ch <= "\u9fff")
    for i in range(len(cjk) - 1):
        out.append((f"c:{cjk[i]}{cjk[i + 1]}", 0.8))

    # 字符 3-gram（对拼写差异/格式噪声更鲁棒）
    compact = re.sub(r"[^0-9a-z\u4e00-\u9fff]", "", t)
    for i in range(len(compact) - 2):
        out.append((f"g:{compact[i:i + 3]}", 0.5))

    # 高价值词元加权（IOC 精确匹配靠它）
    for tok in _HIGH_VALUE_RE.findall(text or ""):
        out.append((f"h:{tok.lower()}", 4.0))

    return out


# --------------------------------------------------------------------------- #
#  后端
# --------------------------------------------------------------------------- #

@dataclass
class EmbedderInfo:
    name: str
    dim: int
    fitted: bool = False


class BaseEmbedder:
    info: EmbedderInfo

    def fit(self, corpus: Sequence[str]) -> "BaseEmbedder":
        return self

    def encode(self, texts: Sequence[str]) -> np.ndarray:
        raise NotImplementedError

    def state(self) -> Dict[str, Any]:
        return {"name": self.info.name, "dim": self.info.dim}


class HashingTfidfEmbedder(BaseEmbedder):
    def __init__(self, dim: int = 1024) -> None:
        self.info = EmbedderInfo(name="hash_tfidf", dim=dim)
        self.dim = int(dim)
        self.idf = np.ones(self.dim, dtype=np.float32)

    # -- 拟合 IDF -- #
    def fit(self, corpus: Sequence[str]) -> "HashingTfidfEmbedder":
        df = np.zeros(self.dim, dtype=np.float64)
        n = 0
        for doc in corpus:
            n += 1
            seen = {f for f, _ in _features(doc)}
            for f in seen:
                df[_hash_idx(f, self.dim)] += 1.0
        self.idf = (np.log((1.0 + n) / (1.0 + df)) + 1.0).astype(np.float32)
        self.info.fitted = True
        return self

    # -- 编码 -- #
    def encode(self, texts: Sequence[str]) -> np.ndarray:
        out = np.zeros((len(texts), self.dim), dtype=np.float32)
        for row, text in enumerate(texts):
            tf: Dict[int, float] = {}
            for feat, weight in _features(text):
                idx = _hash_idx(feat, self.dim)
                tf[idx] = tf.get(idx, 0.0) + weight
            for idx, count in tf.items():
                out[row, idx] = (1.0 + math.log(count)) * self.idf[idx]
            norm = float(np.linalg.norm(out[row]))
            if norm > 0:
                out[row] /= norm
        return out

    def state(self) -> Dict[str, Any]:
        return {"name": "hash_tfidf", "dim": self.dim}


class SentenceTransformerEmbedder(BaseEmbedder):
    """可选后端：需要 `pip install sentence-transformers`（会下载模型）。"""

    def __init__(self, model_name: str = "BAAI/bge-small-zh-v1.5") -> None:
        from sentence_transformers import SentenceTransformer  # noqa: PLC0415

        self.model = SentenceTransformer(model_name)
        self.info = EmbedderInfo(name=f"st:{model_name}",
                                 dim=int(self.model.get_sentence_embedding_dimension()),
                                 fitted=True)

    def encode(self, texts: Sequence[str]) -> np.ndarray:
        vecs = self.model.encode(list(texts), normalize_embeddings=True,
                                 show_progress_bar=False)
        return np.asarray(vecs, dtype=np.float32)

    def state(self) -> Dict[str, Any]:
        return {"name": self.info.name, "dim": self.info.dim}


# --------------------------------------------------------------------------- #
#  工厂
# --------------------------------------------------------------------------- #

def build_embedder(backend: str = "hash", dim: int = 1024,
                   st_model: str = "BAAI/bge-small-zh-v1.5") -> BaseEmbedder:
    backend = (backend or "hash").lower()
    if backend in ("hash", "hash_tfidf", "lexical"):
        return HashingTfidfEmbedder(dim=dim)
    if backend in ("st", "sentence-transformers", "sbert"):
        try:
            return SentenceTransformerEmbedder(st_model)
        except Exception as exc:  # noqa: BLE001
            print(f"[embed] sentence-transformers 不可用（{exc}），回退 hash_tfidf。"
                  f"安装：pip install sentence-transformers")
            return HashingTfidfEmbedder(dim=dim)
    raise ValueError(f"未知嵌入后端: {backend}")


if __name__ == "__main__":  # 自检
    docs = [
        "T1110 Brute Force 暴力破解：单一源地址短时间内对多台主机发起认证尝试",
        "file-srv-02 共享盘出现 3 万次写入，后缀统一为 .lock7z，命中 T1486 数据加密",
        "203.0.113.45 属于 RFC5737 文档网段，不指向真实主机",
    ]
    emb = build_embedder("hash", dim=512).fit(docs)
    q = "勒索软件 加密 共享盘 后缀 lock7z"
    sims = emb.encode([q]) @ emb.encode(docs).T
    print("[自检] 查询:", q)
    for d, s in sorted(zip(docs, sims[0]), key=lambda x: -x[1]):
        print(f"  {s:.4f}  {d[:40]}")
    assert sims[0][1] == max(sims[0]), "最相似的应含 lock7z 的那条"
    print("[自检] OK")
