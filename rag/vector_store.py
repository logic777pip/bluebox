#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""rag/vector_store.py — 轻量持久化向量库（纯 numpy，无 FAISS 依赖）。

设计取舍：本机没有 faiss/sklearn，且知识库规模在 1e4 量级，
暴力余弦检索在中文字向量 1024 维、1 万条时约几十毫秒，完全够用 ——
因此选择「零依赖 + 可审计（纯文本 docs.jsonl）」而不是引入外部向量服务。

持久化产物（目录下三件套，均可 diff / 版本管理）：
    embeddings.npy    float32 [N, dim]
    docs.jsonl        每行 {"doc_id","text","metadata"}
    meta.json         嵌入后端信息 + 维度 + 条目数 + 内容指纹
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

import numpy as np

from .embed import BaseEmbedder, build_embedder


@dataclass
class Document:
    doc_id: str
    text: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Hit:
    doc_id: str
    text: str
    score: float
    metadata: Dict[str, Any] = field(default_factory=dict)

    def cite(self) -> str:
        src = self.metadata.get("source", "kb")
        return f"[{src}:{self.doc_id}]"


class VectorStore:
    def __init__(self, dim: int = 1024) -> None:
        self.dim = int(dim)
        self.docs: List[Document] = []
        self.vectors: Optional[np.ndarray] = None
        self.meta: Dict[str, Any] = {}

    # ------------------------------------------------------------------ #
    #  写
    # ------------------------------------------------------------------ #
    def add(self, docs: Sequence[Document], vectors: np.ndarray) -> None:
        if len(docs) != len(vectors):
            raise ValueError(f"docs 与 vectors 数量不一致: {len(docs)} vs {len(vectors)}")
        vectors = np.asarray(vectors, dtype=np.float32)
        if self.vectors is None:
            self.vectors = vectors
        else:
            self.vectors = np.vstack([self.vectors, vectors])
        self.docs.extend(docs)

    def save(self, directory: Path, embedder_state: Dict[str, Any]) -> None:
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        if self.vectors is None or not self.docs:
            raise ValueError("向量库为空，拒绝保存")

        np.save(directory / "embeddings.npy", self.vectors)
        with (directory / "docs.jsonl").open("w", encoding="utf-8", newline="\n") as fh:
            for d in self.docs:
                fh.write(json.dumps(asdict(d), ensure_ascii=False) + "\n")

        fingerprint = hashlib.sha256(
            "\n".join(d.text for d in self.docs).encode("utf-8")
        ).hexdigest()[:16]
        meta = {
            "count": len(self.docs),
            "dim": int(self.vectors.shape[1]),
            "embedder": embedder_state,
            "content_fingerprint": fingerprint,
        }
        (directory / "meta.json").write_text(
            json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        self.meta = meta

    # ------------------------------------------------------------------ #
    #  读
    # ------------------------------------------------------------------ #
    @classmethod
    def load(cls, directory: Path) -> "VectorStore":
        directory = Path(directory)
        meta_path = directory / "meta.json"
        if not meta_path.exists():
            raise FileNotFoundError(
                f"向量库不存在: {directory}（先运行 training/rag_build_kb.py 或 rag/build_kb.py）"
            )
        store = cls(dim=int(json.loads(meta_path.read_text(encoding="utf-8"))["dim"]))
        store.meta = json.loads(meta_path.read_text(encoding="utf-8"))
        store.vectors = np.load(directory / "embeddings.npy")
        with (directory / "docs.jsonl").open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    obj = json.loads(line)
                    store.docs.append(Document(obj["doc_id"], obj["text"], obj.get("metadata", {})))
        return store

    # ------------------------------------------------------------------ #
    #  检索
    # ------------------------------------------------------------------ #
    def search(self, query_vec: np.ndarray, top_k: int = 5, min_score: float = 0.05,
               where: Optional[Dict[str, Any]] = None) -> List[Hit]:
        if self.vectors is None or not self.docs:
            return []
        q = np.asarray(query_vec, dtype=np.float32).reshape(-1)
        qn = float(np.linalg.norm(q))
        if qn == 0:
            return []
        q = q / qn

        sims = self.vectors @ q
        order = np.argsort(-sims)

        hits: List[Hit] = []
        for idx in order:
            score = float(sims[int(idx)])
            if score < min_score:
                break
            doc = self.docs[int(idx)]
            if where and any(doc.metadata.get(k) != v for k, v in where.items()):
                continue
            hits.append(Hit(doc.doc_id, doc.text, round(score, 4), doc.metadata))
            if len(hits) >= top_k:
                break
        return hits
