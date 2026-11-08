#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""rag/build_kb.py — 构建知识库（向量库）。

知识来源：
  1. `rag/seeds/blue_team_seed.jsonl` —— 本项目编写的蓝队判据/处置playbook（事实性摘要）
  2. 可选：`data/*.jsonl` 领域语料（按 config.build.corpus_sources 过滤后切块）

产物：`rag/kb/` 下 embeddings.npy / docs.jsonl / meta.json / embedder_idf.npy

用法:
    python rag/build_kb.py
    python rag/build_kb.py --no-corpus --dim 512
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from rag.embed import build_embedder  # noqa: E402
from rag.vector_store import Document, VectorStore  # noqa: E402


def load_seeds(path: Path) -> List[Document]:
    docs: List[Document] = []
    if not path.exists():
        print(f"[warn] 种子文件不存在: {path}")
        return docs
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            docs.append(Document(obj["doc_id"], obj["text"], obj.get("metadata", {})))
    return docs


def chunk(text: str, size: int, overlap: int) -> List[str]:
    text = (text or "").strip()
    if len(text) <= size:
        return [text] if text else []
    out: List[str] = []
    step = max(1, size - overlap)
    for start in range(0, len(text), step):
        piece = text[start:start + size].strip()
        if piece:
            out.append(piece)
        if start + size >= len(text):
            break
    return out


def load_corpus(files: Sequence[Path], sources: Sequence[str], size: int, overlap: int,
                max_docs: int = 6000) -> List[Document]:
    docs: List[Document] = []
    allowed = {s.strip() for s in sources if s.strip()}
    for path in files:
        if not path.exists():
            print(f"[warn] 语料文件不存在: {path}")
            continue
        with path.open("r", encoding="utf-8") as fh:
            for i, line in enumerate(fh):
                if len(docs) >= max_docs:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                src = row.get("source", "unknown")
                if allowed and src not in allowed:
                    continue
                # 只把 assistant 的最终回答作为知识（user 提问不进库）
                answers = [m["content"] for m in row.get("messages", [])
                           if m.get("role") == "assistant"]
                if not answers:
                    continue
                for j, piece in enumerate(chunk("\n".join(answers), size, overlap)):
                    docs.append(Document(
                        doc_id=f"corpus-{path.stem}-{i}-{j}",
                        text=piece,
                        metadata={"source": f"corpus:{src}", "file": path.name},
                    ))
    return docs


def main(argv: Optional[List[str]] = None) -> int:
    import yaml  # noqa: PLC0415

    ap = argparse.ArgumentParser(description="构建 RAG 知识库")
    ap.add_argument("--config", default="rag/config.yaml")
    ap.add_argument("--no-corpus", action="store_true", help="只索引 seeds，不索引 data/*.jsonl")
    ap.add_argument("--dim", type=int, default=None, help="覆盖嵌入维度")
    ap.add_argument("--backend", default=None, help="覆盖嵌入后端（hash / st）")
    args = ap.parse_args(argv)

    cfg_path = PROJECT_ROOT / args.config
    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    b = cfg.get("build", {})
    e = cfg.get("embedder", {})

    seeds = load_seeds(PROJECT_ROOT / b.get("seeds_file", "rag/seeds/blue_team_seed.jsonl"))
    print(f"[build] seeds: {len(seeds)} 条")

    corpus_docs: List[Document] = []
    if not args.no_corpus and b.get("include_corpus", True):
        files = [PROJECT_ROOT / f for f in b.get("corpus_files", [])]
        corpus_docs = load_corpus(
            files,
            b.get("corpus_sources", []),
            int(b.get("chunk_chars", 900)),
            int(b.get("chunk_overlap", 120)),
        )
        print(f"[build] corpus: {len(corpus_docs)} 块（来自 {len(files)} 个文件）")

    docs = seeds + corpus_docs
    if not docs:
        print("[error] 没有任何文档可索引")
        return 2

    dim = int(args.dim or e.get("dim", 1024))
    backend = args.backend or e.get("backend", "hash")
    print(f"[build] 嵌入后端={backend} dim={dim}，共 {len(docs)} 条")

    emb = build_embedder(backend, dim=dim, st_model=e.get("st_model", "BAAI/bge-small-zh-v1.5"))
    emb.fit([d.text for d in docs])
    vectors = emb.encode([d.text for d in docs])
    print(f"[build] 向量矩阵: {vectors.shape}")

    store = VectorStore(dim=vectors.shape[1])
    store.add(docs, vectors)
    kb_dir = PROJECT_ROOT / cfg.get("kb_dir", "rag/kb")
    store.save(kb_dir, emb.state())

    # 词法后端的 IDF 必须与库一起持久化，否则查询向量和库向量不在同一空间
    if hasattr(emb, "idf"):
        np.save(kb_dir / "embedder_idf.npy", emb.idf)
        print("[build] 已保存 embedder_idf.npy")

    from collections import Counter
    kinds = Counter(d.metadata.get("kind") or d.metadata.get("source", "?") for d in docs)
    print(f"[build] 完成 → {kb_dir}  构成: {dict(kinds)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
