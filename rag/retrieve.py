#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""rag/retrieve.py — 检索接口 + 抗幻觉接地校验。

两条腿：
  1. **检索**：向量召回（语义/词法）+ 词法精确召回（IOC / ATT&CK ID）双路合并去重。
  2. **接地校验（grounding check）**：从模型答案中抽出所有可验证指标（IP、哈希、
     CVE、ATT&CK 编号、域名），逐个检查是否真的出现在「检索上下文 / 本案观测」里。
     不在 → 判为编造，答案必须被拒绝或重写。这是把「不许臆造 IOC」从提示词
     的口号变成**可执行的闸门**。

用法（CLI 自检）:
    python -m rag.retrieve --query "共享盘被加密 lock7z 怎么处置"
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from rag.embed import BaseEmbedder, build_embedder
from rag.vector_store import Hit, VectorStore

# --------------------------------------------------------------------------- #
#  指标抽取（用于接地校验）
# --------------------------------------------------------------------------- #

_DOC_IP_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.", "127.0.0.1")

_INDICATOR_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("ipv4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    ("sha256", re.compile(r"\b[0-9a-fA-F]{64}\b")),
    ("md5", re.compile(r"\b[0-9a-fA-F]{32}\b")),
    ("cve", re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)),
    ("attck", re.compile(r"\bT\d{4}(?:\.\d{3})?\b")),
    ("domain", re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
                          r"(?:com|net|org|io|cn|top|xyz|ru|info|biz|onion)\b")),
    ("registry", re.compile(r"\bHK(?:LM|CU|CR|U)\\[^\s，,。；;]{4,120}")),
    ("filepath", re.compile(r"[A-Za-z]:\\[^\s，,。；;\"]{4,160}")),
]


@dataclass
class GroundingReport:
    ok: bool
    total: int
    unsupported: List[Tuple[str, str]] = field(default_factory=list)
    supported: List[Tuple[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "total": self.total,
            "unsupported": [{"kind": k, "value": v} for k, v in self.unsupported],
            "supported_count": len(self.supported),
        }


def extract_indicators(text: str) -> List[Tuple[str, str]]:
    """返回 [(kind, value)]，已去重。"""
    out: List[Tuple[str, str]] = []
    seen: set[Tuple[str, str]] = set()
    for kind, pattern in _INDICATOR_PATTERNS:
        for m in pattern.findall(text or ""):
            value = m if isinstance(m, str) else m[0]
            key = (kind, value.lower())
            if key in seen:
                continue
            seen.add(key)
            out.append((kind, value))
    return out


def _is_placeholder(kind: str, value: str) -> bool:
    """文档网段是示例占位符，允许出现（不代表真实资产）。"""
    return kind == "ipv4" and value.startswith(_DOC_IP_PREFIXES)


def grounding_check(answer: str, contexts: Sequence[str], observation: str = "",
                    max_unsupported: int = 0) -> GroundingReport:
    """校验答案中的指标是否被上下文/观测支持。

    参数 contexts 为检索到的知识片段（作为唯一事实来源），observation 为本案原始观测。
    """
    haystack = "\n".join(list(contexts) + [observation or ""]).lower()
    supported: List[Tuple[str, str]] = []
    unsupported: List[Tuple[str, str]] = []

    for kind, value in extract_indicators(answer):
        if _is_placeholder(kind, value) or value.lower() in haystack:
            supported.append((kind, value))
        else:
            unsupported.append((kind, value))

    return GroundingReport(
        ok=len(unsupported) <= max_unsupported,
        total=len(supported) + len(unsupported),
        unsupported=unsupported,
        supported=supported,
    )


# --------------------------------------------------------------------------- #
#  检索器
# --------------------------------------------------------------------------- #

@dataclass
class RetrievedContext:
    hits: List[Hit]
    text: str

    def citations(self) -> List[str]:
        return [h.cite() for h in self.hits]


class Retriever:
    def __init__(self, config_path: Optional[Path] = None, kb_dir: Optional[Path] = None,
                 backend: Optional[str] = None) -> None:
        cfg_path = Path(config_path) if config_path else (PROJECT_ROOT / "rag" / "config.yaml")
        import yaml  # noqa: PLC0415

        self.cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}

        kb = Path(kb_dir) if kb_dir else (PROJECT_ROOT / self.cfg.get("kb_dir", "rag/kb"))
        self.kb_dir = kb
        self.store = VectorStore.load(kb)

        emb_cfg = self.cfg.get("embedder", {})
        want = backend or self.store.meta.get("embedder", {}).get("name", emb_cfg.get("backend", "hash"))
        if want.startswith("st:"):
            self.embedder: BaseEmbedder = build_embedder("st", st_model=want.split(":", 1)[1])
        else:
            self.embedder = build_embedder(emb_cfg.get("backend", "hash"), dim=int(emb_cfg.get("dim", 1024)))

        # 词法后端必须复现构建时的 IDF，否则查询与库向量不在同一空间
        idf_path = kb / "embedder_idf.npy"
        if idf_path.exists() and hasattr(self.embedder, "idf"):
            import numpy as np  # noqa: PLC0415

            idf = np.load(idf_path)
            if len(idf) == self.embedder.dim:
                self.embedder.idf = idf
            else:
                raise RuntimeError(f"IDF 维度不匹配: {len(idf)} vs {self.embedder.dim}")

        r = self.cfg.get("retrieval", {})
        self.top_k = int(r.get("top_k", 5))
        self.min_score = float(r.get("min_score", 0.05))
        self.exact_top_k = int(r.get("exact_top_k", 3))
        self.max_context_chars = int(r.get("max_context_chars", 4000))

    # -- 检索 -- #
    def _search_one(self, query: str, k: int) -> List[Hit]:
        """单查询：向量召回 + 词法精确召回（不做重排）。"""
        vec = self.embedder.encode([query])
        hits = self.store.search(vec, top_k=max(k * 3, 12), min_score=self.min_score)

        # 词法精确召回：IOC / ATT&CK 编号直接做子串匹配，避免被语义相似度淹没
        keys = [v.lower() for kind, v in extract_indicators(query)
                if kind in ("ipv4", "sha256", "md5", "cve", "attck", "domain")]
        if keys:
            extra: List[Hit] = []
            for doc in self.store.docs:
                low = doc.text.lower()
                if any(kk in low for kk in keys):
                    extra.append(Hit(doc.doc_id, doc.text, 1.0, doc.metadata))
                if len(extra) >= self.exact_top_k:
                    break
            seen = {h.doc_id for h in hits}
            hits = extra + [h for h in hits if h.doc_id not in seen]
        return hits

    def decompose(self, text: str, max_sub: int = 4) -> List[str]:
        """把长告警拆成子查询。

        必要性：整段告警（几十到几百字）做单一 query 时，向量会被大量无关词稀释，
        实测余弦相似度会掉到 min_score 以下 → **零召回**。按句子/分句分别检索再合并
        是标准做法，也保证「告警里那一个关键短语」能命中对应判据。
        """
        parts = [p.strip() for p in re.split(r"[。；;.!?\n]+", text or "") if len(p.strip()) >= 6]
        parts.sort(key=len, reverse=True)
        subs = parts[:max_sub]
        ind = [v for _k, v in extract_indicators(text) if _k in ("ipv4", "sha256", "md5", "cve", "attck", "domain")]
        if ind:
            subs.append(" ".join(ind[:6]))
        return subs or [text]

    def search(self, query: str, top_k: Optional[int] = None) -> List[Hit]:
        """多子查询合并检索（长文本自动拆分）。"""
        k = top_k or self.top_k
        best: Dict[str, Hit] = {}
        for sub in self.decompose(query):
            for h in self._search_one(sub, k):
                prev = best.get(h.doc_id)
                if prev is None or h.score > prev.score:
                    best[h.doc_id] = h
        return self.rerank(list(best.values()), k)

    @staticmethod
    def _source_weight(hit: Hit) -> float:
        """策展内容（本项目编写的判据/playbook）优先于批量语料。"""
        kind = str(hit.metadata.get("kind", ""))
        src = str(hit.metadata.get("source", ""))
        if src == "seed":
            return 1.35 if kind in ("technique", "playbook") else 1.25
        if src.startswith("corpus:synth"):
            return 1.15          # 行为对齐语料与蓝队任务最贴近
        if src.startswith("corpus:blackbox") or src.startswith("corpus:phishing"):
            return 1.08
        # 通用批量语料（含英文 CTI）：词法后端下与中文查询共享大量拉丁词元，
        # 容易把真正相关的策展条目挤下去，因此适度降权。
        return 0.85

    def rerank(self, hits: List[Hit], top_k: int, per_source_cap: int = 2) -> List[Hit]:
        """加权 + 同源限流，避免前几名被同一来源的低相关块占满。"""
        scored = sorted(hits, key=lambda h: -(h.score * self._source_weight(h)))
        out: List[Hit] = []
        used: Dict[str, int] = {}
        for h in scored:
            src = str(h.metadata.get("source", "?"))
            if used.get(src, 0) >= per_source_cap:
                continue
            used[src] = used.get(src, 0) + 1
            out.append(h)
            if len(out) >= top_k:
                break
        return out

    def build_context(self, query: str, top_k: Optional[int] = None) -> RetrievedContext:
        hits = self.search(query, top_k)
        budget = self.max_context_chars
        parts: List[str] = []
        used: List[Hit] = []
        for h in hits:
            block = f"{h.cite()} {h.text}"
            if sum(len(p) for p in parts) + len(block) > budget:
                break
            parts.append(block)
            used.append(h)
        return RetrievedContext(used, "\n\n".join(parts))


# --------------------------------------------------------------------------- #
#  CLI 自检
# --------------------------------------------------------------------------- #

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="RAG 检索自检")
    ap.add_argument("--query", required=True)
    ap.add_argument("--top-k", type=int, default=None)
    ap.add_argument("--check-answer", default=None, help="额外的接地校验文本")
    args = ap.parse_args(argv)

    r = Retriever()
    print(f"[kb] {r.kb_dir}  条目={len(r.store.docs)}  嵌入={r.store.meta.get('embedder')}")
    ctx = r.build_context(args.query, args.top_k)
    print(f"\n[query] {args.query}\n")
    for h in ctx.hits:
        print(f"  {h.score:.4f}  {h.cite()}  {h.text[:90]}...")

    if args.check_answer:
        rep = grounding_check(args.check_answer, [h.text for h in ctx.hits], args.query)
        print("\n[grounding]", json.dumps(rep.to_dict(), ensure_ascii=False))
        return 0 if rep.ok else 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
