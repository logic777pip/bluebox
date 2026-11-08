"""rag 包：抗幻觉检索层（向量库 + 接地校验）。"""
from .embed import BaseEmbedder, HashingTfidfEmbedder, build_embedder  # noqa: F401
from .retrieve import (  # noqa: F401
    GroundingReport,
    Retriever,
    RetrievedContext,
    extract_indicators,
    grounding_check,
)
from .vector_store import Document, Hit, VectorStore  # noqa: F401

__all__ = [
    "BaseEmbedder",
    "HashingTfidfEmbedder",
    "build_embedder",
    "Document",
    "Hit",
    "VectorStore",
    "Retriever",
    "RetrievedContext",
    "GroundingReport",
    "extract_indicators",
    "grounding_check",
]
