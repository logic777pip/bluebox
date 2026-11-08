"""agent 包：蓝队应急响应 Agent（RAG + 情报 + schema + 接地校验 + 两阶段确认）。"""
from .agent import (  # noqa: F401
    AgentResponse,
    BlueTeamAgent,
    LocalBackend,
    OllamaBackend,
    StubBackend,
    build_backend,
    build_system_prompt,
    build_user_prompt,
)

__all__ = [
    "BlueTeamAgent",
    "AgentResponse",
    "StubBackend",
    "OllamaBackend",
    "LocalBackend",
    "build_backend",
    "build_system_prompt",
    "build_user_prompt",
]
