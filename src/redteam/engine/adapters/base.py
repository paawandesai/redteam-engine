"""Base adapter interface for target agents.

All framework-specific adapters implement the AgentAdapter protocol.
The scan runner depends only on this interface, not on any specific framework.
"""

from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel


class AgentResponse(BaseModel):
    """Captured agent execution result."""

    text: str
    tool_calls: list[dict] = []
    intermediate_steps: list[dict] = []
    raw_response: dict = {}
    latency_ms: float = 0.0
    error: str | None = None


class AgentCapabilities(BaseModel):
    """Describes what the target agent can do."""

    has_retrieval: bool = False
    has_tools: bool = False
    tool_list: list[str] = []
    has_memory: bool = False
    multi_agent: bool = False


class AgentAdapter(Protocol):
    """Protocol that all framework adapters must satisfy."""

    async def invoke(
        self, prompt: str, context: dict | None = None
    ) -> AgentResponse: ...

    async def get_capabilities(self) -> AgentCapabilities: ...

    async def setup_injection(
        self, content: str, injection_point: str
    ) -> None: ...

    async def cleanup_injection(self) -> None: ...
