"""Base adapter interface for target agents.

All framework-specific adapters implement the AgentAdapter protocol.
The scan runner depends only on this interface, not on any specific framework.
"""

from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel


class AgentResponse(BaseModel):
    """Captured agent execution result.

    For single-turn invocations, `turns` is empty and the top-level
    fields describe the only response. For multi-turn invocations,
    `turns` holds a per-turn breakdown and the top-level fields
    aggregate across turns: `text` is the final turn's text, and
    `tool_calls`/`intermediate_steps` accumulate every turn's calls
    in chronological order.
    """

    text: str
    tool_calls: list[dict] = []
    intermediate_steps: list[dict] = []
    raw_response: dict = {}
    latency_ms: float = 0.0
    error: str | None = None
    turns: list[dict] = []  # per-turn breakdown for multi-turn scans


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

    # Multi-turn support. The runner only calls these when an
    # AdversarialPrompt has more than one send_prompt step. Adapters
    # may raise NotImplementedError if they don't support multi-turn.
    async def start_conversation(self) -> None: ...

    async def continue_conversation(self, message: str) -> AgentResponse: ...
