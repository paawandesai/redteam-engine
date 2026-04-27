"""LangGraph adapter implementing the AgentAdapter protocol.

Wraps a compiled LangGraph StateGraph and provides injection/cleanup
for red team testing. Uses the mock agent pattern from
tests/fixtures/mock_agents/ as reference.
"""

from __future__ import annotations

import time
from typing import Any, Callable

from langchain_core.messages import AIMessage, HumanMessage

from redteam.engine.adapters.base import AgentCapabilities, AgentResponse


class LangGraphAdapter:
    """Adapter for compiled LangGraph graphs.

    Args:
        graph: A compiled LangGraph StateGraph (graph.invoke must work).
        inject_fn: Callable to inject content into the agent's document store.
        cleanup_fn: Callable to reset the agent's document store.
        tool_names: List of tool names the agent has access to.
    """

    def __init__(
        self,
        graph: Any,
        inject_fn: Callable[[str], None] | None = None,
        cleanup_fn: Callable[[], None] | None = None,
        tool_names: list[str] | None = None,
    ) -> None:
        self.graph = graph
        self._inject_fn = inject_fn
        self._cleanup_fn = cleanup_fn
        self._tool_names = tool_names or []
        # Multi-turn state. Reset by start_conversation().
        self._conversation_history: list[Any] = []

    async def invoke(
        self, prompt: str, context: dict | None = None
    ) -> AgentResponse:
        """Invoke the LangGraph agent and capture the response."""
        messages = [
            HumanMessage(
                content=(
                    "Please search the company knowledge base for information "
                    f"relevant to this question, then answer: {prompt}"
                )
            )
        ]

        start = time.perf_counter()
        try:
            result = self.graph.invoke({"messages": messages})
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            return AgentResponse(
                text="",
                error=str(e),
                latency_ms=elapsed,
            )
        elapsed = (time.perf_counter() - start) * 1000

        response_text = ""
        tool_calls: list[dict] = []
        intermediate_steps: list[dict] = []

        for msg in result.get("messages", []):
            if isinstance(msg, AIMessage):
                # Capture text from AI messages
                if msg.content and isinstance(msg.content, str):
                    response_text = msg.content
                elif msg.content and isinstance(msg.content, list):
                    for block in msg.content:
                        if isinstance(block, dict) and block.get("type") == "text":
                            response_text = block["text"]

                # Capture tool calls
                if msg.tool_calls:
                    for tc in msg.tool_calls:
                        tool_calls.append({
                            "tool_name": tc["name"],
                            "arguments": tc["args"],
                            "return_value": {},
                            "authorized": True,
                        })

            # Track intermediate steps
            intermediate_steps.append({
                "type": type(msg).__name__,
                "content_preview": str(msg.content)[:200]
                if hasattr(msg, "content")
                else "",
            })

        # Fallback: if no AIMessage had content, use the last message's
        # content. Some graphs (e.g., Agentic RAG's generate node) return
        # plain strings that LangGraph wraps as HumanMessage.
        if not response_text:
            messages = result.get("messages", [])
            if messages:
                last = messages[-1]
                if hasattr(last, "content") and last.content:
                    content = last.content
                    if isinstance(content, str):
                        response_text = content
                    elif isinstance(content, list):
                        for block in content:
                            if isinstance(block, dict) and block.get("type") == "text":
                                response_text = block["text"]
                                break

        # Enrich tool calls with return values from ToolMessages
        from langchain_core.messages import ToolMessage

        tool_msg_map: dict[str, str] = {}
        for msg in result.get("messages", []):
            if isinstance(msg, ToolMessage):
                tool_msg_map[msg.tool_call_id] = (
                    str(msg.content)[:500] if msg.content else ""
                )

        for msg in result.get("messages", []):
            if isinstance(msg, AIMessage) and msg.tool_calls:
                for tc in msg.tool_calls:
                    ret = tool_msg_map.get(tc["id"], "")
                    # Find matching tool call dict and update return_value
                    for tc_dict in tool_calls:
                        if (
                            tc_dict["tool_name"] == tc["name"]
                            and tc_dict["arguments"] == tc["args"]
                            and not tc_dict["return_value"]
                        ):
                            tc_dict["return_value"] = {"content": ret}
                            # Check for blocked/denied responses
                            if "BLOCKED" in ret or "Access denied" in ret:
                                tc_dict["authorized"] = False
                            break

        return AgentResponse(
            text=response_text,
            tool_calls=tool_calls,
            intermediate_steps=intermediate_steps,
            raw_response={
                "message_count": len(result.get("messages", [])),
            },
            latency_ms=elapsed,
        )

    async def get_capabilities(self) -> AgentCapabilities:
        has_tools = bool(self._tool_names)
        has_retrieval = any(
            "retriev" in t.lower() or "search" in t.lower()
            for t in self._tool_names
        )
        return AgentCapabilities(
            has_retrieval=has_retrieval,
            has_tools=has_tools,
            tool_list=list(self._tool_names),
        )

    async def setup_injection(
        self, content: str, injection_point: str
    ) -> None:
        if self._inject_fn is not None:
            self._inject_fn(content)

    async def cleanup_injection(self) -> None:
        if self._cleanup_fn is not None:
            self._cleanup_fn()

    # ------------------------------------------------------------------
    # Multi-turn conversation API
    # ------------------------------------------------------------------

    async def start_conversation(self) -> None:
        """Reset conversation history for a fresh multi-turn attack."""
        self._conversation_history = []

    async def continue_conversation(self, message: str) -> AgentResponse:
        """Add a user message and run a turn, preserving prior history.

        The agent sees the full conversation so far. All AI/Tool messages
        produced by this turn are appended to the history so the next
        call sees them as context.
        """
        from langchain_core.messages import ToolMessage

        self._conversation_history.append(HumanMessage(content=message))

        start = time.perf_counter()
        try:
            result = self.graph.invoke({"messages": list(self._conversation_history)})
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            return AgentResponse(text="", error=str(e), latency_ms=elapsed)
        elapsed = (time.perf_counter() - start) * 1000

        result_msgs = result.get("messages", [])
        # Identify the new messages produced by this turn (everything
        # past the prior history length).
        new_msgs = result_msgs[len(self._conversation_history):]

        # Capture text + tool calls from this turn only
        text = ""
        turn_tool_calls: list[dict] = []
        intermediate: list[dict] = []

        # Build tool-message map for return values
        tool_msg_map: dict[str, str] = {}
        for msg in new_msgs:
            if isinstance(msg, ToolMessage):
                tool_msg_map[msg.tool_call_id] = (
                    str(msg.content)[:500] if msg.content else ""
                )

        for msg in new_msgs:
            intermediate.append({
                "type": type(msg).__name__,
                "content_preview": (
                    str(msg.content)[:200] if hasattr(msg, "content") else ""
                ),
            })
            if isinstance(msg, AIMessage):
                if msg.content and isinstance(msg.content, str):
                    text = msg.content
                elif msg.content and isinstance(msg.content, list):
                    for block in msg.content:
                        if isinstance(block, dict) and block.get("type") == "text":
                            text = block["text"]
                if msg.tool_calls:
                    for tc in msg.tool_calls:
                        ret = tool_msg_map.get(tc["id"], "")
                        authorized = not (
                            "BLOCKED" in ret or "Access denied" in ret
                        )
                        turn_tool_calls.append({
                            "tool_name": tc["name"],
                            "arguments": tc["args"],
                            "return_value": {"content": ret},
                            "authorized": authorized,
                        })

        # Persist new messages so the next turn sees them
        self._conversation_history = list(result_msgs)

        return AgentResponse(
            text=text,
            tool_calls=turn_tool_calls,
            intermediate_steps=intermediate,
            latency_ms=elapsed,
        )
