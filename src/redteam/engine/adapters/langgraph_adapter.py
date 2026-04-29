"""LangGraph adapter implementing the AgentAdapter protocol.

Wraps any compiled LangGraph graph that uses MessagesState (or accepts
{"messages": [...]} as input). Works with `create_react_agent()` graphs
and custom StateGraphs alike.

Public arguments:
    graph: A compiled LangGraph (graph.invoke must work).
    inject_fn: Optional callable to inject content into the agent's
        document store. If None, RAG-injection prompts will run against
        a non-injecting agent — they'll typically PASS, which is correct.
    cleanup_fn: Optional callable to reset the document store after
        each prompt.
    tool_names: Optional explicit tool list. If omitted, the adapter
        attempts to auto-detect tools by inspecting the graph's nodes.
"""

from __future__ import annotations

import time
from typing import Any, Callable

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from redteam.engine.adapters.base import AgentCapabilities, AgentResponse


_MESSAGES_STATE_HINT = (
    "This agent doesn't accept MessagesState input "
    "({'messages': [HumanMessage(...)]}). "
    "The LangGraphAdapter only supports graphs that use MessagesState. "
    "For other input schemas, write a custom adapter — "
    "see src/redteam/engine/adapters/base.py for the AgentAdapter protocol "
    "and docs/scanning-your-agent.md."
)


def _auto_detect_tools(graph: Any) -> list[str]:
    """Best-effort auto-detection of tool names from a compiled graph.

    Tries multiple introspection strategies; returns whatever it can
    find, sorted. Returns [] if nothing detected.
    """
    detected: set[str] = set()

    def _harvest(obj: Any) -> None:
        # ToolNode-like objects expose .tools_by_name (dict[str, Tool])
        tbn = getattr(obj, "tools_by_name", None)
        if isinstance(tbn, dict):
            detected.update(str(k) for k in tbn.keys())
        # Some nodes keep a .tools iterable
        tools = getattr(obj, "tools", None)
        if tools and hasattr(tools, "__iter__"):
            try:
                for t in tools:
                    name = getattr(t, "name", None)
                    if isinstance(name, str):
                        detected.add(name)
            except TypeError:
                pass

    # Strategy 1: graph.nodes (compiled graphs expose this)
    try:
        nodes = getattr(graph, "nodes", None)
        if isinstance(nodes, dict):
            for node in nodes.values():
                _harvest(node)
                # Some graphs wrap the actual runnable in .runnable / .bound
                for attr in ("runnable", "bound", "node"):
                    inner = getattr(node, attr, None)
                    if inner is not None:
                        _harvest(inner)
    except Exception:
        pass

    # Strategy 2: graph.builder.nodes (StateGraph builder, before compile)
    try:
        builder = getattr(graph, "builder", None)
        if builder is not None:
            bnodes = getattr(builder, "nodes", {}) or {}
            for n in (bnodes.values() if hasattr(bnodes, "values") else []):
                _harvest(n)
    except Exception:
        pass

    return sorted(detected)


class LangGraphAdapter:
    """Adapter for compiled LangGraph graphs using MessagesState."""

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
        # Explicit tool_names override auto-detection. Otherwise inspect.
        self._tool_names = (
            list(tool_names) if tool_names is not None else _auto_detect_tools(graph)
        )
        # Multi-turn state. Reset by start_conversation().
        self._conversation_history: list[Any] = []

    async def invoke(
        self, prompt: str, context: dict | None = None
    ) -> AgentResponse:
        """Invoke the agent with a single user message and capture the response.

        The prompt is sent verbatim as a HumanMessage; the adapter does
        not prepend any framing text. If the agent has retrieval tools
        and a system prompt that encourages retrieval, the agent will
        retrieve on its own.
        """
        messages = [HumanMessage(content=prompt)]

        start = time.perf_counter()
        try:
            result = self.graph.invoke({"messages": messages})
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            err = str(e)
            # Heuristic: if the graph rejects MessagesState input, add the hint
            if any(s in err.lower() for s in ("messages", "state", "schema", "input")):
                err = f"{err}\n\n{_MESSAGES_STATE_HINT}"
            return AgentResponse(text="", error=err, latency_ms=elapsed)
        elapsed = (time.perf_counter() - start) * 1000

        if not isinstance(result, dict) or "messages" not in result:
            return AgentResponse(
                text="",
                error=(
                    "Graph returned no 'messages' key. " + _MESSAGES_STATE_HINT
                ),
                latency_ms=elapsed,
            )

        return self._extract_response(result.get("messages", []), elapsed)

    def _extract_response(
        self, msgs: list[Any], latency_ms: float
    ) -> AgentResponse:
        """Pull text + tool calls + intermediate steps out of a message list."""
        response_text = ""
        tool_calls: list[dict] = []
        intermediate_steps: list[dict] = []

        for msg in msgs:
            if isinstance(msg, AIMessage):
                if msg.content and isinstance(msg.content, str):
                    response_text = msg.content
                elif msg.content and isinstance(msg.content, list):
                    for block in msg.content:
                        if isinstance(block, dict) and block.get("type") == "text":
                            response_text = block["text"]
                if msg.tool_calls:
                    for tc in msg.tool_calls:
                        tool_calls.append({
                            "tool_name": tc["name"],
                            "arguments": tc["args"],
                            "return_value": {},
                            "authorized": True,
                        })
            intermediate_steps.append({
                "type": type(msg).__name__,
                "content_preview": (
                    str(msg.content)[:200] if hasattr(msg, "content") else ""
                ),
            })

        # Fallback: if no AIMessage had text, use the last message's content
        if not response_text and msgs:
            last = msgs[-1]
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
        tool_msg_map: dict[str, str] = {}
        for msg in msgs:
            if isinstance(msg, ToolMessage):
                tool_msg_map[msg.tool_call_id] = (
                    str(msg.content)[:500] if msg.content else ""
                )
        for msg in msgs:
            if isinstance(msg, AIMessage) and msg.tool_calls:
                for tc in msg.tool_calls:
                    ret = tool_msg_map.get(tc["id"], "")
                    for tc_dict in tool_calls:
                        if (
                            tc_dict["tool_name"] == tc["name"]
                            and tc_dict["arguments"] == tc["args"]
                            and not tc_dict["return_value"]
                        ):
                            tc_dict["return_value"] = {"content": ret}
                            if "BLOCKED" in ret or "Access denied" in ret:
                                tc_dict["authorized"] = False
                            break

        return AgentResponse(
            text=response_text,
            tool_calls=tool_calls,
            intermediate_steps=intermediate_steps,
            raw_response={"message_count": len(msgs)},
            latency_ms=latency_ms,
        )

    async def get_capabilities(self) -> AgentCapabilities:
        has_tools = bool(self._tool_names)
        # Heuristic: any tool with "retriev" or "search" in the name
        # (retrieve_documents, search_documents, vector_search, etc.)
        has_retrieval = any(
            "retriev" in t.lower() or "search" in t.lower() or "vector" in t.lower()
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
        """Inject content into the agent's doc store, if supported.

        Silently no-op if no inject_fn was provided. RAG-injection prompts
        run against an agent without retrieval will then PASS naturally —
        the injection has no surface to land on.
        """
        if self._inject_fn is not None:
            self._inject_fn(content)

    async def cleanup_injection(self) -> None:
        """Reset the agent's doc store, if a cleanup_fn was provided."""
        if self._cleanup_fn is not None:
            self._cleanup_fn()

    # ------------------------------------------------------------------
    # Multi-turn conversation API
    # ------------------------------------------------------------------

    async def start_conversation(self) -> None:
        """Reset conversation history for a fresh multi-turn attack."""
        self._conversation_history = []

    async def continue_conversation(self, message: str) -> AgentResponse:
        """Add a user message and run a turn, preserving prior history."""
        self._conversation_history.append(HumanMessage(content=message))

        start = time.perf_counter()
        try:
            result = self.graph.invoke({"messages": list(self._conversation_history)})
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            return AgentResponse(text="", error=str(e), latency_ms=elapsed)
        elapsed = (time.perf_counter() - start) * 1000

        result_msgs = result.get("messages", [])
        new_msgs = result_msgs[len(self._conversation_history):]

        text = ""
        turn_tool_calls: list[dict] = []
        intermediate: list[dict] = []

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
