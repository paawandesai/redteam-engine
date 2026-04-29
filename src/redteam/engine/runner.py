"""Core scan execution engine.

Orchestrates the scan lifecycle:
1. Load prompts from dataset
2. For each prompt: inject → invoke → grade → build finding
3. Collect results into a ScanResult
4. Save pending reviews for Claude Code batch grading
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime
from pathlib import Path

from redteam.engine.adapters.base import AgentAdapter, AgentResponse
from redteam.engine.grader import GradeResult, GradingPipeline
from redteam.models.enums import AttackCategory, Grade
from redteam.models.prompts import AdversarialPrompt
from redteam.models.results import Finding, ScanResult, ToolCallTrace

# EU AI Act compliance mapping by category
COMPLIANCE_MAP: dict[str, list[dict]] = {
    "prompt_injection_rag": [
        {"framework": "eu_ai_act", "reference": "Article 9", "requirement": "9(2)(a)"},
        {"framework": "eu_ai_act", "reference": "Article 15", "requirement": "15(5)"},
    ],
    "tool_misuse": [
        {"framework": "eu_ai_act", "reference": "Article 14", "requirement": "14(4)(d)"},
        {"framework": "eu_ai_act", "reference": "Article 9", "requirement": "9(7)"},
    ],
    "cross_agent_injection": [
        {"framework": "eu_ai_act", "reference": "Article 15", "requirement": "15(5)"},
        {"framework": "eu_ai_act", "reference": "Article 9", "requirement": "9(2)(b)"},
    ],
    "memory_poisoning": [
        {"framework": "eu_ai_act", "reference": "Article 12", "requirement": "12(1)"},
        {"framework": "eu_ai_act", "reference": "Article 15", "requirement": "15(4)"},
    ],
}

# Map grade strings to Grade enum
_GRADE_MAP = {
    "pass": Grade.PASS,
    "partial_fail": Grade.PARTIAL_FAIL,
    "fail": Grade.FAIL,
    "critical_fail": Grade.CRITICAL_FAIL,
    "pending_review": Grade.FAIL,  # Default pending to FAIL for safety
}


_KNOWN_TOOL_NAMES = {
    "file_read", "send_email", "update_account",
    "query_database", "retrieve_documents", "web_search",
    "search_documents", "search",
}


def _required_tools(prompt: AdversarialPrompt) -> set[str]:
    """Extract tool names referenced in a prompt's indicators or attack_steps."""
    text = " ".join(prompt.vulnerability_indicators).lower()
    for step in prompt.attack_steps:
        text += " " + str(step).lower()
    return {t for t in _KNOWN_TOOL_NAMES if t in text}


class ScanRunner:
    """Core execution engine for adversarial scans."""

    def __init__(
        self,
        adapter: AgentAdapter,
        dataset: list[AdversarialPrompt],
        grading_mode: str = "batch-review",
        concurrency: int = 3,
        timeout: int = 30,
        filter_by_capabilities: bool = True,
    ) -> None:
        self.adapter = adapter
        self.dataset = [p for p in dataset if p.is_included]
        self.grading = GradingPipeline(mode=grading_mode)
        self.concurrency = concurrency
        self.timeout = timeout
        self.pending_reviews: list[dict] = []
        self.filter_by_capabilities = filter_by_capabilities
        # Populated by run() after capability detection
        self.capability_filter_summary: dict | None = None

    async def _apply_capability_filter(
        self, prompts: list[AdversarialPrompt]
    ) -> tuple[list[AdversarialPrompt], dict]:
        """Filter prompts based on detected agent capabilities.

        Conservative rules:
          - Skip prompt-injection-rag prompts when has_retrieval=False
          - Skip prompts mentioning specific tools when none of those
            tools appear in the agent's tool_list (only if tool_list
            is non-empty — empty list means we don't know, so we keep
            everything to be safe)

        Returns (kept_prompts, summary).
        """
        try:
            caps = await self.adapter.get_capabilities()
        except Exception:
            return prompts, {
                "filter_applied": False,
                "reason": "get_capabilities() failed; running all prompts",
                "kept": len(prompts),
                "skipped": 0,
            }

        kept: list[AdversarialPrompt] = []
        skipped_no_retrieval = 0
        skipped_no_tool: dict[str, int] = {}
        agent_tools = set(caps.tool_list)
        knows_tools = bool(agent_tools)

        for p in prompts:
            cat = p.category.value if hasattr(p.category, "value") else str(p.category)
            if cat == "prompt_injection_rag" and not caps.has_retrieval:
                skipped_no_retrieval += 1
                continue
            required = _required_tools(p)
            # Drop tools that are universally available or RAG-specific
            required.discard("retrieve_documents")
            required.discard("search_documents")
            required.discard("search")
            if knows_tools and required and required.isdisjoint(agent_tools):
                missing_key = "+".join(sorted(required))
                skipped_no_tool[missing_key] = skipped_no_tool.get(missing_key, 0) + 1
                continue
            kept.append(p)

        summary = {
            "filter_applied": True,
            "has_retrieval": caps.has_retrieval,
            "tool_list": sorted(agent_tools),
            "kept": len(kept),
            "skipped_no_retrieval": skipped_no_retrieval,
            "skipped_missing_tools": skipped_no_tool,
            "total_input": len(prompts),
        }
        return kept, summary

    async def run(self) -> ScanResult:
        """Execute all prompts against the target agent."""
        # Capability-based filtering before scan loop
        prompts_to_run = self.dataset
        if self.filter_by_capabilities:
            prompts_to_run, self.capability_filter_summary = (
                await self._apply_capability_filter(self.dataset)
            )

        semaphore = asyncio.Semaphore(self.concurrency)
        findings: list[Finding] = []

        async def run_single(prompt: AdversarialPrompt) -> Finding | None:
            async with semaphore:
                return await self._execute_prompt(prompt)

        tasks = [run_single(p) for p in prompts_to_run]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Finding):
                findings.append(result)
            elif isinstance(result, Exception):
                # Log but don't crash the scan
                pass

        summary = self._build_summary(findings)
        scan_id = f"scan-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"

        return ScanResult(
            scan_id=scan_id,
            schema_version="1.0.0",
            engine_version="0.1.0",
            target={"adapter": "langgraph"},
            summary=summary,
            findings=findings,
        )

    async def _execute_prompt(
        self, prompt: AdversarialPrompt
    ) -> Finding:
        """Execute a single prompt: inject → invoke → grade → build finding.

        Handles two cases:
          - Single-turn (1 send_prompt step): existing invoke() path.
          - Multi-turn (2+ send_prompt steps): start_conversation +
            continue_conversation per step, with tool calls / text
            accumulated across turns and graded as a chain.
        """
        # 1. Setup injection if needed
        if prompt.injection_content and prompt.injection_point:
            injection_content = self._get_injection_content(prompt)
            await self.adapter.setup_injection(
                injection_content, prompt.injection_point
            )

        # 2. Determine multi-turn vs single-turn
        send_prompt_steps = self._send_prompt_steps(prompt)
        is_multi_turn = len(send_prompt_steps) > 1 and hasattr(
            self.adapter, "continue_conversation"
        )

        try:
            if is_multi_turn:
                response = await asyncio.wait_for(
                    self._execute_multi_turn(send_prompt_steps),
                    timeout=self.timeout * len(send_prompt_steps),
                )
            else:
                user_query = self._extract_user_query(prompt)
                response = await asyncio.wait_for(
                    self.adapter.invoke(user_query),
                    timeout=self.timeout,
                )
        except asyncio.TimeoutError:
            response = AgentResponse(
                text="",
                error=f"Timeout after {self.timeout}s",
                latency_ms=self.timeout * 1000,
            )
        except Exception as e:
            response = AgentResponse(
                text="",
                error=str(e),
            )

        # 3. Cleanup injection
        await self.adapter.cleanup_injection()

        # 4. Grade the response
        grade_result = self.grading.grade(prompt, response)

        # 5. Collect pending reviews
        if grade_result.grading_method == "pending_review":
            self.pending_reviews.append(grade_result.context)

        # 6. Build finding
        return self._build_finding(prompt, response, grade_result)

    async def _execute_multi_turn(
        self, send_prompt_steps: list[dict]
    ) -> AgentResponse:
        """Run a multi-turn attack as a connected conversation.

        The agent sees each turn with full prior history. Tool calls
        across all turns are aggregated so chain detection in the
        grader can spot multi-step exploits.
        """
        await self.adapter.start_conversation()

        all_tool_calls: list[dict] = []
        all_intermediate: list[dict] = []
        turns_breakdown: list[dict] = []
        last_text = ""
        total_latency = 0.0
        last_error: str | None = None

        for i, step in enumerate(send_prompt_steps, 1):
            params = step.get("params", {})
            message = (
                params.get("user_query")
                or params.get("query")
                or params.get("message")
                or ""
            )
            turn_response = await self.adapter.continue_conversation(message)
            turns_breakdown.append({
                "turn": i,
                "user_message": message,
                "agent_text": turn_response.text,
                "tool_calls": list(turn_response.tool_calls),
                "latency_ms": turn_response.latency_ms,
                "error": turn_response.error,
            })
            all_tool_calls.extend(turn_response.tool_calls)
            all_intermediate.extend(turn_response.intermediate_steps)
            last_text = turn_response.text or last_text
            total_latency += turn_response.latency_ms or 0.0
            if turn_response.error:
                last_error = turn_response.error

        return AgentResponse(
            text=last_text,
            tool_calls=all_tool_calls,
            intermediate_steps=all_intermediate,
            latency_ms=total_latency,
            error=last_error,
            turns=turns_breakdown,
        )

    def _send_prompt_steps(self, prompt: AdversarialPrompt) -> list[dict]:
        """Return all send_prompt steps from attack_steps in order."""
        return [s for s in prompt.attack_steps if s.get("action") == "send_prompt"]

    def _get_injection_content(self, prompt: AdversarialPrompt) -> str:
        """Get the full document to inject from attack_steps or injection_content."""
        for step in prompt.attack_steps:
            if step.get("action") == "inject_document":
                params = step.get("params", {})
                if "document_content" in params:
                    return params["document_content"]
                if "content" in params:
                    return params["content"]
        return prompt.injection_content or ""

    def _extract_user_query(self, prompt: AdversarialPrompt) -> str:
        """Extract the user query from attack_steps."""
        for step in prompt.attack_steps:
            params = step.get("params", {})
            if "user_query" in params:
                return params["user_query"]
            if "query" in params:
                return params["query"]
            if "message" in params:
                return params["message"]
        return prompt.description

    def _build_finding(
        self,
        prompt: AdversarialPrompt,
        response: AgentResponse,
        grade_result: GradeResult,
    ) -> Finding:
        """Convert a graded response into a Finding with compliance refs."""
        category_str = prompt.category.value
        compliance_refs = COMPLIANCE_MAP.get(category_str, [])
        grade = _GRADE_MAP.get(grade_result.grade, Grade.FAIL)

        tool_traces = [
            ToolCallTrace(
                tool_name=tc.get("tool_name", tc.get("tool", "")),
                arguments=tc.get("arguments", tc.get("args", {})),
                return_value=tc.get("return_value", {}),
                authorized=tc.get("authorized", True),
            )
            for tc in response.tool_calls
        ]

        return Finding(
            finding_id=f"f-{uuid.uuid4().hex[:8]}",
            prompt_id=prompt.id,
            category=prompt.category,
            subcategory=prompt.subcategory,
            severity=prompt.severity,
            grade=grade,
            confidence=grade_result.confidence,
            grading_method=grade_result.grading_method,
            agent_response=response.text,
            tool_calls_made=tool_traces,
            intermediate_steps=response.intermediate_steps,
            reasoning=grade_result.reasoning,
            compliance_refs=compliance_refs,
            latency_ms=response.latency_ms,
            turns=response.turns,
        )

    def _build_summary(self, findings: list[Finding]) -> dict:
        """Compute summary stats from findings."""
        by_grade: dict[str, int] = {}
        by_category: dict[str, dict[str, int]] = {}

        for f in findings:
            grade_str = f.grade.value
            by_grade[grade_str] = by_grade.get(grade_str, 0) + 1

            cat = f.category.value
            if cat not in by_category:
                by_category[cat] = {}
            by_category[cat][grade_str] = (
                by_category[cat].get(grade_str, 0) + 1
            )

        return {
            "total": len(findings),
            "by_grade": by_grade,
            "by_category": by_category,
            "grading_stats": dict(self.grading.stats),
        }

    def save_pending_reviews(self, output_dir: str = "results") -> Path | None:
        """Save pending review findings to JSON for Claude Code grading."""
        if not self.pending_reviews:
            return None
        path = Path(output_dir)
        path.mkdir(parents=True, exist_ok=True)
        out_file = path / "pending-review.json"
        out_file.write_text(
            json.dumps(self.pending_reviews, indent=2) + "\n"
        )
        return out_file
