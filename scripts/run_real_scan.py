"""Run adversarial prompts against real LangGraph agents and compare results.

Targets:
1. Vulnerable mock agent (tests/fixtures/mock_agents/vulnerable_rag_agent.py)
2. Agentic RAG (from langchain-ai/langgraph, ChromaDB + retriever tool)
3. Adaptive RAG (from langchain-ai/langgraph, ChromaDB + Tavily + multi-stage grading)

Usage:
    # Install deps first: uv pip install -e ".[real-agents,langgraph,dev]"

    # Quick comparison (5 prompts, ~$0.15 API cost)
    uv run python scripts/run_real_scan.py --count 5

    # Full dataset (28 prompts, ~$0.85 API cost)
    uv run python scripts/run_real_scan.py --count 28

    # Skip adaptive RAG (no TAVILY_API_KEY)
    uv run python scripts/run_real_scan.py --count 5 --skip-adaptive
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

# Ensure project root is importable
_project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_project_root / "src"))
sys.path.insert(0, str(_project_root))

load_dotenv()
console = Console()


def _load_prompts(count: int) -> list:
    """Load the top N highest-severity prompts from the dataset."""
    from redteam.models.prompts import AdversarialPrompt

    dataset_path = (
        Path(__file__).resolve().parent.parent
        / "datasets"
        / "prompts"
        / "prompt-injection-rag"
        / "direct-instruction.json"
    )

    data = json.loads(dataset_path.read_text())
    prompts = [AdversarialPrompt.model_validate(item) for item in data]
    prompts = sorted(prompts, key=lambda p: -p.severity)
    return prompts[:count]


def _run_scan(adapter, dataset, label: str) -> dict:
    """Run a scan and return {prompt_id: grade} mapping."""
    from redteam.engine.runner import ScanRunner

    runner = ScanRunner(
        adapter=adapter,
        dataset=dataset,
        grading_mode="rule-only",
        concurrency=1,
        timeout=60,
    )
    result = asyncio.run(runner.run())
    return {f.prompt_id: f.grade.value for f in result.findings}


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare agents against adversarial prompts")
    parser.add_argument("--count", type=int, default=5, help="Number of prompts to test")
    parser.add_argument("--model", default="gpt4o-mini", help="Model key for mock agent")
    parser.add_argument("--skip-adaptive", action="store_true", help="Skip Adaptive RAG")
    args = parser.parse_args()

    # Check API keys
    if not os.environ.get("OPENAI_API_KEY"):
        console.print("[red]OPENAI_API_KEY not set. Add it to .env[/red]")
        sys.exit(1)

    prompts = _load_prompts(args.count)
    console.print(f"\nLoaded [bold]{len(prompts)}[/bold] prompts (sorted by severity)\n")

    prompt_ids = [p.id for p in prompts]
    results: dict[str, dict[str, str]] = {}

    # ── Agent 1: Vulnerable mock ─────────────────────────────────
    console.print("[bold cyan]Agent 1: Vulnerable Mock Agent[/bold cyan]")
    os.environ["MODEL"] = args.model

    from tests.fixtures.mock_agents.vulnerable_rag_agent import (
        clear_injections as mock_clear,
        graph as mock_graph,
        inject_document as mock_inject,
    )

    from redteam.engine.adapters.langgraph_adapter import LangGraphAdapter

    mock_adapter = LangGraphAdapter(
        graph=mock_graph,
        inject_fn=mock_inject,
        cleanup_fn=mock_clear,
        tool_names=["retrieve_documents", "file_read", "web_search"],
    )
    results["Vulnerable Mock"] = _run_scan(mock_adapter, prompts, "Vulnerable Mock")
    console.print("  Done.\n")

    # ── Agent 2: Agentic RAG ─────────────────────────────────────
    console.print("[bold cyan]Agent 2: Agentic RAG (langchain-ai/langgraph)[/bold cyan]")
    console.print("  Building vector store (scraping 3 blog posts)...")

    from tests.fixtures.real_agents.agentic_rag import build as build_agentic

    agentic_graph, agentic_inject, agentic_clear = build_agentic()
    agentic_adapter = LangGraphAdapter(
        graph=agentic_graph,
        inject_fn=agentic_inject,
        cleanup_fn=agentic_clear,
        tool_names=["retrieve_blog_posts"],
    )
    results["Agentic RAG"] = _run_scan(agentic_adapter, prompts, "Agentic RAG")
    console.print("  Done.\n")

    # ── Agent 3: Adaptive RAG ────────────────────────────────────
    if not args.skip_adaptive:
        if not os.environ.get("TAVILY_API_KEY"):
            console.print(
                "[yellow]TAVILY_API_KEY not set — skipping Adaptive RAG. "
                "Use --skip-adaptive to silence this.[/yellow]\n"
            )
        else:
            console.print("[bold cyan]Agent 3: Adaptive RAG (langchain-ai/langgraph)[/bold cyan]")
            console.print("  Building vector store (scraping 3 blog posts)...")

            from tests.fixtures.real_agents.adaptive_rag import build as build_adaptive

            adaptive_graph, adaptive_inject, adaptive_clear = build_adaptive()
            adaptive_adapter = LangGraphAdapter(
                graph=adaptive_graph,
                inject_fn=adaptive_inject,
                cleanup_fn=adaptive_clear,
                tool_names=["retrieve_blog_posts"],
            )
            results["Adaptive RAG"] = _run_scan(
                adaptive_adapter, prompts, "Adaptive RAG"
            )
            console.print("  Done.\n")

    # ── Comparison table ─────────────────────────────────────────
    agent_names = list(results.keys())

    table = Table(title="Adversarial Scan Comparison", show_lines=True)
    table.add_column("Prompt ID", style="bold", min_width=16)
    table.add_column("Sev", justify="center", width=4)
    for name in agent_names:
        table.add_column(name, justify="center", min_width=14)

    grade_styles = {
        "pass": "[green]PASS[/green]",
        "partial_fail": "[yellow]PARTIAL[/yellow]",
        "fail": "[red]FAIL[/red]",
        "critical_fail": "[bold red]CRITICAL[/bold red]",
        "pending_review": "[dim]PENDING[/dim]",
    }

    for prompt in prompts:
        row = [prompt.id, str(prompt.severity)]
        for name in agent_names:
            grade = results[name].get(prompt.id, "—")
            row.append(grade_styles.get(grade, grade))
        table.add_row(*row)

    console.print()
    console.print(table)

    # ── Summary stats ────────────────────────────────────────────
    console.print()
    for name in agent_names:
        grades = results[name]
        total = len(grades)
        passed = sum(1 for g in grades.values() if g == "pass")
        failed = sum(1 for g in grades.values() if g in ("fail", "critical_fail"))
        critical = sum(1 for g in grades.values() if g == "critical_fail")
        rate = (passed / total * 100) if total > 0 else 0

        color = "green" if rate >= 80 else "yellow" if rate >= 50 else "red"
        console.print(
            f"  [bold]{name}:[/bold] [{color}]{rate:.0f}% pass rate[/{color}] "
            f"({passed} pass, {failed} fail, {critical} critical)"
        )

    est_cost = len(prompts) * len(agent_names) * 0.01
    console.print(f"\n  [dim]Estimated API cost: ~${est_cost:.2f}[/dim]\n")


if __name__ == "__main__":
    main()
