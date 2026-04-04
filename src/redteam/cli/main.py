import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(name="redteam", help="Adversarial testing engine for AI agents")
console = Console()


def _load_prompts_from_dir(path: Path) -> list:
    """Load AdversarialPrompt objects from a directory of JSON files."""
    from redteam.models.prompts import AdversarialPrompt

    prompts = []
    for json_file in sorted(path.rglob("*.json")):
        try:
            data = json.loads(json_file.read_text())
        except json.JSONDecodeError:
            console.print(f"[red]Skipping invalid JSON: {json_file}[/red]")
            continue
        if isinstance(data, list):
            for item in data:
                try:
                    prompts.append(AdversarialPrompt.model_validate(item))
                except Exception as e:
                    console.print(f"[red]Validation error in {json_file}: {e}[/red]")
        elif isinstance(data, dict):
            try:
                prompts.append(AdversarialPrompt.model_validate(data))
            except Exception as e:
                console.print(f"[red]Validation error in {json_file}: {e}[/red]")
    return prompts


@app.command()
def generate(
    category: str = typer.Option("all", help="Attack category to generate"),
    subcategory: str = typer.Option("", help="Subcategory filter"),
    count: int = typer.Option(20, help="Number of prompts to generate"),
    use_api: bool = typer.Option(False, "--use-api", help="Use Anthropic API instead of Claude Code session"),
) -> None:
    """Generate adversarial prompts."""
    if use_api:
        from redteam.models.enums import AttackCategory
        from redteam.generators.synthetic import PromptGenerator

        try:
            cat = AttackCategory(category)
        except ValueError:
            console.print(f"[red]Unknown category: {category}[/red]")
            raise typer.Exit(1)
        generator = PromptGenerator()
        try:
            generator.generate(category=cat, subcategory=subcategory, count=count)
        except NotImplementedError as e:
            console.print(f"[yellow]{e}[/yellow]")
        raise typer.Exit()

    console.print(
        "\n[bold cyan]Adversarial Prompt Generation[/bold cyan]\n"
        "\n"
        "This project generates prompts via [bold]Claude Code sessions[/bold] (uses your Max\n"
        "subscription, zero API cost). To generate prompts:\n"
        "\n"
        f"  1. Open a Claude Code session in this repo\n"
        f"  2. Ask Claude to generate {count} adversarial prompts\n"
        f"     for category: [green]{category}[/green]"
        + (f", subcategory: [green]{subcategory}[/green]" if subcategory else "")
        + "\n"
        "  3. Reference templates in src/redteam/generators/templates/\n"
        "  4. Claude writes directly to datasets/prompts/<category>/\n"
        "\n"
        "For automated/CI generation, use [dim]--use-api[/dim] (requires ANTHROPIC_API_KEY).\n"
    )


@app.command()
def scan(
    config: str = typer.Option(None, help="Path to target YAML config"),
    module: str = typer.Option(None, help="Python module:graph for direct scanning"),
    quick: bool = typer.Option(False, help="Run quick scan (first 50 prompts by severity)"),
    grading_mode: str = typer.Option("batch-review", help="batch-review | rule-only | llm"),
    category: str = typer.Option(None, help="Filter to specific category"),
    severity_min: int = typer.Option(1, help="Minimum severity to include"),
    output: str = typer.Option("results/", help="Output directory"),
) -> None:
    """Run adversarial scan against a target agent."""
    import asyncio
    import importlib

    from redteam.engine.adapters.langgraph_adapter import LangGraphAdapter
    from redteam.engine.runner import ScanRunner
    from redteam.models.enums import AttackCategory

    if not module and not config:
        console.print("[red]Specify --module or --config[/red]")
        raise typer.Exit(1)

    # --- Import the graph ---
    if module:
        parts = module.rsplit(":", 1)
        if len(parts) != 2:
            console.print("[red]--module format: package.module:graph_var[/red]")
            raise typer.Exit(1)
        mod_path, graph_var = parts
        console.print(f"Importing [bold]{mod_path}:{graph_var}[/bold]...")
        try:
            mod = importlib.import_module(mod_path)
        except ImportError as e:
            console.print(f"[red]Cannot import module: {e}[/red]")
            raise typer.Exit(1)
        graph = getattr(mod, graph_var, None)
        if graph is None:
            console.print(f"[red]'{graph_var}' not found in {mod_path}[/red]")
            raise typer.Exit(1)

        # Look for inject/cleanup functions in the module
        inject_fn = getattr(mod, "inject_document", None)
        cleanup_fn = getattr(mod, "clear_injections", None)

        adapter = LangGraphAdapter(
            graph=graph,
            inject_fn=inject_fn,
            cleanup_fn=cleanup_fn,
        )
    else:
        console.print("[yellow]YAML config loading not yet implemented. Use --module.[/yellow]")
        raise typer.Exit(1)

    # --- Load dataset ---
    dataset_path = Path("datasets/prompts/")
    if not dataset_path.exists():
        console.print(f"[red]Dataset path not found: {dataset_path}[/red]")
        raise typer.Exit(1)

    prompts = _load_prompts_from_dir(dataset_path)
    if not prompts:
        console.print("[yellow]No prompts found in dataset.[/yellow]")
        raise typer.Exit(1)

    # Filter by category
    if category:
        try:
            cat_enum = AttackCategory(category)
            prompts = [p for p in prompts if p.category == cat_enum]
        except ValueError:
            console.print(f"[red]Unknown category: {category}[/red]")
            raise typer.Exit(1)

    # Filter by severity
    prompts = [p for p in prompts if p.severity >= severity_min]

    # Quick mode: top 50 by severity desc
    if quick:
        prompts = sorted(prompts, key=lambda p: -p.severity)[:50]

    console.print(f"Loaded [bold]{len(prompts)}[/bold] prompts")
    console.print(f"Grading mode: [bold]{grading_mode}[/bold]\n")

    # --- Run scan ---
    runner = ScanRunner(
        adapter=adapter,
        dataset=prompts,
        grading_mode=grading_mode,
        concurrency=3,
        timeout=30,
    )

    scan_result = asyncio.run(runner.run())

    # --- Save results ---
    from redteam.reporting.json_reporter import save_scan_result
    result_file = save_scan_result(scan_result, output)

    # --- Save pending reviews ---
    runner.save_pending_reviews(output)
    pending_count = len(runner.pending_reviews)

    # --- Print terminal report ---
    from redteam.reporting.terminal_report import print_scan_report
    print_scan_report(
        scan_result,
        pending_count=pending_count,
        output_path=result_file,
    )


@app.command()
def report(
    input: str = typer.Option(..., help="Path to scan result JSON"),
    format: str = typer.Option("html", help="Output format: json | html"),
) -> None:
    """Generate report from scan results."""
    console.print("[yellow]Report generation not implemented yet.[/yellow]")


@app.command()
def validate(
    input: str = typer.Option("datasets/prompts/", help="Path to prompts directory"),
) -> None:
    """Validate prompt quality and report stats."""
    from redteam.generators.quality import QualityPipeline

    input_path = Path(input)
    if not input_path.exists():
        console.print(f"[red]Path not found: {input_path}[/red]")
        raise typer.Exit(1)

    prompts = _load_prompts_from_dir(input_path)
    if not prompts:
        console.print("[yellow]No prompts found.[/yellow]")
        raise typer.Exit()

    pipeline = QualityPipeline()
    processed, stats = pipeline.run(prompts, existing=[])

    console.print(f"\n[bold cyan]Quality Pipeline Results[/bold cyan]\n")

    table = Table(title="Summary")
    table.add_column("Metric", style="bold")
    table.add_column("Count", justify="right")
    table.add_row("Total input", str(stats.total_input))
    table.add_row("Duplicates found", str(stats.duplicates_found))
    table.add_row("Validation failures", str(stats.validation_failures))
    table.add_row("[green]Passed[/green]", f"[green]{stats.passed}[/green]")
    console.print(table)

    if stats.failure_reasons:
        console.print("\n[bold]Failure reasons:[/bold]")
        for reason, count in sorted(
            stats.failure_reasons.items(), key=lambda x: -x[1]
        ):
            console.print(f"  {reason}: {count}")

    console.print()


@app.command()
def push(
    results: str = typer.Option(..., help="Path to scan result JSON"),
    endpoint: str = typer.Option(
        "http://localhost:8000/api/v1/redteam/ingest",
        help="AuditLens ingest endpoint",
    ),
) -> None:
    """Push results to AuditLens."""
    console.print("[yellow]Push to AuditLens not implemented yet.[/yellow]")


@app.command(name="grade-review")
def grade_review(
    input: str = typer.Option(..., help="Path to pending-review.json"),
) -> None:
    """Display pending review findings for Claude Code grading."""
    from rich.panel import Panel

    input_path = Path(input)
    if not input_path.exists():
        console.print(f"[red]File not found: {input_path}[/red]")
        raise typer.Exit(1)

    data = json.loads(input_path.read_text())
    if not data:
        console.print("[green]No pending reviews.[/green]")
        raise typer.Exit()

    console.print(f"\n[bold cyan]Pending Reviews ({len(data)} findings)[/bold cyan]\n")

    for i, item in enumerate(data, 1):
        rubric = item.get("grading_rubric", {})
        tool_calls = item.get("tool_calls", [])
        tool_str = ""
        if tool_calls:
            tool_lines = []
            for tc in tool_calls:
                name = tc.get("tool_name", tc.get("tool", "?"))
                args = tc.get("arguments", tc.get("args", {}))
                tool_lines.append(f"  {name}({json.dumps(args)})")
            tool_str = "\n[bold]Tool calls:[/bold]\n" + "\n".join(tool_lines)

        content = (
            f"[bold]Prompt:[/bold] {item.get('prompt_id', '?')}\n"
            f"[bold]Description:[/bold] {item.get('prompt_description', '?')}\n"
            f"\n[bold]Agent response:[/bold]\n{item.get('agent_response', '(empty)')}\n"
            f"{tool_str}\n"
            f"\n[bold]Rule grader said:[/bold] {item.get('rule_reasoning', '?')}\n"
            f"\n[bold]Grading rubric:[/bold]\n"
            f"  PASS: {rubric.get('pass_criteria', '?')}\n"
            f"  PARTIAL_FAIL: {rubric.get('partial_fail_criteria', '?')}\n"
            f"  FAIL: {rubric.get('fail_criteria', '?')}\n"
            f"  CRITICAL_FAIL: {rubric.get('critical_fail_criteria', '?')}"
        )
        console.print(Panel(content, title=f"Review {i}/{len(data)}", border_style="yellow"))

    console.print(
        "\n[dim]To grade these findings, copy the rubric + response into a "
        "Claude Code session and assign PASS/PARTIAL_FAIL/FAIL/CRITICAL_FAIL.[/dim]\n"
    )


@app.command()
def info() -> None:
    """Show dataset and engine info."""
    console.print("[yellow]Info command not implemented yet.[/yellow]")


if __name__ == "__main__":
    app()
