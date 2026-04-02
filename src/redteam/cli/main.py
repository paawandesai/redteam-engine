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
    config: str = typer.Option("", help="Path to target config YAML"),
    module: str = typer.Option("", help="Python module:graph for direct invocation"),
    grading_mode: str = typer.Option("batch-review", help="Grading mode: batch-review | llm | rule-only"),
    quick: bool = typer.Option(False, help="Quick scan with reduced prompt set"),
) -> None:
    """Run adversarial scan against target."""
    console.print("[yellow]Scan engine not implemented yet.[/yellow]")


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


@app.command()
def info() -> None:
    """Show dataset and engine info."""
    console.print("[yellow]Info command not implemented yet.[/yellow]")


if __name__ == "__main__":
    app()
