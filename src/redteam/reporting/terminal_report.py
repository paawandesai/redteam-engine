"""Rich terminal report for scan results.

Prints a polished, color-coded summary of scan findings
with category breakdowns, top critical findings, remediation
guidance, and EU AI Act compliance references.
"""

from __future__ import annotations

import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from redteam.models.results import ScanResult

console = Console()

REMEDIATION_MAP: dict[str, str] = {
    "prompt_injection_rag": (
        "Add tool input validation and authorization gates between "
        "LLM decisions and tool execution"
    ),
    "tool_misuse": (
        "Implement least-privilege tool access and argument sanitization"
    ),
    "cross_agent_injection": (
        "Validate inter-agent messages and enforce sender authentication"
    ),
    "memory_poisoning": (
        "Add memory lifecycle management and context validation"
    ),
}

GRADE_STYLES: dict[str, str] = {
    "critical_fail": "bold red",
    "fail": "red",
    "partial_fail": "yellow",
    "pass": "green",
    "pending_review": "dim",
}


def print_scan_report(
    scan_result: ScanResult,
    pending_count: int = 0,
    output_path: str = "",
) -> None:
    """Print a polished terminal report for a completed scan."""
    summary = scan_result.summary
    findings = scan_result.findings

    # ── 1. HEADER ──────────────────────────────────────────────
    target = scan_result.target
    total_latency_ms = sum(f.latency_ms for f in findings)
    duration_s = total_latency_ms / 1000 if findings else 0

    header_lines = [
        f"[bold cyan]Target:[/bold cyan] {target.get('name', target.get('adapter', 'unknown'))}",
        f"[bold cyan]Framework:[/bold cyan] {target.get('framework', target.get('adapter', '-'))}",
        f"[bold cyan]Engine:[/bold cyan] v{scan_result.engine_version}",
        f"[bold cyan]Prompts:[/bold cyan] {summary.get('total', 0)}",
        f"[bold cyan]Duration:[/bold cyan] {duration_s:.1f}s",
    ]
    console.print(Panel(
        "\n".join(header_lines),
        title="[bold]Red Team Scan Report[/bold]",
        border_style="cyan",
    ))

    # ── 2. SUMMARY BADGES ─────────────────────────────────────
    by_grade = summary.get("by_grade", {})
    badge_line = Text()
    badge_order = ["critical_fail", "fail", "partial_fail", "pass"]
    badge_labels = {
        "critical_fail": "CRITICAL",
        "fail": "FAILED",
        "partial_fail": "PARTIAL",
        "pass": "PASSED",
    }
    for grade in badge_order:
        count = by_grade.get(grade, 0)
        if count > 0:
            style = GRADE_STYLES.get(grade, "white")
            label = badge_labels.get(grade, grade.upper())
            badge_line.append(f" {count} {label} ", style=style)
            badge_line.append("  ")

    console.print()
    console.print(badge_line)
    console.print()

    # ── 3. CATEGORY BREAKDOWN TABLE ───────────────────────────
    by_category = summary.get("by_category", {})
    if by_category:
        table = Table(title="Category Breakdown", show_lines=False)
        table.add_column("Category", style="bold", min_width=25)
        table.add_column("Tests", justify="right")
        table.add_column("Pass", justify="right", style="green")
        table.add_column("Fail", justify="right", style="red")
        table.add_column("Critical", justify="right", style="bold red")
        table.add_column("Rate", justify="right")

        for cat, grades in sorted(by_category.items()):
            total = sum(grades.values())
            passed = grades.get("pass", 0)
            failed = grades.get("fail", 0)
            critical = grades.get("critical_fail", 0)
            rate = (passed / total * 100) if total > 0 else 0

            if rate >= 80:
                rate_str = f"[green]{rate:.0f}%[/green]"
            elif rate >= 50:
                rate_str = f"[yellow]{rate:.0f}%[/yellow]"
            else:
                rate_str = f"[red]{rate:.0f}%[/red]"

            cat_display = cat.replace("_", "-")
            table.add_row(
                cat_display, str(total), str(passed),
                str(failed), str(critical), rate_str,
            )

        console.print(table)
        console.print()

    # ── 4. TOP CRITICAL FINDINGS (up to 5) ────────────────────
    critical_findings = sorted(
        [f for f in findings if f.grade.value in ("critical_fail", "fail")],
        key=lambda f: -f.severity,
    )[:5]

    if critical_findings:
        console.print("[bold red]Top Critical Findings[/bold red]\n")
        for i, finding in enumerate(critical_findings, 1):
            severity_badge = f"[bold red]SEV-{finding.severity}[/bold red]"
            grade_style = GRADE_STYLES.get(finding.grade.value, "white")
            grade_text = f"[{grade_style}]{finding.grade.value.upper()}[/{grade_style}]"

            console.print(
                f"  {i}. {severity_badge} {grade_text} "
                f"[bold]{finding.prompt_id}[/bold]"
            )

            # Tool calls
            non_retrieval_calls = [
                tc for tc in finding.tool_calls_made
                if tc.tool_name not in ("retrieve_documents", "search_documents")
            ]
            if non_retrieval_calls:
                for tc in non_retrieval_calls:
                    args_str = json.dumps(
                        {k: v for k, v in tc.arguments.items()},
                        default=str,
                    )
                    if len(args_str) > 60:
                        args_str = args_str[:57] + "..."
                    console.print(
                        f"     Agent called [bold]{tc.tool_name}[/bold]({args_str})"
                    )

            # Truncated response
            if finding.agent_response:
                preview = finding.agent_response[:200]
                if len(finding.agent_response) > 200:
                    preview += "..."
                console.print(f"     [dim]{preview}[/dim]")

            # Compliance refs
            if finding.compliance_refs:
                refs = ", ".join(
                    f"{r.get('reference', '')} {r.get('requirement', '')}"
                    for r in finding.compliance_refs
                )
                console.print(f"     [cyan]EU AI Act: {refs}[/cyan]")

            console.print()

    # ── 5. REMEDIATION SUMMARY ────────────────────────────────
    failed_categories = set()
    for f in findings:
        if f.grade.value in ("critical_fail", "fail"):
            failed_categories.add(f.category.value)

    if failed_categories:
        console.print("[bold]Remediation Guidance[/bold]\n")
        for cat in sorted(failed_categories):
            fix = REMEDIATION_MAP.get(cat, "Review agent configuration")
            cat_display = cat.replace("_", "-")
            console.print(f"  [bold]{cat_display}:[/bold] {fix}")
        console.print()

    # ── 6. COMPLIANCE FOOTER ──────────────────────────────────
    console.print(Panel(
        "[bold]EU AI Act[/bold] enforcement: August 2, 2026\n"
        "Full compliance report: [dim]$ redteam report --format html --input <scan.json>[/dim]",
        border_style="blue",
    ))

    # ── 7. PENDING REVIEWS ────────────────────────────────────
    if pending_count > 0:
        console.print(
            f"\n[yellow]{pending_count} findings need manual review.[/yellow]\n"
            "Run: [bold]redteam grade-review --input results/pending-review.json[/bold]"
        )

    # ── 8. SAVE LOCATION ─────────────────────────────────────
    if output_path:
        console.print(f"\nScan saved to [bold]{output_path}[/bold]")

    console.print()
