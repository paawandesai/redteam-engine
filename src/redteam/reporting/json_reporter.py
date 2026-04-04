"""JSON reporter for scan results."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from redteam.models.results import ScanResult


def save_scan_result(scan_result: ScanResult, output_dir: str) -> str:
    """Save ScanResult as JSON file. Return the file path.

    Filename format: scan-{date}-{scan_id[:8]}.json
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    filename = f"{scan_result.scan_id}.json"

    result_file = output_path / filename
    result_file.write_text(scan_result.model_dump_json(indent=2) + "\n")
    return str(result_file)
