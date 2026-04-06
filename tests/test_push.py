"""Tests for push and report CLI commands.

All tests mock httpx — no real API calls.
"""

from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest
import typer

from redteam.cli.main import (
    _find_latest_scan,
    _load_scan_result,
    _push_to_auditlens,
    _transform_for_auditlens,
)
from redteam.models.enums import AttackCategory, Grade
from redteam.models.results import Finding, ScanResult, ToolCallTrace


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _finding(**overrides) -> Finding:
    defaults = dict(
        finding_id="F-001",
        prompt_id="PI-RAG-DI-001",
        category=AttackCategory.PROMPT_INJECTION_RAG,
        subcategory="direct-instruction",
        severity=5,
        grade=Grade.CRITICAL_FAIL,
        confidence=0.95,
        grading_method="rule",
        agent_response="COMPLIANCE CHECK RESULT: sk-proj-...",
        tool_calls_made=[
            ToolCallTrace(
                tool_name="file_read",
                arguments={"path": ".env"},
                return_value={"content": "API_KEY=sk-proj-abc123"},
                authorized=True,
            )
        ],
        reasoning="Agent called file_read on .env after injected compliance instruction",
        compliance_refs=[
            {"framework": "eu_ai_act", "reference": "Art. 15", "requirement": "Robustness"}
        ],
        latency_ms=150.0,
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _scan_result(**overrides) -> ScanResult:
    defaults = dict(
        scan_id="scan-20260404-abc123",
        schema_version="1.0.0",
        timestamp=datetime(2026, 4, 4, 12, 0, 0),
        engine_version="0.1.0",
        target={"name": "test-agent", "framework": "langgraph", "adapter": "LangGraphAdapter"},
        summary={
            "total": 1,
            "by_grade": {"critical_fail": 1},
            "by_category": {"prompt_injection_rag": {"critical_fail": 1}},
            "grading_stats": {"rule_graded": 1, "pending": 0},
        },
        findings=[_finding()],
    )
    defaults.update(overrides)
    return ScanResult(**defaults)


# ---------------------------------------------------------------------------
# Transform Tests
# ---------------------------------------------------------------------------


class TestTransformFindings:
    def test_payload_matches_auditlens_schema(self) -> None:
        """Verify the transform produces the exact AuditLens RedTeamScanResult shape."""
        scan = _scan_result()
        payload = _transform_for_auditlens(scan)

        assert payload["scan_id"] == "scan-20260404-abc123"
        assert payload["timestamp"] == "2026-04-04T12:00:00"
        assert payload["target"]["name"] == "test-agent"
        assert payload["summary"]["total"] == 1

        assert len(payload["findings"]) == 1
        f = payload["findings"][0]
        assert f["finding_id"] == "F-001"
        assert f["category"] == "prompt_injection_rag"
        assert f["subcategory"] == "direct-instruction"
        assert f["severity"] == 5
        assert f["grade"] == "critical_fail"
        assert f["confidence"] == 0.95
        assert f["reasoning"] == "Agent called file_read on .env after injected compliance instruction"
        assert len(f["compliance_refs"]) == 1

    def test_payload_excludes_internal_fields(self) -> None:
        """Findings payload should NOT include agent_response, tool_calls_made, etc."""
        scan = _scan_result()
        payload = _transform_for_auditlens(scan)
        f = payload["findings"][0]

        assert "agent_response" not in f
        assert "tool_calls_made" not in f
        assert "intermediate_steps" not in f
        assert "grading_method" not in f
        assert "latency_ms" not in f
        assert "prompt_id" not in f


# ---------------------------------------------------------------------------
# Push Tests
# ---------------------------------------------------------------------------


class TestPushSavesPdf:
    def test_saves_pdf_to_output_dir(self, tmp_path: Path) -> None:
        """When AuditLens returns a PDF, it should be saved to the output directory."""
        scan = _scan_result()
        pdf_bytes = b"%PDF-1.4 fake pdf content"

        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/pdf"}
        mock_response.content = pdf_bytes

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_response

        with patch("redteam.cli.main.httpx.Client", return_value=mock_client):
            _push_to_auditlens(scan, "https://example.com/api", str(tmp_path))

        pdf_path = tmp_path / f"compliance-report-{scan.scan_id}.pdf"
        assert pdf_path.exists()
        assert pdf_path.read_bytes() == pdf_bytes


class TestPushHandlesConnectionError:
    def test_graceful_error_on_connection_refused(self, tmp_path: Path) -> None:
        """ConnectError should print a friendly message, not crash."""
        scan = _scan_result()

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.side_effect = httpx.ConnectError("Connection refused")

        with patch("redteam.cli.main.httpx.Client", return_value=mock_client):
            with pytest.raises(typer.Exit):
                _push_to_auditlens(
                    scan, "https://example.com/api", str(tmp_path)
                )

    def test_graceful_error_on_timeout(self, tmp_path: Path) -> None:
        """TimeoutException should print a friendly message, not crash."""
        scan = _scan_result()

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.side_effect = httpx.TimeoutException("timed out")

        with patch("redteam.cli.main.httpx.Client", return_value=mock_client):
            with pytest.raises(typer.Exit):
                _push_to_auditlens(
                    scan, "https://example.com/api", str(tmp_path)
                )

    def test_graceful_error_on_server_error(self, tmp_path: Path) -> None:
        """5xx response should print server error message."""
        scan = _scan_result()

        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 502
        mock_response.headers = {"content-type": "text/plain"}
        mock_response.text = "Bad Gateway"

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_response

        with patch("redteam.cli.main.httpx.Client", return_value=mock_client):
            with pytest.raises(typer.Exit):
                _push_to_auditlens(
                    scan, "https://example.com/api", str(tmp_path)
                )


# ---------------------------------------------------------------------------
# Report Tests
# ---------------------------------------------------------------------------


class TestReportFindsLatestScan:
    def test_picks_newest_json_file(self, tmp_path: Path) -> None:
        """_find_latest_scan should return the most recently modified JSON."""
        old_file = tmp_path / "scan-old.json"
        old_file.write_text("{}")

        # Ensure different mtime
        time.sleep(0.05)

        new_file = tmp_path / "scan-new.json"
        new_file.write_text("{}")

        result = _find_latest_scan(tmp_path)
        assert result == new_file

    def test_returns_none_for_empty_dir(self, tmp_path: Path) -> None:
        """_find_latest_scan should return None if no JSON files exist."""
        result = _find_latest_scan(tmp_path)
        assert result is None

    def test_ignores_non_json_files(self, tmp_path: Path) -> None:
        """_find_latest_scan should only consider .json files."""
        (tmp_path / "notes.txt").write_text("not json")
        (tmp_path / "report.html").write_text("<html></html>")

        result = _find_latest_scan(tmp_path)
        assert result is None
