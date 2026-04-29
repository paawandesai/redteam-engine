"""Pytest configuration: marker registration and API-key skip logic.

Tests that hit live LLM APIs should be marked `@pytest.mark.requires_api`.
When `OPENAI_API_KEY` (or `ANTHROPIC_API_KEY` if needed) is not set, those
tests are skipped automatically. Mock-only tests run unconditionally.
"""

from __future__ import annotations

import os

import pytest


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "requires_api: test invokes a real LLM API; skipped when no API key is set",
    )


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    has_openai = bool(os.environ.get("OPENAI_API_KEY"))
    has_anthropic = bool(os.environ.get("ANTHROPIC_API_KEY"))
    if has_openai and has_anthropic:
        return
    skip_reason = []
    if not has_openai:
        skip_reason.append("OPENAI_API_KEY")
    if not has_anthropic:
        skip_reason.append("ANTHROPIC_API_KEY")
    skip_marker = pytest.mark.skip(
        reason=f"requires {' and '.join(skip_reason)}"
    )
    for item in items:
        if "requires_api" in item.keywords:
            item.add_marker(skip_marker)
