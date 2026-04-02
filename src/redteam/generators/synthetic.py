"""Optional API-based prompt generation.

Primary generation method is Claude Code sessions writing directly to dataset
files (uses Max subscription, zero API cost). This module is scaffolding for
future CI/automation pipelines that need API-based generation.

Usage:
    redteam generate --use-api --category prompt-injection-rag --count 20
"""

from __future__ import annotations

from redteam.models.enums import AttackCategory
from redteam.models.prompts import AdversarialPrompt


class PromptGenerator:
    """API-based adversarial prompt generator.

    Calls the Anthropic API to generate adversarial prompts. Requires
    ANTHROPIC_API_KEY to be set. Costs API credits — prefer Claude Code
    sessions for manual generation.
    """

    def __init__(self, model: str = "claude-sonnet-4-20250514") -> None:
        self.model = model

    def generate(
        self,
        category: AttackCategory,
        subcategory: str = "",
        count: int = 20,
    ) -> list[AdversarialPrompt]:
        """Generate adversarial prompts via Anthropic API.

        Args:
            category: Attack category to generate prompts for.
            subcategory: Optional subcategory filter.
            count: Number of prompts to generate.

        Returns:
            List of generated AdversarialPrompt instances.

        Raises:
            NotImplementedError: This is scaffolding for future automation.
        """
        raise NotImplementedError(
            "API-based generation is not yet implemented. "
            "Use Claude Code sessions to generate prompts directly — "
            "see src/redteam/generators/templates/ for reference templates."
        )
