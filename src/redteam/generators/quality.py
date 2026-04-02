"""Quality pipeline for adversarial prompts: dedup + validation.

Runs entirely locally with no API calls. Uses TF-IDF cosine similarity
for deduplication and rule-based checks for validation.
"""

import math
import re
from collections import Counter
from dataclasses import dataclass

from redteam.models.enums import AttackCategory
from redteam.models.prompts import AdversarialPrompt

# Expected severity ranges per category (from CLAUDE.md)
CATEGORY_SEVERITY_RANGES: dict[AttackCategory, tuple[int, int]] = {
    AttackCategory.PROMPT_INJECTION_RAG: (3, 5),
    AttackCategory.TOOL_MISUSE: (2, 5),
    AttackCategory.CROSS_AGENT_INJECTION: (3, 5),
    AttackCategory.MEMORY_POISONING: (2, 5),
}

# ID prefix conventions per category
CATEGORY_ID_PREFIXES: dict[AttackCategory, str] = {
    AttackCategory.PROMPT_INJECTION_RAG: "PI-RAG",
    AttackCategory.TOOL_MISUSE: "TM",
    AttackCategory.CROSS_AGENT_INJECTION: "CAI",
    AttackCategory.MEMORY_POISONING: "MP",
}

DEDUP_THRESHOLD = 0.85


@dataclass(frozen=True)
class QualityStats:
    total_input: int
    duplicates_found: int
    validation_failures: int
    passed: int
    failure_reasons: dict[str, int]


def _tokenize(text: str) -> list[str]:
    """Simple whitespace + punctuation tokenizer, lowercased."""
    return re.findall(r"[a-z0-9]+", text.lower())


def _build_tfidf_vector(
    tokens: list[str], idf: dict[str, float]
) -> dict[str, float]:
    tf = Counter(tokens)
    total = len(tokens) if tokens else 1
    return {
        term: (count / total) * idf.get(term, 0.0)
        for term, count in tf.items()
    }


def _cosine_similarity(
    vec_a: dict[str, float], vec_b: dict[str, float]
) -> float:
    common_keys = set(vec_a) & set(vec_b)
    if not common_keys:
        return 0.0
    dot = sum(vec_a[k] * vec_b[k] for k in common_keys)
    mag_a = math.sqrt(sum(v * v for v in vec_a.values()))
    mag_b = math.sqrt(sum(v * v for v in vec_b.values()))
    if mag_a == 0.0 or mag_b == 0.0:
        return 0.0
    return dot / (mag_a * mag_b)


def _compute_idf(doc_tokens: list[list[str]]) -> dict[str, float]:
    n_docs = len(doc_tokens)
    if n_docs == 0:
        return {}
    doc_freq: Counter[str] = Counter()
    for tokens in doc_tokens:
        doc_freq.update(set(tokens))
    return {
        term: math.log((1 + n_docs) / (1 + df)) + 1
        for term, df in doc_freq.items()
    }


class QualityPipeline:
    """Local quality pipeline: deduplication + validation. No API calls."""

    def __init__(self, dedup_threshold: float = DEDUP_THRESHOLD) -> None:
        self.dedup_threshold = dedup_threshold

    def deduplicate(
        self,
        prompts: list[AdversarialPrompt],
        existing: list[AdversarialPrompt],
    ) -> list[AdversarialPrompt]:
        """Mark duplicates using TF-IDF cosine similarity on descriptions.

        Compares each prompt in `prompts` against all others and against
        `existing`. Threshold: 0.85. Marks duplicate='yes_excluded' on
        duplicates, 'yes_canonical' on the kept version.
        """
        all_prompts = list(existing) + list(prompts)
        texts = [p.description + " " + p.attack_detail for p in all_prompts]
        doc_tokens = [_tokenize(t) for t in texts]
        idf = _compute_idf(doc_tokens)
        vectors = [_build_tfidf_vector(t, idf) for t in doc_tokens]

        n_existing = len(existing)
        excluded_indices: set[int] = set()

        # Compare new prompts against existing
        for i in range(n_existing, len(all_prompts)):
            if i in excluded_indices:
                continue
            for j in range(i):
                if j in excluded_indices:
                    continue
                sim = _cosine_similarity(vectors[i], vectors[j])
                if sim >= self.dedup_threshold:
                    excluded_indices.add(i)
                    break

        # Compare new prompts against each other
        for i in range(n_existing, len(all_prompts)):
            if i in excluded_indices:
                continue
            for j in range(i + 1, len(all_prompts)):
                if j in excluded_indices:
                    continue
                sim = _cosine_similarity(vectors[i], vectors[j])
                if sim >= self.dedup_threshold:
                    excluded_indices.add(j)

        results: list[AdversarialPrompt] = []
        canonical_indices: set[int] = set()

        # Find which prompts are canonical (had a duplicate marked against them)
        for i in excluded_indices:
            for j in range(len(all_prompts)):
                if j == i or j in excluded_indices:
                    continue
                sim = _cosine_similarity(vectors[i], vectors[j])
                if sim >= self.dedup_threshold:
                    canonical_indices.add(j)
                    break

        for idx in range(n_existing, len(all_prompts)):
            prompt = all_prompts[idx]
            if idx in excluded_indices:
                results.append(
                    prompt.model_copy(
                        update={"duplicate": "yes_excluded", "is_included": False}
                    )
                )
            elif idx in canonical_indices:
                results.append(
                    prompt.model_copy(update={"duplicate": "yes_canonical"})
                )
            else:
                results.append(prompt)

        return results

    def validate(
        self, prompts: list[AdversarialPrompt]
    ) -> list[AdversarialPrompt]:
        """Quality checks (all local, no API):

        1. grading_rubric has all 4 levels defined and they differ
        2. severity is in expected range for the category
        3. attack_steps is non-empty
        4. description is at least 50 characters
        5. vulnerability_indicators is non-empty
        6. id follows naming convention (e.g. PI-RAG-DI-001)
        """
        results: list[AdversarialPrompt] = []
        for prompt in prompts:
            flags = list(prompt.quality_flags)

            # 1. Rubric completeness
            rubric = prompt.grading_rubric
            rubric_values = [
                rubric.pass_criteria,
                rubric.partial_fail_criteria,
                rubric.fail_criteria,
                rubric.critical_fail_criteria,
            ]
            if any(not v.strip() for v in rubric_values):
                flags.append("empty_rubric_level")
            elif len(set(rubric_values)) < 4:
                flags.append("duplicate_rubric_levels")

            # 2. Severity range
            expected = CATEGORY_SEVERITY_RANGES.get(prompt.category)
            if expected:
                lo, hi = expected
                if not (lo <= prompt.severity <= hi):
                    flags.append(
                        f"severity_out_of_range(expected={lo}-{hi},got={prompt.severity})"
                    )

            # 3. Attack steps
            if not prompt.attack_steps:
                flags.append("empty_attack_steps")

            # 4. Description length
            if len(prompt.description) < 50:
                flags.append("description_too_short")

            # 5. Vulnerability indicators
            if not prompt.vulnerability_indicators:
                flags.append("empty_vulnerability_indicators")

            # 6. ID convention
            prefix = CATEGORY_ID_PREFIXES.get(prompt.category, "")
            if prefix and not prompt.id.startswith(prefix):
                flags.append(f"id_prefix_mismatch(expected={prefix})")

            new_flags = [f for f in flags if f not in prompt.quality_flags]
            if new_flags:
                results.append(
                    prompt.model_copy(
                        update={
                            "quality_flags": flags,
                            "is_included": False,
                        }
                    )
                )
            else:
                results.append(prompt)

        return results

    def run(
        self,
        prompts: list[AdversarialPrompt],
        existing: list[AdversarialPrompt],
    ) -> tuple[list[AdversarialPrompt], QualityStats]:
        """Run full pipeline: deduplicate then validate.

        Returns (processed_prompts, stats).
        """
        total_input = len(prompts)

        deduped = self.deduplicate(prompts, existing)
        duplicates_found = sum(
            1 for p in deduped if p.duplicate == "yes_excluded"
        )

        validated = self.validate(deduped)
        validation_failures = sum(
            1
            for p in validated
            if p.quality_flags and p.duplicate != "yes_excluded"
        )

        passed = sum(1 for p in validated if p.is_included)

        failure_reasons: dict[str, int] = {}
        for p in validated:
            for flag in p.quality_flags:
                failure_reasons[flag] = failure_reasons.get(flag, 0) + 1

        stats = QualityStats(
            total_input=total_input,
            duplicates_found=duplicates_found,
            validation_failures=validation_failures,
            passed=passed,
            failure_reasons=dict(failure_reasons),
        )

        return validated, stats
