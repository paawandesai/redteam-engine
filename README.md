# redteam-engine

Adversarial security testing for AI agents. Finds vulnerabilities in LangGraph agents through multi-turn social engineering, RAG injection, and tool exploitation.

## Key Finding

We tested 10 multi-turn attack chains against 4 frontier LLMs. **6 attacks succeed on every model.**

| Model | Chains completed | Rate |
|---|---:|---:|
| GPT-4o | 9/10 | 90% |
| Sonnet 4 | 8/10 | 80% |
| GPT-4o-mini | 7/10 | 70% |
| Haiku 4.5 | 6/10 | 60% |

A 3-message account takeover (lookup → email change → password reset) completes on every model. No identity verification at any step — the agent does what the user asks.

Full findings: [FINDINGS.md](FINDINGS.md). Verbatim transcripts: `results/multi-turn-verification/`.

## Scan Your Own Agent

```bash
git clone https://github.com/paawandesai/redteam-engine
cd redteam-engine
uv sync --extra langgraph --extra dev

# Scan your agent
PYTHONPATH=. uv run redteam scan \
  --module your_agent:graph \
  --quick --grading-mode rule-only
```

The scanner auto-detects your agent's tools and loads only relevant attack prompts. See [docs/scanning-your-agent.md](docs/scanning-your-agent.md) for setup.

## What Gets Tested

| Category | Prompts | Needs RAG? | What it tests |
|---|---:|:---:|---|
| Conversational escalation | 10 | No | Multi-turn privilege escalation |
| Identity spoofing | 8 | No | Authority claims without verification |
| Scope violation | 8 | No | Acting outside stated purpose |
| System disclosure | 8 | No | Revealing internal configuration |
| Argument injection | 8 | No | SQL injection, path traversal, command injection via tools |
| RAG direct injection | 53 | Yes | Poisoned documents triggering unauthorized tool calls |
| Output manipulation | 8 | Yes | Harmful textual advice via injected content |
| Indirect injection | 5 | Yes | Attacks via user-submitted artifacts (tickets, reviews) |
| Tool chain exfiltration | 5 | Yes | Multi-tool attack chains via injection |
| **Total** | **113** | | |

## Architecture

- **Adapter pattern** — framework-agnostic; LangGraph today, extensible to other agent frameworks via the `AgentAdapter` Protocol (`src/redteam/engine/adapters/base.py`)
- **Two-tier grader** — rule-based detection + batch review for ambiguous cases; severity-based force-review keeps sev≥4 passes from being false negatives
- **Multi-turn runner** — maintains conversation state across turns for social-engineering chains
- **Chain detection** — five attack patterns (account takeover, data exfiltration, bulk modification, mass email, bulk data exposure) detected across the full multi-turn tool-call sequence
- **Capability-based prompt filtering** — runner inspects the adapter's reported tools and skips prompts that target tools the agent doesn't have
- **Compliance mapping** — every finding emits OWASP / MITRE ATLAS / CWE / EU AI Act references; mappings independently verified in [COMPLIANCE_VERIFICATION.md](COMPLIANCE_VERIFICATION.md)

## Verification

- [ENTERPRISE_VALIDATION.md](ENTERPRISE_VALIDATION.md) — methodology cross-checked against the Gravitee 2026 State of AI Agent Security Report, OWASP, peer-reviewed papers, and the project's own scan artifacts. Includes spot-checks of 6 graded findings and a vulnerable-vs-hardened comparison scan (14/71 → 10/71).
- [COMPLIANCE_VERIFICATION.md](COMPLIANCE_VERIFICATION.md) — EU AI Act Article 9 / 12 / 14 / 15 mappings verified against regulation text.

## Running Tests

```bash
# Mock-only tests (no API keys needed)
uv run pytest -v -m "not requires_api"

# Full suite including live agent tests (uses your OPENAI_API_KEY / ANTHROPIC_API_KEY)
uv run pytest -v
```

## Reproducing the Headline Results

```bash
# 4-model multi-turn benchmark (~5 min, ~$2 in API spend)
for m in gpt4o-mini gpt4o sonnet haiku; do
  MODEL=$m PYTHONPATH=. uv run python scripts/run_multi_turn_verification.py
done
uv run python scripts/build_multi_turn_matrix.py

# Vulnerable-vs-hardened structural-defense comparison (~10 min, ~$0.30)
PYTHONPATH=. uv run redteam scan \
  --module tests.fixtures.mock_agents.vulnerable_rag_agent:graph \
  --grading-mode rule-only --category prompt_injection_rag \
  --output results/v/
PYTHONPATH=. uv run redteam scan \
  --module tests.fixtures.mock_agents.hardened_rag_agent:graph \
  --grading-mode rule-only --category prompt_injection_rag \
  --output results/h/
```

## Compliance Mapping

| Category | EU AI Act articles emitted on every Finding |
|---|---|
| Prompt Injection via RAG | Article 9(2)(a), Article 15(5) |
| Tool Misuse | Article 14(4)(d), Article 9(7) |
| Cross-Agent Injection | Article 15(5), Article 9(2)(b) |
| Memory Poisoning | Article 12(1), Article 15(4) |

Every Finding also carries OWASP LLM Top 10, OWASP Agentic Top 10, MITRE ATLAS, and CWE refs. See [COMPLIANCE_VERIFICATION.md](COMPLIANCE_VERIFICATION.md) for verification against the regulation text.

## Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/new-attack-category`)
3. Write prompts using the templates in `src/redteam/generators/templates/`
4. Validate with `uv run redteam validate --input datasets/prompts/`
5. Run tests with `uv run pytest`
6. Open a PR

## License

MIT — see [LICENSE](LICENSE).
