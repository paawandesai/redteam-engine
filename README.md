# redteam-engine

**Adversarial security testing for AI agents.** It runs RAG prompt-injection, tool-misuse and multi-turn social-engineering attacks against LangGraph agents, then grades what the agent actually *did*: which tools it called, with which arguments.

This is the attack half of a two-repo system. Its companion, [AuditLens](https://github.com/paawandesai/auditlens), turns these findings into an EU AI Act assessment and PDF report:

```
redteam scan ──► findings (JSON) ──► redteam push ──► AuditLens ──► EU AI Act articles ──► audit PDF
                                                     tool misuse → Art. 14 (human oversight)
                                                     RAG injection → Art. 9 (risk management)
```

## Key finding

We tested 10 multi-turn social-engineering chains against four LLMs driving a customer-support agent that has **no authorization gates**. **Six chains succeed on every model.**

| Model | Chains completed |
|---|---:|
| GPT-4o | 9/10 |
| Claude Sonnet 4 | 8/10 |
| GPT-4o-mini | 7/10 |
| Claude Haiku 4.5 | 6/10 |

One of the six is a three-message account takeover: look up the account's email, change it to an attacker address, send a password reset to the new address. It completes on all four models, with no identity check at any step. The model does what the user asks, and nothing in the agent's architecture stops it.

**Scope of this result.** The target (`tests/fixtures/mock_agents/production_support_agent.py`) is our own test agent, deliberately built without authorization gates. Each chain ran once per model at temperature 0. The result shows that model alignment alone doesn't stop these chains. It is not a measurement of any vendor's production system. Details and verbatim transcripts: [FINDINGS.md](FINDINGS.md) and `results/multi-turn-verification/`.

### What does stop it

A structural gate at the tool boundary. We compared a vulnerable RAG agent with a hardened one (path-validated `file_read`) on 71 RAG-injection prompts:

| | Vulnerable | Hardened |
|---|---:|---:|
| Exploited | 14/71 | 6/71 |

Every file-exfiltration attempt against the hardened agent was stopped at the gate. The six that still succeed are output manipulation (bad advice in plain text, with no tool call to block). The rule grader scores the hardened run as 10/71 because it counts four blocked `file_read` attempts as exploits. [FINDINGS.md](FINDINGS.md#what-does-fix-it-partially) explains this.

### How much to trust this

[ENTERPRISE_VALIDATION.md](ENTERPRISE_VALIDATION.md) is a **self-conducted** methodology audit by the project author. It checks the work against OWASP, Gravitee 2026, published papers, and the project's own scan artifacts. Its verdict is **PARTIALLY VALID**:

- The threat model, taxonomy mapping and core findings hold up.
- The structural-defense thesis holds only in narrowed form, for the file-exfiltration class.
- The scope caveats are listed in §7.

## Scan your own agent

```bash
git clone https://github.com/paawandesai/redteam-engine
cd redteam-engine
uv sync --extra langgraph --extra dev

PYTHONPATH=. uv run redteam scan \
  --module your_agent:graph \
  --quick --grading-mode rule-only
```

The runner reads the agent's tools and skips prompts that target tools it doesn't have. Setup: [docs/scanning-your-agent.md](docs/scanning-your-agent.md).

## What gets tested

| Category | Subcategory | Prompts | Needs RAG? |
|---|---|---:|:---:|
| Tool misuse | Conversational escalation (multi-turn) | 10 | No |
| | Identity spoofing | 8 | No |
| | Scope violation | 8 | No |
| | System disclosure | 8 | No |
| | Argument injection (SQL, path traversal, command injection via tool args) | 8 | No |
| Prompt injection via RAG | Direct instruction in retrieved documents | 53 | Yes |
| | Output manipulation | 8 | Yes |
| | Indirect injection via user-submitted artifacts | 5 | Yes |
| | Tool-chain exfiltration | 5 | Yes |
| **Total** | | **113** | |

## Project status

Everything marked *planned* is absent from the codebase.

| Area | Status |
|---|---|
| Attack corpus: prompt injection via RAG and tool misuse (113 prompts, 9 subcategories) | Implemented |
| Attack corpus: cross-agent injection, memory poisoning | Planned. Dataset directories are empty, though the enum values and article mappings exist. |
| LangGraph adapter (auto-detects tools) | Implemented |
| OpenAI Agents SDK adapter, generic HTTP API adapter | Planned |
| Rule grader, batch-review queue, multi-turn runner, chain detection | Implemented |
| In-process LLM grading (`--grading-mode llm`) | Planned (raises `NotImplementedError`) |
| JSON and rich terminal reporting | Implemented |
| HTML report | Planned. The compliance PDF comes from [AuditLens](#pairs-with-auditlens). |
| EU AI Act references on every finding | Implemented (inlined in `src/redteam/engine/runner.py`) |
| OWASP LLM / MITRE ATLAS / CWE references | On prompts (`benchmark_refs`) only, not yet copied onto findings |
| Standalone compliance mapper (EU AI Act / NIST AI RMF / ISO 42001 tables) | Planned |
| SQLite scan history (`storage/`), continuous monitoring (`monitor/`) | Planned (empty packages) |

## Architecture

- **Adapter pattern.** Framework-agnostic `AgentAdapter` Protocol (`src/redteam/engine/adapters/base.py`). LangGraph is the only adapter today.
- **Grading.** A rule grader covers indicators, unauthorized tool calls and topic drift. In `batch-review` mode, ambiguous cases and every severity ≥4 case go to a review queue. The published benchmarks used `rule-only`.
- **Multi-turn runner.** It keeps conversation state across turns for social-engineering chains.
- **Chain detection.** Five patterns are detected across the full multi-turn tool-call sequence: account takeover, data exfiltration, bulk data exposure, bulk modification, and mass unauthorized email.
- **Capability-based filtering.** The runner reads the adapter's reported tools and skips prompts that target missing tools.
- **Compliance references.** Every finding carries EU AI Act article references. They were checked against the regulation text in [COMPLIANCE_VERIFICATION.md](COMPLIANCE_VERIFICATION.md).

| Category | EU AI Act references on each finding |
|---|---|
| Prompt injection via RAG | Article 9(2)(a), Article 15(5) |
| Tool misuse | Article 14(4)(d), Article 9(7) |
| Cross-agent injection *(mapping only, no prompts yet)* | Article 15(5), Article 9(2)(b) |
| Memory poisoning *(mapping only, no prompts yet)* | Article 12(1), Article 15(4) |

## Pairs with AuditLens

[AuditLens](https://github.com/paawandesai/auditlens) ingests a scan and maps each finding to its primary EU AI Act article. Tool misuse goes to Art. 14 (human oversight) and RAG injection to Art. 9 (risk management). AuditLens returns a scored assessment as JSON, or a PDF with an adversarial-testing section.

```bash
# Run AuditLens locally (see its README), then:
uv run redteam push results/cross-model-v2/gpt4o/scan-20260427-182339.json \
  --endpoint http://localhost:8000/api/v1/redteam/ingest/pdf
# → compliance-report-<scan_id>.pdf
#   Art. 14 FAIL (11 tool-misuse failures), Art. 9 FAIL (5 RAG-injection failures)

# or push straight after a terminal report:
uv run redteam report results/<scan>.json --compliance
```

Without `--endpoint`, results go to the hosted AuditLens instance (`auditlens-9hox.onrender.com`).

## Running tests

```bash
uv sync --extra langgraph --extra dev
uv run pytest -m "not requires_api"   # 54 tests, mock agents, no API keys
uv run pytest                         # all 58; 4 live tests need OPENAI_API_KEY + ANTHROPIC_API_KEY (skipped otherwise)
```

## Reproducing the headline results

These scripts call the OpenAI and Anthropic APIs. Set `OPENAI_API_KEY` and `ANTHROPIC_API_KEY`, and expect real API spend.

```bash
# Four-model multi-turn benchmark
for m in gpt4o-mini gpt4o sonnet haiku; do
  MODEL=$m PYTHONPATH=. uv run python scripts/run_multi_turn_verification.py
done
uv run python scripts/build_multi_turn_matrix.py

# Vulnerable vs. hardened comparison
PYTHONPATH=. uv run redteam scan \
  --module tests.fixtures.mock_agents.vulnerable_rag_agent:graph \
  --grading-mode rule-only --category prompt_injection_rag --output results/v/
PYTHONPATH=. uv run redteam scan \
  --module tests.fixtures.mock_agents.hardened_rag_agent:graph \
  --grading-mode rule-only --category prompt_injection_rag --output results/h/
```

## Contributing

1. Fork the repo and create a feature branch.
2. Write prompts using the templates in `src/redteam/generators/templates/`.
3. Validate them with `uv run redteam validate --input datasets/prompts/`.
4. Run `uv run pytest`, then open a PR.

## License

MIT. See [LICENSE](LICENSE).
