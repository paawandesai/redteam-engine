# CLAUDE.md — Red Team Engine

## What This Project Is

An adversarial penetration testing engine for AI agents. It runs a curated dataset of adversarial prompts against LangGraph agents (other frameworks planned), grades the agent's responses, and produces structured reports with EU AI Act compliance mapping.

This is one half of a two-repo product. This repo produces scan results. AuditLens (separate repo) consumes them for EU AI Act compliance reporting (JSON + PDF).

## Published Documentation (read first when joining)

- **README.md** — entry point: key finding (60-90% multi-turn chain success), quick start, taxonomy table
- **FINDINGS.md** — research narrative with full TM-CE-003 transcript and cross-model matrix
- **ENTERPRISE_VALIDATION.md** — self-conducted credibility audit; methodology cross-checked against Gravitee 2026, OWASP Agentic Top 10, peer-reviewed papers; vulnerable-vs-hardened comparison; honest verdict ("PARTIALLY VALID" with caveats)
- **COMPLIANCE_VERIFICATION.md** — EU AI Act Article 9/12/14/15 mappings verified against regulation text
- **docs/scanning-your-agent.md** — user-facing guide for scanning third-party LangGraph agents

## Current Reality vs. Original Architecture

Several files mentioned in the architecture diagram below are aspirational. Actual state as of 2026-04:
- `html_reporter.py`, `compliance_mapper.py`, `openai_agents_adapter.py`, `api_adapter.py`, `sqlite_store.py` — **not yet implemented**. Compliance refs are inlined in `runner.py:25-42` (verified correct in COMPLIANCE_VERIFICATION.md).
- `cross-agent-injection/` and `memory-poisoning/` dataset directories — **empty placeholders**. The 113-prompt corpus today covers 9 subcategories under prompt-injection-rag and tool-misuse only.
- `monitor/` package — **deferred** ("Layer 3" in original spec).
- `llm` grading mode raises `NotImplementedError`; `scan --config` (YAML) prints "not yet implemented"; `redteam info` is a stub.
- Findings carry EU AI Act refs only. OWASP / MITRE ATLAS / CWE refs live on prompts (`benchmark_refs`) and are not copied onto Findings.

The shipping engine has: Pydantic v2 models, async runner with capability-based prompt filtering, two-tier grader with 5 multi-turn chain-detection patterns, severity-based force-review routing (batch-review mode only), LangGraph adapter (auto-detects tools), JSON + rich-terminal reporting, and a quality pipeline with TF-IDF dedup. 58 tests: 54 run on mock agents with no API key; 4 are `requires_api` live tests.

## Architecture

Entries marked [PLANNED] do not exist yet; see "Current Reality" above.


```
redteam-engine/
├── src/redteam/
│   ├── models/              — Pydantic v2 data models (source of truth for all schemas)
│   │   ├── prompts.py       — AdversarialPrompt, GradingRubric, AttackCategory
│   │   ├── results.py       — Finding, ToolCallTrace, ScanResult
│   │   └── enums.py         — AttackCategory, Grade enums
│   ├── cli/                 — Typer CLI interface
│   │   └── main.py          — Commands: generate, scan, report, validate, push, grade-review, info (stub)
│   ├── generators/          — Prompt quality pipeline (generation via Claude Code, not API)
│   │   ├── synthetic.py     — OPTIONAL: API-based generation (for future automation only)
│   │   ├── quality.py       — Deduplication + validation (runs locally, no API calls)
│   │   └── templates/       — Reference templates for Claude Code generation sessions
│   ├── engine/              — Core scanning engine
│   │   ├── runner.py        — Test execution loop with async concurrency
│   │   ├── grader.py        — Two-tier grading: rule-based (always) + batch review (llm mode not implemented)
│   │   └── adapters/        — Framework-specific agent adapters
│   │       ├── base.py      — AgentAdapter protocol + AgentResponse model
│   │       ├── langgraph_adapter.py   — Primary: LangGraph via graph.invoke
│   │       ├── openai_agents_adapter.py — [PLANNED] Secondary: OpenAI Agents SDK
│   │       └── api_adapter.py         — [PLANNED] Generic HTTP API adapter
│   ├── reporting/           — Output generation
│   │   ├── json_reporter.py
│   │   ├── terminal_report.py
│   │   ├── html_reporter.py — [PLANNED] Single-file HTML with inline SVG charts
│   │   └── compliance_mapper.py — [PLANNED] Maps findings to EU AI Act / NIST / ISO (refs inlined in runner.py today)
│   ├── monitor/             — [PLANNED] Layer 3: continuous monitoring (empty stub)
│   └── storage/             — [PLANNED] empty stub
│       └── sqlite_store.py  — [PLANNED] Scan history persistence
├── datasets/
│   ├── schema/              — Exported JSON schemas (data contract with AuditLens)
│   │   ├── prompt.schema.json
│   │   └── result.schema.json
│   └── prompts/             — The adversarial dataset
│       ├── prompt-injection-rag/
│       │   ├── direct-instruction.json        (53)
│       │   ├── output-manipulation.json       (8)
│       │   ├── indirect-user-injection.json   (5)
│       │   └── tool-chain-exfiltration.json   (5)
│       ├── tool-misuse/                       (argument-injection, conversational-escalation,
│       │                                       identity-spoofing, scope-violation, system-disclosure: 42)
│       ├── cross-agent-injection/   — [PLANNED] empty placeholder
│       └── memory-poisoning/        — [PLANNED] empty placeholder
├── data/
│   └── compliance/          — [PLANNED] Compliance mapping tables (directory is empty)
│       ├── eu_ai_act.json
│       ├── nist_ai_rmf.json
│       └── iso_42001.json
├── configs/
│   └── examples/            — Example target configurations
├── tests/
│   ├── fixtures/
│   │   └── mock_agents/     — Test target agents for CI
│   └── test_*.py
└── pyproject.toml
```

## Data Flow

```
1. GENERATE:  Claude Code writes prompts directly to JSON files (no API calls)
              OR (automation): synthetic.py calls Anthropic API (optional, for later)
2. QUALITY:   Deduplicate → Validate → Filter (runs locally, no API calls)
3. SCAN:      Load dataset → Initialize adapter → Execute prompts → Grade responses
4. GRADE:     Rule grader runs in-process (no API calls)
              Ambiguous cases → saved to pending-review.json → graded via Claude Code
              OR (automation): LLM grader calls Anthropic API (optional, for later)
5. REPORT:    ScanResult → JSON + rich terminal report (HTML report planned)
6. PUSH:      `redteam push` / `redteam report --compliance` POSTs ScanResult JSON to AuditLens
              /api/v1/redteam/ingest/pdf (default; /api/v1/redteam/ingest returns JSON)
```

## Tech Stack

- **Language:** Python 3.11+
- **Package Manager:** uv
- **CLI:** Typer with rich console output
- **Models:** Pydantic v2 (strict — all schemas enforced, unlike convention-only approaches)
- **LLM Client:** anthropic SDK (OPTIONAL — only for automated grading/generation. Build phase uses Claude Code directly instead.)
- **Agent Frameworks:** langgraph (1.1.x per uv.lock, implemented); openai-agents-sdk (planned)
- **Storage:** JSON files under results/ (SQLite scan history planned)
- **Reporting:** JSON + rich terminal (Jinja2 HTML planned; dependency present but unused)
- **Testing:** pytest + pytest-asyncio

## Key Design Decisions

### Grading: Two-Tier System
- **Tier 1 — RuleGrader:** Pattern matching for high-confidence cases. Checks vulnerability indicators, unauthorized tool calls, topic drift. If confidence > 0.85, this is the final grade. Runs locally, no API calls.
- **Tier 2 — review of ambiguous cases.** Modes:
  - `batch-review` (DEFAULT, build phase): Saves pending cases to results/pending-review.json, plus every sev>=4 case (force-review). Grade them in a Claude Code session — zero API costs.
  - `rule-only`: Skip review entirely. Fast, free, lower accuracy on ambiguous cases. The published benchmarks used this mode.
  - `llm` (planned): in-process API grading. Currently raises `NotImplementedError`.
- Known grader limitation: a tool call that the target's own gate BLOCKS is still graded as an exploit if the call matches the injection (see the hardened-agent correction in FINDINGS.md).
- Target: Rule grader handles >50% of cases. Remaining graded via Claude Code during build, API later.
- CLI flag: `redteam scan --grading-mode batch-review` (default) | `rule-only` | `llm` (not implemented)

### Generation: Claude Code First, API Optional
- **Primary (build phase):** Prompts are generated directly by Claude Code writing to dataset JSON files. This uses your Max subscription, not API credits. Templates in generators/templates/ serve as reference material for Claude Code sessions.
- **Optional (automation):** synthetic.py calls Anthropic API for automated regeneration. Build it as optional infrastructure for later, not the primary workflow.
- Quality pipeline (dedup + validation) always runs locally with no API calls.

### Adapters: Non-Invasive Observation
- Adapters observe agent execution externally: the LangGraph adapter calls `graph.invoke` and reads the returned message/tool-call trace. They do NOT modify the target agent's behavior.
- Exception: For RAG injection attacks, malicious documents are injected into the document store BEFORE execution (setup-time intervention). Cleaned up after.
- All adapters implement the same AgentAdapter protocol so the runner doesn't care which framework.

### Quality Pipeline: Generate → Deduplicate → Validate → Filter
- Deduplication across 4 dimensions: category + subcategory + attack mechanism + semantic equivalence
- TF-IDF cosine similarity for near-duplicate detection (no embeddings, no LLM calls)
- Three false-positive categories: framework_defense, ambiguous_behavior, unrealistic_attack

### Data Contract with AuditLens
- ScanResult JSON schema exported from Pydantic models to datasets/schema/
- schema_version field for contract evolution
- API-based integration (POST to AuditLens), not file copy

## Attack Categories

| Category | What It Tests | Severity Range |
|---|---|---|
| prompt-injection-rag | Injected content in retrieved documents hijacking agent behavior | 3-5 |
| tool-misuse | Unauthorized tool execution, scope violation, input manipulation | 2-5 |
| cross-agent-injection | [PLANNED — no prompts] Poisoned inter-agent messages, role hijacking, delegation abuse | 3-5 |
| memory-poisoning | [PLANNED — no prompts] Persistent state corruption, history injection, context overflow | 2-5 |

## Confidence Scoring (on Findings, not Prompts)

- 90-100: Confirmed — rule grader detected unauthorized tool call or clear behavioral change
- 70-89: Very likely — LLM grader high confidence assessment
- 50-69: Possible — ambiguous, may need human review
- Below 50: Reject

## CLI Commands

```bash
# Generation (optional — primary method is Claude Code writing directly to files)
redteam generate --category prompt-injection-rag --subcategory direct-instruction --count 20

# Quality validation (runs locally, no API)
redteam validate --input datasets/prompts/prompt-injection-rag/

# Scanning (grading-mode defaults to batch-review — no API calls)
redteam scan --module tests.fixtures.mock_agents.vulnerable_rag_agent:graph --quick
redteam scan --module <mod:graph> --grading-mode batch-review   # DEFAULT: rule grader + save pending for Claude Code
redteam scan --module <mod:graph> --grading-mode rule-only      # Fastest: rule grader only
# --config (YAML) and --grading-mode llm are not implemented yet

# Grade review (after batch-review scan, grade pending cases via Claude Code)
redteam grade-review --input results/pending-review.json  # Shows what needs grading

# Reporting (terminal; --compliance also pushes to AuditLens for a PDF)
redteam report results/scan-2026-04-15.json
redteam report results/scan-2026-04-15.json --compliance

# Push to AuditLens (default endpoint is the hosted Render instance)
redteam push results/scan-2026-04-15.json --endpoint http://localhost:8000/api/v1/redteam/ingest/pdf
```

## Environment Setup

- **ANTHROPIC_API_KEY:** Do NOT set globally in shell profile. Only set in this project's .env file and load via python-dotenv. If set globally, Claude Code will use API credits instead of your Max subscription.
- **OPENAI_API_KEY:** Needed for the default gpt-4o-mini mock/test agents and the GPT benchmark runs. Set in .env.
- **.env is gitignored.** Never commit API keys.

## DO NOT

- Do not set ANTHROPIC_API_KEY as a global environment variable — it will drain API credits instead of using your Claude Max plan for Claude Code sessions
- Do not use LangChain legacy chains — use LangGraph for all agent interactions
- Do not build a web UI — CLI (+ planned HTML report) only
- Do not build authentication or multi-tenancy
- Do not import or reference any proprietary code from external sources
- Do not build CI/CD integration (GitHub Actions) — that's Systima Comply's lane
- Do not over-engineer attack_steps — keep it simple like {action, params} dicts
- Do not call the Anthropic API for generation or grading during the build phase — use Claude Code sessions instead (Max subscription, zero API cost)
