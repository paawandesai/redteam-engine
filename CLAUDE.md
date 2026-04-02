# CLAUDE.md — Red Team Engine

## What This Project Is

An adversarial penetration testing engine for AI agents. It runs a curated dataset of adversarial prompts against LangGraph and OpenAI Agents SDK targets, grades the agent's responses, and produces structured reports with EU AI Act compliance mapping.

This is one half of a two-repo product. This repo produces scan results. AuditLens (separate repo) consumes them for compliance reporting and GRC export.

## Architecture

```
redteam-engine/
├── src/redteam/
│   ├── models/              — Pydantic v2 data models (source of truth for all schemas)
│   │   ├── prompts.py       — AdversarialPrompt, GradingRubric, AttackCategory
│   │   ├── results.py       — Finding, ToolCallTrace, ScanResult
│   │   └── enums.py         — AttackCategory, Grade enums
│   ├── cli/                 — Typer CLI interface
│   │   └── main.py          — Commands: generate, scan, report, validate, push, info
│   ├── generators/          — Prompt quality pipeline (generation via Claude Code, not API)
│   │   ├── synthetic.py     — OPTIONAL: API-based generation (for future automation only)
│   │   ├── quality.py       — Deduplication + validation (runs locally, no API calls)
│   │   └── templates/       — Reference templates for Claude Code generation sessions
│   ├── engine/              — Core scanning engine
│   │   ├── runner.py        — Test execution loop with async concurrency
│   │   ├── grader.py        — Two-tier grading: rule-based (always) + LLM (three modes)
│   │   └── adapters/        — Framework-specific agent adapters
│   │       ├── base.py      — AgentAdapter protocol + AgentResponse model
│   │       ├── langgraph_adapter.py   — Primary: LangGraph via astream_events
│   │       ├── openai_agents_adapter.py — Secondary: OpenAI Agents SDK
│   │       └── api_adapter.py         — Generic HTTP API adapter
│   ├── reporting/           — Output generation
│   │   ├── json_reporter.py
│   │   ├── html_reporter.py — Single-file HTML with inline SVG charts
│   │   └── compliance_mapper.py — Maps findings to EU AI Act / NIST / ISO
│   ├── monitor/             — Layer 3: continuous monitoring (later)
│   └── storage/
│       └── sqlite_store.py  — Scan history persistence
├── datasets/
│   ├── schema/              — Exported JSON schemas (data contract with AuditLens)
│   │   ├── prompt.schema.json
│   │   └── result.schema.json
│   └── prompts/             — The adversarial dataset
│       ├── prompt-injection-rag/
│       │   ├── direct-instruction.json
│       │   ├── context-manipulation.json
│       │   ├── metadata-injection.json
│       │   └── multi-hop.json
│       ├── tool-misuse/
│       ├── cross-agent-injection/
│       └── memory-poisoning/
├── data/
│   └── compliance/          — Compliance mapping tables
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
5. REPORT:    ScanResult → JSON + HTML + compliance mapping
6. PUSH:      POST ScanResult JSON to AuditLens /api/v1/redteam/ingest
```

## Tech Stack

- **Language:** Python 3.11+
- **Package Manager:** uv
- **CLI:** Typer with rich console output
- **Models:** Pydantic v2 (strict — all schemas enforced, unlike convention-only approaches)
- **LLM Client:** anthropic SDK (OPTIONAL — only for automated grading/generation. Build phase uses Claude Code directly instead.)
- **Agent Frameworks:** langgraph 0.2.x (primary target), openai-agents-sdk (secondary)
- **Storage:** SQLite (scan history)
- **Reporting:** Jinja2 (HTML), JSON
- **Testing:** pytest + pytest-asyncio

## Key Design Decisions

### Grading: Two-Tier System with Three Modes
- **Tier 1 — RuleGrader:** Pattern matching for high-confidence cases. Checks vulnerability indicators, unauthorized tool calls, topic drift. If confidence > 0.85, this is the final grade. Runs locally, no API calls.
- **Tier 2 — LLM grading for ambiguous cases.** Three modes:
  - `batch-review` (DEFAULT, build phase): Saves pending cases to results/pending-review.json. Grade them in a Claude Code session — uses your Max subscription, zero API costs.
  - `llm` (automation, later): Calls Claude Sonnet via Anthropic API in-process. Costs API credits. Use for automated monitoring/CI pipelines.
  - `rule-only`: Skip LLM grading entirely. Fast, free, lower accuracy on ambiguous cases.
- Target: Rule grader handles >50% of cases. Remaining graded via Claude Code during build, API later.
- CLI flag: `redteam scan --grading-mode batch-review` (default) | `llm` | `rule-only`

### Generation: Claude Code First, API Optional
- **Primary (build phase):** Prompts are generated directly by Claude Code writing to dataset JSON files. This uses your Max subscription, not API credits. Templates in generators/templates/ serve as reference material for Claude Code sessions.
- **Optional (automation):** synthetic.py calls Anthropic API for automated regeneration. Build it as optional infrastructure for later, not the primary workflow.
- Quality pipeline (dedup + validation) always runs locally with no API calls.

### Adapters: Non-Invasive Observation
- Adapters observe agent execution externally via LangGraph's `astream_events` API. They do NOT modify the target agent's behavior.
- Exception: For RAG injection attacks, malicious documents are injected into the document store BEFORE execution (setup-time intervention). Cleaned up after.
- All adapters implement the same AgentAdapter protocol so the runner doesn't care which framework.

### Quality Pipeline: Generate → Deduplicate → Validate → Filter
- Deduplication across 4 dimensions: category + subcategory + attack mechanism + semantic equivalence
- Embedding similarity (cosine > 0.85) as fast pre-filter, then LLM pairwise comparison
- Expected ~30% attrition from raw generation to final dataset
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
| cross-agent-injection | Poisoned inter-agent messages, role hijacking, delegation abuse | 3-5 |
| memory-poisoning | Persistent state corruption, history injection, context overflow | 2-5 |

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
redteam scan --config configs/examples/langgraph-rag-agent.yaml
redteam scan --module tests.fixtures.mock_agents.vulnerable_rag_agent:graph --quick
redteam scan --grading-mode batch-review   # DEFAULT: rule grader + save pending for Claude Code
redteam scan --grading-mode llm            # Full automation: rule grader + API-based LLM grading
redteam scan --grading-mode rule-only      # Fastest: rule grader only, skip ambiguous cases

# Grade review (after batch-review scan, grade pending cases via Claude Code)
redteam grade-review --input results/pending-review.json  # Shows what needs grading

# Reporting
redteam report --input results/scan-2026-04-15.json --format html

# Push to AuditLens
redteam push --results results/scan-2026-04-15.json --endpoint http://localhost:8000/api/v1/redteam/ingest

# Info
redteam info
```

## Environment Setup

- **ANTHROPIC_API_KEY:** Do NOT set globally in shell profile. Only set in this project's .env file and load via python-dotenv. If set globally, Claude Code will use API credits instead of your Max subscription.
- **OPENAI_API_KEY:** Only needed when testing OpenAI Agents SDK targets. Set in .env.
- **.env is gitignored.** Never commit API keys.

## DO NOT

- Do not set ANTHROPIC_API_KEY as a global environment variable — it will drain API credits instead of using your Claude Max plan for Claude Code sessions
- Do not use LangChain legacy chains — use LangGraph for all agent interactions
- Do not build a web UI — CLI + HTML reports only
- Do not build authentication or multi-tenancy
- Do not import or reference any proprietary code from external sources
- Do not build CI/CD integration (GitHub Actions) — that's Systima Comply's lane
- Do not over-engineer attack_steps — keep it simple like {action, params} dicts
- Do not call the Anthropic API for generation or grading during the build phase — use Claude Code sessions instead (Max subscription, zero API cost)
