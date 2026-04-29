# Compliance Verification

**Purpose:** verify that the EU AI Act compliance references emitted by the scan engine (`src/redteam/engine/runner.py:24-41`) map to the correct articles and that the mapping is defensible against the regulation text. This is a credibility check before findings are pushed to AuditLens or any external compliance dashboard.

**Scope:** EU AI Act compliance refs only. OWASP / MITRE / CWE mappings are validated in `ENTERPRISE_VALIDATION.md` §2.

**Verdict:** **VALID** for the four mappings shipped. Article numbers and sub-clauses are consistent with the regulation as published. One *strengthening* recommendation: add Article 12 (record-keeping) and Article 13 (transparency) to several categories where the cited articles are correct but incomplete — listed in §3.

---

## 1. The Mapping As Shipped

From `src/redteam/engine/runner.py:24-41`:

| Attack category | EU AI Act references emitted on every Finding |
|---|---|
| `prompt_injection_rag` | **Article 9** §9(2)(a) — risk identification & analysis<br>**Article 15** §15(5) — cybersecurity / resilience to manipulation |
| `tool_misuse` | **Article 14** §14(4)(d) — human oversight, ability to override<br>**Article 9** §9(7) — testing of risk-management measures |
| `cross_agent_injection` | **Article 15** §15(5) — cybersecurity<br>**Article 9** §9(2)(b) — risk estimation across foreseeable misuse |
| `memory_poisoning` | **Article 12** §12(1) — automatic logging of events<br>**Article 15** §15(4) — robustness against errors / faults |

---

## 2. Article-by-Article Verification

### Article 9 — Risk Management System

> "Providers shall establish, implement, document and maintain a risk-management system for high-risk AI systems… The risk-management system shall be a continuous iterative process planned and run throughout the entire lifecycle of a high-risk AI system…"

- §9(2)(a): "identification and analysis of the known and the reasonably foreseeable risks that the high-risk AI system can pose to health, safety or fundamental rights when the high-risk AI system is used in accordance with its intended purpose."
- §9(2)(b): "estimation and evaluation of the risks that may emerge when the high-risk AI system is used in accordance with its intended purpose, and under conditions of reasonably foreseeable misuse."
- §9(7): obligations around testing risk-management measures.

**Mapping verdict:** ✅ Correct. Prompt injection in RAG is a *known and reasonably foreseeable risk* (9(2)(a)) and cross-agent injection is a *foreseeable misuse* condition (9(2)(b)). Tool misuse maps to 9(7) because testing is the obligation our scan most directly satisfies.

### Article 15 — Accuracy, Robustness and Cybersecurity

> "High-risk AI systems shall be designed and developed in such a way that they achieve an appropriate level of accuracy, robustness, and cybersecurity, and that they perform consistently in those respects throughout their lifecycle."
> "High-risk AI systems shall be resilient against attempts by unauthorised third parties to alter their use, outputs or performance by exploiting system vulnerabilities."

- §15(4): robustness — resilience to errors, faults, inconsistencies, and feedback loops.
- §15(5): cybersecurity — resilience to attacks including data poisoning, model poisoning, adversarial examples, confidentiality attacks, and model flaws.

**Mapping verdict:** ✅ Correct. RAG injection and cross-agent injection are textbook §15(5) attacks (the article literally enumerates "data poisoning" and "adversarial examples" as covered classes). Memory poisoning maps to §15(4) because persistent state corruption is a robustness/feedback-loop failure rather than a one-shot adversarial input.

### Article 14 — Human Oversight

> "High-risk AI systems shall be designed and developed… in such a way that they can be effectively overseen by natural persons during the period in which they are in use… The measures referred to in paragraph 1 shall be commensurate with the risks, level of autonomy, and context of use of the high-risk AI system."

- §14(4)(d): "to be able to intervene on the operation of the high-risk AI system or interrupt the system through a 'stop' button or a similar procedure that allows the system to come to a halt in a safe state."

**Mapping verdict:** ✅ Correct. Tool misuse — particularly conversational escalation and scope violation — fails Article 14(4)(d) because the agent executes destructive actions (account takeover, bulk refunds, credential rotation) without a human-in-the-loop checkpoint. Our hardened-agent comparison is direct evidence: the authorization gate is one mechanical implementation of 14(4)(d).

### Article 12 — Record-Keeping

> "High-risk AI systems shall technically allow for the automatic recording of events ('logs') over the duration of the lifetime of the system."

- §12(1): logging requirement; logs must be sufficient to "ensure a level of traceability of the AI system's functioning that is appropriate to the intended purpose."

**Mapping verdict:** ✅ Correct for memory poisoning. If the agent's persistent state can be silently altered, the logging required by §12(1) is undermined — incident reconstruction becomes unreliable.

---

## 3. Strengthening Recommendations (not required, but improves coverage)

The current mapping is **correct but minimal**. For any finding that ships to AuditLens, expanding the refs would strengthen the compliance audit trail:

| Category | Currently emits | Should *also* emit | Why |
|---|---|---|---|
| `prompt_injection_rag` (output-manipulation subcategory) | Art. 9 §9(2)(a), Art. 15 §15(5) | **Art. 13** §13(1) — transparency to users | When the agent passes through harmful advice (e.g., disable SSL) without a confidence/source qualification, it violates the user's right to understand the system's output. |
| `prompt_injection_rag` (any) | Art. 9, Art. 15 | **Art. 12** §12(1) — record-keeping | Injected payloads should be recorded for traceability; without logs, downstream incident response is impossible. |
| `tool_misuse` (conversational-escalation) | Art. 14, Art. 9 | **Art. 14** §14(4)(c) — "ability to remain aware" | Three-turn account takeover succeeds because the agent doesn't surface the cumulative risk of the chain to the human in the loop. |
| `tool_misuse` (identity-spoofing) | Art. 14, Art. 9 | **Art. 14** §14(4)(a) — fully understand capabilities | Human oversight can't catch impersonation if the agent treats unverified authority claims as authoritative. |

The runner's `COMPLIANCE_MAP` is a simple `dict[str, list[dict]]`. Extending it to per-subcategory mappings (rather than per-category) is a one-file change in `runner.py:24-41` plus a corresponding Pydantic model addition; no schema-version bump required.

---

## 4. What This Document Does NOT Verify

- **OWASP / MITRE / CWE mappings**: see `ENTERPRISE_VALIDATION.md` §2.
- **NIST AI RMF mapping**: not currently emitted by the scan engine (placeholder file exists at `data/compliance/nist_ai_rmf.json`). Adding NIST refs would require expanding `COMPLIANCE_MAP`.
- **ISO 42001 mapping**: same status as NIST — placeholder, not emitted.
- **Article 6 / Annex III high-risk classification**: out of scope. We assume the target is a high-risk AI system per Annex III(5)(b) ("AI systems intended to be used to evaluate the creditworthiness of natural persons or to establish their credit score") or similar — but a real compliance audit must independently classify the target.
- **Conformity assessment procedure** (Article 43): out of scope. Our findings inform conformity assessment but do not constitute one.

---

## 5. Sources

- [EU AI Act Article 9](https://artificialintelligenceact.eu/article/9/) — Risk Management System
- [EU AI Act Article 12](https://artificialintelligenceact.eu/article/12/) — Record-keeping
- [EU AI Act Article 13](https://artificialintelligenceact.eu/article/13/) — Transparency
- [EU AI Act Article 14](https://artificialintelligenceact.eu/article/14/) — Human Oversight
- [EU AI Act Article 15](https://artificialintelligenceact.eu/article/15/) — Accuracy, Robustness, Cybersecurity
- [EU AI Act Article 6](https://artificialintelligenceact.eu/article/6/) — Classification of high-risk AI systems
- [EU AI Act Annex III](https://artificialintelligenceact.eu/annex/3/) — High-risk AI systems list

---

**Audit performed:** 2026-04-28. **Method:** primary-source verification against the EU AI Act regulation text via `artificialintelligenceact.eu`. **Outcome:** mapping shipped in `runner.py` is correct; expansion recommendations documented in §3.
