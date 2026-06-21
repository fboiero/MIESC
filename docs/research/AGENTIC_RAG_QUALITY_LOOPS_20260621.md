# Agentic + RAG Quality Loops — Design (2026-06-21)

How to raise the weak metrics (Paper 1 precision 22.1%; Paper 2 standalone
compile 64% / vuln-elimination 66%) and detect hallucinations / false positives,
by **orchestrating the components MIESC already has** into agentic loops, and by
**enriching the RAG** (including with negative/benign examples). Additive design:
nothing here changes the frozen Paper 1/2 baselines until deliberately re-run.

## 1. The problem, precisely

| Metric | Now | Failure mode it reflects |
|--------|-----|--------------------------|
| P1 precision | 22.1% | too many false positives (informational + over-eager LLM findings) |
| P1 LLM findings | single-run | LLM hallucination (finding not grounded in the code) |
| P2 standalone compile | 64% | patch breaks compilation (undefined symbols) |
| P2 vuln-elimination | 66% | re-scan is a weak oracle (circularity threat) |

A **false positive** = a real, deterministic detector output that is *not a true
vulnerability in context* (e.g., `block.timestamp` inside a `require`-only timelock).
A **hallucination** = an LLM-asserted finding that is *not grounded in the code at
all* (cites a line/function/pattern that isn't there). Different defects, different
detectors — but both attack precision.

## 2. Building blocks that already exist (use, don't reinvent)

| Component | File | What it gives us |
|-----------|------|------------------|
| `EmbeddingRAG` / `VulnerabilityDocument` | `src/llm/embedding_rag.py` | source-weighted semantic retrieval over a vuln knowledge base (ChromaDB + all-MiniLM-L6-v2); `source_tier` weighting |
| `HallucinationDetector` | `src/security/hallucination_detector.py` | per-finding grounding: cross-validate vs static, `_check_location_match`, `_verify_code_pattern`, `_detect_anomalies`, status + adjusted confidence |
| `FalsePositiveFilter` | `src/ml/fp_filter.py` | RAG-validated FP filtering, per-detector FP rates, context/version/library patterns, FP probability |
| `DeepAuditAgent` | `src/agents/deep_audit_agent.py` | agentic multi-LLM consensus (+0.20 agree / −0.30 joint-reject / −0.10 disagree) |
| `vuln_verifier_adapter`, `audit_consensus_adapter` | `src/adapters/` | verifier + consensus roles |

The pieces exist but run mostly **independently and single-pass**. The win is
composing them into **closed loops with an oracle**.

## 3. The four agentic loops

### Loop A — Adversarial FP refutation (→ P1 precision)
For each candidate finding:
1. RAG-retrieve the matching vuln pattern **and** any matching *benign* pattern (§4).
2. Spawn N independent skeptics, each with a distinct **lens**: (i) code-grounding,
   (ii) exploitability, (iii) mitigation-present, (iv) benign-context. Each is
   prompted to **refute** (default to "false positive" under uncertainty).
3. Drop the finding only on **majority refutation** → conservative, so recall is
   protected while precision rises.
This generalizes the existing 2-model consensus to an N-lens panel. *Hypothesis:
precision 22% → 40–55% with ≤1pp recall loss, because the dropped items are the
informational/over-eager class, not the true positives.*

### Loop B — Hallucination grounding gate (→ trustworthy LLM findings)
A finding passes only if it clears grounding checks (all already partly in
`HallucinationDetector`):
- **Location grounding**: cited line/function exists (`_check_location_match`).
- **Pattern grounding**: the vuln pattern is actually present (`_verify_code_pattern`
  + RAG pattern similarity).
- **Reproduction grounding**: generate the exploit test (`miesc test-gen`); if the
  test **cannot trigger** the vuln, the finding is a hallucination/FP. *(This is the
  bidirectional loop Paper 2 already describes — promote it from prose to an oracle.)*
- **Cross-model grounding**: a second independent model must agree.
Fail ≥2 → flag `hallucinated`, drop or route to manual review.

### Loop C — Compile self-repair (→ P2 compile 64%↑) [remediation lane / Codex]
generate patch → compile → on failure, feed the **compiler error + RAG fix-template**
back to the model → regenerate (bounded retries). The current patcher is single-shot;
a 2–3 step repair loop should close most of the 42 undefined-symbol failures.
*Owner: remediation lane — design only here.*

### Loop D — Exploit-test elimination oracle (→ P2 vuln-elimination rigor)
Replace the re-scan elimination criterion with the **generated exploit test** as
oracle: patch → run test → if the drain still succeeds, the fix is incomplete → loop.
Directly answers Paper 2's re-scan-circularity threat-to-validity.

## 4. RAG enrichment — the precision lever

Every loop above is only as good as its grounding context. Today the KB is 93
vulnerability docs. Two enrichment moves:

### 4.1 More authoritative sources (higher `source_tier` weight)
- **Primary/standards** (highest weight): full SWC Registry, OWASP SC Top-10 (2025),
  Solidity "security considerations", Trail of Bits *building-secure-contracts*,
  Consensys best-practices.
- **Incident post-mortems** (medium): rekt.news, BlockSec/SlowMist analyses,
  Code4rena/Sherlock reports — ground "is this pattern *real*" with concrete cases.
- **Fix templates** (high): OpenZeppelin canonical mitigations — ground both
  remediation and the "is a mitigation already present?" FP check.

### 4.2 Negative / benign patterns — the key insight
Standard RAG KBs store only **vulnerable** examples, so the model never learns what
*looks vulnerable but is safe*. We add a **benign-pattern corpus**: "this matches
pattern X but is safe **because** Y" (reentrancy-guarded, CEI-ordered,
`onlyOwner`-protected, Solidity ≥0.8 arithmetic, `block.timestamp` in a timelock
`require`, OZ `SafeERC20`). At verification time, if a finding's code matches a
benign pattern more strongly than the vulnerable one, it is a likely FP.

This is the single highest-leverage RAG change for **precision**, and it is purely
**additive** — a separate corpus (`data/rag/benign_patterns_seed_*.jsonl`), opt-in,
so the frozen Paper-1 KB version is untouched until a deliberate re-baseline.

## 5. How the loops separate hallucination from false positive

| Signal | Hallucination | False positive |
|--------|:-------------:|:--------------:|
| Cited location exists in code | ✗ often | ✓ |
| Vuln pattern present in code | ✗ | ✓ (but benign in context) |
| Matches a **benign** RAG pattern | — | ✓ strong |
| Exploit test triggers the vuln | ✗ | ✗ |
| Second model agrees | ✗ | mixed |

Hallucinations fail *grounding*; false positives are *grounded but benign*. The
harness records which, so the fix differs (drop hallucination; downgrade FP with the
benign-pattern citation as the reason).

## 5b. Coverage diagnostic against the real 569 false positives

The canonical SmartBugs run (`paper1_smartbugs_eval_layers_1_6_7.jsonl`) records FPs
per contract at the **category** level (not per-finding with locations), so a rigorous
per-finding precision measurement needs a richer findings dump (re-run with location
output) — that is future work, not claimed here. What the category data *does* let us
do honestly is target the benign corpus. The 569 real FPs distribute as:

| FPs | Category | Benign corpus |
|----:|----------|---------------|
| 128 | arithmetic | covered (Sol ≥0.8) |
| 77 | reentrancy | covered (guard / CEI) |
| 76 | access_control | covered (onlyOwner) |
| 64 | unchecked_low_level_calls | covered (SafeERC20 / checked) |
| 47 | bad_randomness | covered (non-entropy block var) |
| 46 | time_manipulation | covered (timelock) |
| 46 | denial_of_service | covered (bounded loop) |
| 43 | front_running | **added** (commit-reveal / no order-dependence) |
| 42 | short_addresses | **added** (deprecated on Sol ≥0.5) |

After adding the front-running and short-address benign patterns, the corpus covers
**all 9 FP-producing categories**. This is a *coverage* statement (the lever can reach
every category), NOT a precision-lift claim — the lift must be measured per-finding.

## 6. Build plan + honest measurement

1. **Seed the benign-pattern corpus** (additive data file) — done in this change.
2. **Prototype harness** wiring RAG + `HallucinationDetector` + adversarial verifier
   (pluggable LLM; rule-based fallback so it runs offline) — done in this change
   (`scripts/agentic_quality_loop.py`).
3. **Measure on a held-out slice** (NOT the frozen corpus) with a pluggable LLM, then
   report precision/recall deltas as a *new dated artifact* — only fold into a paper
   when a deliberate re-baseline is opened (changing the RAG KB bumps the version the
   Paper-1 profile pins).
4. **Compile self-repair (Loop C)** + **exploit-test oracle (Loop D)** → remediation
   lane (Codex), after fix_eval finalizes.

> Reproducibility guardrail: the canonical KB version
> (`...source-review-v4`) and the frozen Paper 1/2 numbers MUST NOT change silently.
> The benign corpus and the harness are opt-in; metric gains are reported as new
> dated artifacts and only promoted into a paper under an explicit baseline.
