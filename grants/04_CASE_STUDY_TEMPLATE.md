# Case Study Template — "We audited _____ with MIESC"

Use this template to publish a single, concrete pre-audit triage case
study. **One good case study beats three grant paragraphs** — it is the
most valuable social proof you can produce.

The goal: prove the README's promise ("one command replaces 4–8 hours
of manual tool orchestration") with a real contract, real numbers, and
honest trade-offs.

---

## Who to approach

Best targets, in order of fit:

1. **A DeFi protocol that's pre-mainnet** — they care about audit
   readiness but haven't paid for the full $50–200K audit yet. MIESC's
   triage fits their stage exactly.
2. **An academic DeFi research project** — NFT marketplaces, governance
   experiments, thesis-stage DeFi protocols. Low stakes + eager to
   publish.
3. **An OSS protocol with a history of audits** — run MIESC retroactively
   on a pre-audit version of their code and compare to the auditor's
   findings. Social proof: "MIESC would have found 8 of the 11
   issues ToB reported."
4. **A project that GOT exploited** — do a retroactive analysis of
   their pre-exploit code and show what MIESC would have surfaced.

**Argentine / LATAM angle**: a Buenos Aires / Mendoza / CABA DeFi
project, a UTN thesis, or an ESCUELA / IOU research project. Lower
approach barrier + regional story for the grants.

---

## Template (fill in)

### Executive summary

> **Contract**: [name + commit hash] ([link to GitHub])
> **Size**: [X] Solidity files, [Y] LOC
> **Context**: [what the contract does in 1 sentence]
> **MIESC run**: [command invocation] on [date]
> **Result**: [N] findings across [M] severity levels in [T] seconds
> **Validated manually**: [P] true positives, [F] false positives,
> [M] mitigated-but-worth-flagging
> **Time to triage with MIESC vs. manual tool orchestration**: [X min]
> vs. [Y hours]

### Why this contract

[2–3 sentences: why they needed security analysis, what stage they
were at, why they chose MIESC over paying for a full audit or running
tools individually]

### Running MIESC

```bash
pip install miesc
miesc audit full contracts/ -o results.json
miesc report results.json -t premium -f pdf --llm-interpret
```

Include:
- The exact contents of `results.json` (or a diffed summary)
- Screenshots or excerpts of the PDF report
- A specific finding, walked through: title → description → MIESC's
  attack_scenario → project's response (fixed / mitigated / accepted)

### What MIESC caught

A table of each finding, with:

| Severity | Title | MIESC finder (tool) | Project's verdict | Fixed in commit |
|---|---|---|---|---|
| Critical | Reentrancy in `claim()` | Slither + DeepAudit consensus | True positive | `abc123` |
| High | Unchecked return | Aderyn | True positive | `def456` |
| High | Access-control gap on `set*` | MIESC multi-LLM consensus | Needs manual review (disagreement) | Pending |
| Medium | Timestamp dependence | Slither | False positive (intentional) | — |

### What MIESC missed

Be honest. Include:
- Any issue the project's internal review / subsequent auditor found
  that MIESC didn't.
- Categories MIESC currently doesn't cover well (e.g., bespoke
  business-logic bugs, economic design flaws).
- The project's own note on where the triage didn't replace judgement.

### What the triage enabled

- Time-to-fix: how long did the project spend responding vs. how long
  would an external audit have taken
- Did MIESC unblock anything (e.g., mainnet deploy, upstream code
  review, investor due diligence)?
- Would the project use MIESC again? For what stage?

### Technical commentary

- Which MIESC layers contributed most value (Layer 1 static? Layer 5
  AI? formal verification via `miesc specs`?)
- Which layers were pure noise on this contract (document explicitly —
  tells future users how to configure)
- Hardware / runtime cost: X min wall-clock on Y-core MacBook, or
  Docker on EC2 c5.large. This matters for grant applications.

---

## Quote to harvest

Ask the project lead for one of these, in their own words:

> "MIESC replaced [N hours / $K of external tooling time] of manual
> triage. We would have missed [finding] without it, but we still
> needed [manual review / full audit] for [reason]."

A one-line quote is worth more than a page of prose.

---

## Publishing the case study

**Where**:
1. `docs/case_studies/<project_name>.md` in this repo
2. Blog post on Fernando's site (link from README)
3. Mirror on dev.to or Medium for SEO
4. Twitter/X thread + Farcaster
5. Quote in the paper's §Evaluation

**Licensing**: ensure the target project grants permission to publish,
in writing. Templates in `docs/case_studies/CONSENT_TEMPLATE.md`
(create when first case study is ready).

---

## Why this beats more code

MIESC's v5.1.8 release has 5,332 tests, 13 Cairo vuln types, multi-LLM
consensus, formal-verification bridge, and a 95.8% SmartBugs-curated recall
benchmark (81.8% on real-world exploits). The
bottleneck is **not engineering**. The bottleneck is evidence of use by
real teams.

One case study = one grant accepted. Two = funding path real. Three =
product-market fit proof.
