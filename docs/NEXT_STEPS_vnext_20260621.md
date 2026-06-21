# MIESC v-next — Next Steps Checklist (2026-06-21)

Consolidated action list after the v-next session. Everything below is the remaining
work; all autonomous/safe work is already integrated to `main`.

## Already shipped to `main` (done)
- Detection: SmartBugs recall 0.972 → **0.993** (deterministic; 5/6 prior misses closed).
- Quality: coverage 87% → **89%** (6391 tests green); 3 real bugs fixed (RAG ImportError,
  format_instruction, result_aggregator silent-drop).
- Harness: reports external-tool crash counts per run (reproducibility).
- Security: 6/8 MED backlog items verified-fixed; Ollama exposure (MED-004) fixed; backlog
  corrected.
- Adoption: `miesc doctor` shows per-tool install commands for missing tools.
- Docs hygiene: ROADMAP/CHANGELOG/CONTRIBUTING fixed, docs/ decluttered, 5.x release notes,
  tool count standardized to 50, numbers aligned to 99.3% in non-frozen docs.

## ACTION — Fernando

### 1. Finalize Paper 1 baseline (content is ready on branch `paper1-vnext-baseline-draft`)
The branch has the full v-next content: `miesc-paper.tex` (9 edits), `paper1_claims_matrix.json`,
and `README.md` — all consistent at 99.3%. To finalize:
```bash
cd <repo>
git checkout paper1-vnext-baseline-draft
pdflatex -output-directory=paper paper/miesc-paper.tex   # x2-3 for refs/cite
m=.paper-freeze-local/PAPER_REPRODUCIBILITY_FREEZE.sha256
awk '{print $2}' "$m" | xargs shasum -a 256 > "$m.new" && mv "$m.new" "$m"   # PDF FIRST, then this
sh .paper-freeze-local/validate_paper_reproducibility_freeze.sh
git tag -a paper-reproducibility-baseline-2026-06-21 -m "Paper 1 v-next: recall 99.3%"
git checkout main && git merge --no-ff paper1-vnext-baseline-draft
git -c pack.threads=1 -c pack.windowMemory=32m -c pack.packSizeLimit=64m push origin main --tags
```

### 2. DPGA review
Numbers are now consistent (DPG-COMPLIANCE = 99.3%). 9 indicators self-assessed Compliant.
Advance the DPGA review / respond to any reviewer observations.

### 3. Decisions still open
- Tool count: standardized on **50** (verified in LAYERS); confirm this is the intended
  marketing number (alternative was the paper's 35 "analysis modules").
- Optional: embed `demo/miesc-demo.cast` (asciinema) in the README for a live demo.

## ACTION — Codex (Paper 2 / remediation lane)
Per `paper/paper2_vnext_evidence_20260621.md` + `..._finalization_template_20260621.md`:
1. Restore patcher self-contained: compile rate regressed to **28%** (33/119) vs frozen
   64%. Recover ≥64%, target higher.
2. Add independent verification (Slither/SMTChecker/Foundry on patched-that-compile) to
   remove the re-scan circularity.
3. Re-run `fix_eval` full → finalize Paper 2 baseline (template has the exact .tex spots).

## Known remaining (low-tractability, documented)
- MED-003 (curl-to-shell hash): rustup/foundry installers are rolling; TLS-mitigated.
- MED-005 (base-image digest pin): tag-pinned; digest pin adds maintenance burden.
- Tool-crash variance (aderyn/slither on legacy AST): external; harness now reports counts.
