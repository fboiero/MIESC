# MIESC 5.4.x Release Notes

Current line: **5.4.3** (2026-05-16). Full per-version detail in
[`../CHANGELOG.md`](../CHANGELOG.md); this is the user-facing summary of the 5.4 line.

## Highlights

### Research Evaluation Framework (5.4.0)
- **`miesc evaluate`** command group: `corpus` (precision/recall/F1/timing ground-truth
  eval), `ablation` (per-layer contribution), `compare` (statistical run comparison),
  `info` (dataset stats).
- Reproducible experiment config (`--config experiment.yaml`), JSONL export for ML
  pipelines, per-layer timing, auto-generated experiment cards (version/platform/seed/
  command), 80+ category-normalization aliases.
- Research Guide (`docs/guides/RESEARCH.md`) and a copy-paste CI workflow for automated
  benchmark evaluation.

### Remediation pipeline — Paper 2 (5.4.0)
- Expanded find→fix→verify documentation: before/after patch listings, Foundry exploit
  test generation, formal-verification (CHC) methodology, threats-to-validity, and
  compilation-rate analysis.

### Multi-chain analyzers (5.4.x)
- Cardano (Plutus / Aiken), Algorand (TEAL / PyTeal), and Stellar (Soroban) analyzers
  alongside EVM and Starknet/Cairo, routed by `miesc analyze`.

### Distribution & hardening (5.4.1–5.4.3)
- PyPI (`pip install miesc`) and multi-arch + full Docker images on GHCR.
- CI: MyPy gating, coverage threshold, benchmark-regression checks, weekly dependency
  scanning, Sigstore release signing, SBOM.
- Documentation: SUPPORT, GOVERNANCE, MAINTENANCE, ARCHITECTURE, COMMUNITY, mutation-
  testing and signed-commits guides.

## Benchmarks (current)
- SmartBugs-curated: **95.8% recall** (Paper 1 reproducible profile; a v-next baseline
  raising this to 99.3% with deterministic detectors is pending PDF/freeze finalization).
- EVMBench local high-severity extraction: **92.5% recall** (4-provider ensemble).
- 11 real DeFi exploits: **81.8% recall** (95% Wilson CI [52%, 95%]).

## Install / upgrade
```bash
pip install --upgrade miesc          # 5.4.3
# or Docker:
docker pull ghcr.io/fboiero/miesc:5.4.3
```

## Links
- Changelog: [`../CHANGELOG.md`](../CHANGELOG.md)
- Roadmap: [`ROADMAP.md`](ROADMAP.md)
- Reproducibility: [`../paper/PAPER1_REPRODUCIBILITY.md`](../paper/PAPER1_REPRODUCIBILITY.md)

> Release-notes discipline for the 5.x line was restored in 2026-06; earlier per-release
> notes (v4.x) are in [`archive/`](archive/).
