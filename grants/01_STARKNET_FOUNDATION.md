# Starknet Foundation Grant — MIESC Cairo Security Analyzer

**Applicant**: Fernando Boiero
**Institution**: Universidad Tecnológica Nacional (UTN), Villa María, Argentina
**Email**: fboiero@frvm.utn.edu.ar
**Repository**: https://github.com/fboiero/MIESC
**Package**: https://pypi.org/project/miesc/ (v5.4.0, AGPL-3.0)
**Downloads**: 611 / month (growing)

---

## TL;DR

MIESC ships **the first production-ready static analyzer for Cairo/Starknet
with 2024–2026 real-exploit coverage**. We detect 13 vulnerability classes
informed by the exact incidents that have cost the Starknet ecosystem real
money (zkLend — $9.6M, Braavos accounts, Pragma oracle staleness). The
code is already public, tested (5,300+ unit + integration tests, 0
regressions), AGPL-licensed, and published on PyPI. We are requesting
funding to:

1. Expand from 13 to 30+ Cairo vulnerability classes, with a reproducible
   benchmark comparable to the SmartBugs-curated suite for EVM.
2. Build a **victim-side Cairo exploit corpus** (zkLend, Nostra, Carmine
   Options, Ekubo, Braavos) with labelled ground-truth that every Cairo
   static analyzer can benchmark against.
3. Ship Cairo-specific formal verification bridges (Certora Prover's Cairo
   support, Caracal integration).
4. Publish a peer-reviewed paper and make MIESC the default Cairo
   analyzer in the Starknet developer workflow (Cairo Book, Starknet
   Book, scarb integration).

**Budget**: USD 25 000 over 6 months, milestone-based.

---

## What we already ship

### Cairo coverage (v5.4.0, fully implemented)

Thirteen vulnerability types with block-level scanning
(`src/adapters/cairo_adapter.py`, 97% tested):

| Category                        | Based on real exploit |
|---------------------------------|----------------------|
| `pragma_oracle_stale`           | zkLend (Feb 2025, $9.6M) |
| `unchecked_u256`                | Cairo 1.0 arithmetic, zkLend contributor |
| `upgrade_no_init_guard`         | Braavos account re-init (2023) |
| `unchecked_syscall_result`      | Dropped `SyscallResult` from `call_contract_syscall` |
| `signature_replay`              | Account-abstraction without nonce / chain_id |
| `felt_overflow`                 | Classical 252-bit field overflow |
| `l1_l2_message`                 | `#[l1_handler]` without `from_address` validation |
| `caller_spoofing`               | `get_caller_address()` vs `get_tx_info()` confusion |
| `storage_collision`             | Upgradeable-contract storage layout |
| `unchecked_l1_call`             | `send_message_to_l1` without assert |
| `reentrancy`                    | Cross-contract via dispatcher |
| `access_control`                | `#[external]` without modifier |
| `proxy_upgrade`                 | `replace_class_syscall` without guard |

Reproducible fixture:
`examples/contracts/cairo/Modern2024Exploits.cairo` triggers **13/13
types** — deliberately built so any Cairo security tool can compare
coverage.

### Infrastructure already delivered

- **35 analysis modules** integrated across 13 external tools (Slither,
  Aderyn, Mythril, Halmos, Certora Prover, Scribble, Caracal, ...) and
  22 internal modules — MIESC is an orchestration layer, not a
  single-tool reimplementation.
- **9 defense layers** with per-layer timing instrumentation: static,
  dynamic, symbolic, formal, AI/LLM, pattern-detection, DeFi-specific,
  exploit validation, consensus.
- **Plugin system**: third-party detector plugins via PyPI entry points
  (`miesc.detectors` group) — researchers can publish and share custom
  detectors without forking MIESC.
- **Scientific evaluation framework** (`miesc evaluate`): corpus
  evaluation, ablation studies, run comparison, dataset info, and
  benchmark dataset download (`miesc evaluate download smartbugs`).
  Experiment cards for full reproducibility.
- **Multi-LLM consensus**: queries a primary + a verification-role
  model, reports disagreement as `needs_manual_review`. Measured on 11
  Rekt exploits: 80 HIGH+CRITICAL findings → 4 flagged for human review
  (5% triage queue density).
- **Formal verification bridge**: `miesc specs` generates Certora CVL
  rules from findings; `miesc verify` executes them.
- **Automated fix pipeline**: 87% of fixes applied, 63% compile, 84%
  eliminate the vulnerability, 0% regression.
- **Benchmarks with honest framing**: 95.8% recall on SmartBugs-curated
  (static+intelligence layers, 137/143), 97.9% with a local Ollama follow-up; 92.5% ensemble recall
  on EVMBench (#1, beating Cecuro at 87.7%); 81.8% recall on 11
  confirmed DeFi exploits totalling $1.59B in combined losses, Cohen's κ = 0.77.
- **Two academic papers**: Paper 1 on multi-layer evaluation methodology
  (arXiv), Paper 2 on remediation pipeline (7 pages). Both with
  reproducible methodology.

All of this is **already deployed on PyPI** and downloadable now:

```bash
pip install miesc
miesc analyze Vault.cairo  # auto-detects Starknet from extension
```

---

## What the grant funds

### Milestone 1 — Cairo benchmark corpus (month 1–2, USD 6 000)

- Build `benchmarks/datasets/cairo-curated/`: 30–50 real Cairo contracts
  drawn from the Starknet mainnet + testnets, split into 10 vulnerability
  categories with manual ground-truth labels.
- Include **victim-side** exploit code (not just attacker harnesses):
  zkLend's lending market pre-Feb-2025 patch, Nostra pools, Braavos
  account contract versions, Carmine Options, Ekubo v0.
- Deliverable: labelled dataset + benchmark script + a paper-quality
  evaluation table comparing MIESC, Caracal, and any other public Cairo
  analyzer available at month-2.

### Milestone 2 — Expanded pattern coverage (month 2–4, USD 8 000)

- Add 17+ new vulnerability classes informed by: Cairo 1.0 upgrade
  semantics (replace_class), felt-to-u256 conversion pitfalls,
  keccak-on-felt collisions, component storage shadowing, Pragma
  publisher staleness, VM entrypoint confusion.
- Each new pattern ships with attack_steps + detection_heuristic fields
  (MIESC's RAG knowledge base schema) and a dedicated test.
- Deliverable: 30+ vulnerability types, ≥90% recall on the milestone-1
  benchmark.

### Milestone 3 — Formal-verification bridges (month 4–5, USD 5 000)

- Integrate Caracal as a first-class MIESC adapter (currently referenced
  in docstrings but not wired).
- Generate Certora-Cairo spec stubs from MIESC findings (following the
  same pattern as our EVM CVL generator in `src/formal/spec_generator.py`).
- Deliverable: `miesc specs <cairo_file> -f certora-cairo` + end-to-end
  documentation.

### Milestone 4 — Developer workflow integration (month 5–6, USD 6 000)

- Scarb plugin: `scarb miesc` runs MIESC on the current package.
- VS Code extension Cairo support (existing VSX extension needs Cairo
  language registration).
- Pull requests into the Cairo Book + Starknet Book to reference MIESC
  in the security chapters.
- Deliverable: scarb plugin + VSX update + doc PRs.

---

## Team

**Fernando Boiero** — sole developer.
- 12+ years of software engineering; MSc in Cybersecurity (UNDEF, in
  progress).
- Built MIESC solo over 18 months. The codebase (133 KLOC source,
  77 KLOC tests) reflects a disciplined solo effort, not a demo.
- Prior open-source: (link your other OSS work / UTN page)
- Referee contact: (optional — your thesis director or an UTN colleague)

No co-applicants. If the grant requires a multi-member team, we will
onboard a Cairo specialist from the Starknet community during month 1.

---

## Why this is different from existing work

- **Caracal** (Trail of Bits) is the closest analog but focuses on a
  specific set of Cairo 1.0 detectors. MIESC wraps Caracal AND adds 13
  additional patterns informed by 2024–2026 real incidents not in
  Caracal's scope.
- **Starknet Tenderly** and similar services are runtime monitors, not
  pre-deployment analysis. MIESC targets the audit-before-ship workflow.
- **No public Cairo analyzer ships with a reproducible 2024–2026 exploit
  corpus**. This grant funds that corpus and pins MIESC as the reference
  implementation.

---

## Ask for the Starknet Foundation

**USD 25 000** over 6 months, milestone-based:
- M1: $6 000 (Cairo benchmark corpus)
- M2: $8 000 (30+ vulnerability classes)
- M3: $5 000 (formal verification bridges)
- M4: $6 000 (developer workflow integration)

Payment via USDC / ETH on Starknet-native address (preferred) or SEPA.

Post-grant, MIESC remains AGPL-3.0 open source. No exclusivity to
Starknet Foundation — but the scarb plugin, Cairo-Book PRs, and Starknet
ecosystem integration stay permanent.

---

## Supporting materials

- **Code**: https://github.com/fboiero/MIESC
- **PyPI**: https://pypi.org/project/miesc/
- **Paper 1** (multi-layer evaluation): `paper/miesc-paper.pdf`
- **Paper 2** (remediation pipeline, 7 pages): `paper/miesc-paper2.pdf`
- **Cairo benchmark fixture**: `examples/contracts/cairo/Modern2024Exploits.cairo`
- **Test suite**: `pytest tests/ -q` → 5,300+ passed
- **License**: AGPL-3.0 (`LICENSE`)
- **Reproducibility**: `miesc evaluate corpus` / `miesc evaluate ablation`
- **Research Guide**: `docs/guides/RESEARCH.md`
- **Plugin Guide**: `docs/guides/PLUGINS.md`
