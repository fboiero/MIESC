# MIESC — DPGA Filing Checklist

A short, concrete pre-flight for Fernando to complete **before / at** the moment
of filing MIESC with the Digital Public Goods Alliance. It complements the full
[`DPGA_SUBMISSION.md`](./DPGA_SUBMISSION.md) package and the compliance statement
in [`../policies/DPG-COMPLIANCE.md`](../policies/DPG-COMPLIANCE.md).

This is a **self-assessment supporting an open review**. Nothing here asserts
that the DPGA has granted recognition. Where an item cannot be confirmed from the
repository alone, it is marked as a human action for Fernando.

The dated CI/PR readiness snapshot lives alongside this file in
[`DPGA_FILING_READINESS_20260819.md`](./DPGA_FILING_READINESS_20260819.md): this
document is the "how to file" pre-flight; that one is the point-in-time repo
state. Per that snapshot, do **not** state "all latest CI is green" until the
post-merge workflows complete — it is accurate to say the repo has no open PRs
and the hosted docs endpoint returned HTTP 200 on 2026-08-19.

## Snapshot verified in this pass (against `main`, release v6.0.0)

- All nine indicator evidence paths resolve on the current default branch.
- All relative links and `DPG-COMPLIANCE.md` anchors resolve (EN/ES).
- Security-scanner claim matches `.github/workflows/ci.yml` exactly (Bandit,
  pip-audit, safety, Trivy, CodeQL). **No Semgrep/Snyk claim survives** — they
  were never wired in.
- Line-coverage figure reconciled to the release-validated **81%** (previously
  overstated as 88%); mutation 75% on core v6 modules.
- Three broken evidence links and one stale Docker tag corrected in
  [`../policies/DPGA_Application_Responses.csv`](../policies/DPGA_Application_Responses.csv).

## Must confirm before filing (human action — do NOT fabricate)

- [ ] **Application id `#13478`** is current in the DPGA portal
      (`app.digitalpublicgoods.net/a/13478`) and refers to this submission.
      Carried from earlier records — flagged "verify" in the package header.
- [ ] **Global ID `GID0092948`** is current and matches application #13478.
- [ ] **Review status** — check whether the review is still open, has reviewer
      questions pending, or has been decided; update the status line in
      `DPGA_SUBMISSION.md` and `DPG-COMPLIANCE.md` accordingly.
- [ ] **Hosted docs render live** — open <https://fboiero.github.io/MIESC> and
      confirm it renders (cited as indicator-5 evidence; not verifiable from the
      repo).
- [ ] **DPG evangelist / shepherd thread** referenced if the review is being
      shepherded (historically Bolaji Ayodeji, per `DPG-COMPLIANCE.md`).

## Attach / link at filing time

- [ ] **v6.0.0 release** on GitHub (tag `v6.0.0`) as the release under review.
- [ ] **Release-validation record** —
      [`../policies/POST_RELEASE_VALIDATION_2026-07-13.md`](../policies/POST_RELEASE_VALIDATION_2026-07-13.md)
      (canonical source for the coverage/mutation figures).
- [ ] **SBOM** — [`../policies/SBOM.md`](../policies/SBOM.md) +
      [`.github/workflows/sbom.yml`](../../.github/workflows/sbom.yml)
      (CycloneDX/SPDX generated per release).
- [ ] **Signing / release verification (Sigstore)** —
      [`../policies/RELEASE_VERIFICATION.md`](../policies/RELEASE_VERIFICATION.md)
      and [`../guides/SIGNED_COMMITS.md`](../guides/SIGNED_COMMITS.md).
- [ ] **OpenSSF Scorecard** — [`.github/workflows/scorecard.yml`](../../.github/workflows/scorecard.yml).
- [ ] **Application-response answers** —
      [`../policies/DPGA_Application_Responses.csv`](../policies/DPGA_Application_Responses.csv);
      confirm the version pasted into the portal matches v6.0.0 (project
      version, Docker tag, metrics).

## Reviewer-facing evidence index (the 9 indicators)

Each row was confirmed present on `main` at v6.0.0.

| # | Indicator | Primary evidence (relative to `docs/dpga/`) |
|---|-----------|---------------------------------------------|
| 1 | SDG relevance | [`../policies/SDG_RELEVANCE.md`](../policies/SDG_RELEVANCE.md) · [`DPG-COMPLIANCE.md §1`](../policies/DPG-COMPLIANCE.md#indicator-1-sdg-relevance) |
| 2 | Open licensing | [`LICENSE`](../../LICENSE) (AGPL-3.0-only, OSI-approved) |
| 3 | Clear ownership | [`DPG-COMPLIANCE.md §3`](../policies/DPG-COMPLIANCE.md#indicator-3-clear-ownership) · [`CONTRIBUTORS.md`](../CONTRIBUTORS.md) |
| 4 | Platform independence | [`DPG-COMPLIANCE.md §4`](../policies/DPG-COMPLIANCE.md#indicator-4-platform-independence) · [`ARCHITECTURE.md`](../ARCHITECTURE.md) |
| 5 | Documentation | <https://fboiero.github.io/MIESC> · [`README.md`](../../README.md) / [`README_ES.md`](../../README_ES.md) · [`openapi.yaml`](../openapi.yaml) |
| 6 | Data extraction / portability | [`DPG-COMPLIANCE.md §6`](../policies/DPG-COMPLIANCE.md#indicator-6-data-extraction) (JSON, SARIF 2.1, CSV, MD, HTML, PDF) |
| 7 | Privacy & applicable laws | [`../policies/PRIVACY.md`](../policies/PRIVACY.md) |
| 8 | Standards & best practices | [`DPG-COMPLIANCE.md §8`](../policies/DPG-COMPLIANCE.md#indicator-8-standards--best-practices) · [`CODE_OF_CONDUCT.md`](../../CODE_OF_CONDUCT.md) |
| 9 | Do no harm by design | [`../policies/DO_NO_HARM.md`](../policies/DO_NO_HARM.md) · [`../policies/RESPONSIBLE_USE.md`](../policies/RESPONSIBLE_USE.md) · [`DPG-COMPLIANCE.md §9`](../policies/DPG-COMPLIANCE.md#indicator-9-do-no-harm) |

## Consistency items to keep aligned

- [ ] **License SPDX** expressed as `AGPL-3.0-only` across `LICENSE`,
      `pyproject.toml`, and the portal form.
- [ ] **SDG-9 target** reconciled to **9.b** across `DPG-COMPLIANCE.md`,
      `SDG_RELEVANCE.md`, `DPGA_SUBMISSION.md`, and the responses CSV. If you
      prefer 9.5 in the portal, change it in one place and re-align the others.
- [ ] **Metrics** (tool/module count, chain count, KB patterns, benchmark
      figures) match the release being submitted before filing.

## Flagged for Fernando (frozen files — not edited in this pass)

- The root [`README.md`](../../README.md) states the project "is fully compliant
  with all 9 DPGA indicators." That is stronger than the honest "self-assessed
  9/9, under review" framing used throughout this package. Soften it to
  "self-assesses as meeting all 9 DPGA indicators (application #13478 under
  review)" the next time the README baseline is intentionally refreshed — do not
  edit it ad hoc while frozen.

---

*Additive filing-support documentation. References existing repository evidence;
does not modify any frozen paper, benchmark, or claims artifact.*
