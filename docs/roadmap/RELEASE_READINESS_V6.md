# Release Readiness Audit — v6.0.0

Status of this document: **audit / checklist only.** No version has been bumped
and no release has been cut. The point here is to make cutting v6.0.0 a
button-press once the feature set is complete, and to record exactly what has to
change and where.

Current version on `main`: **5.4.3** (`miesc/__init__.py:14`). v6.0.0 is a MAJOR
bump.

Audited against `origin/main` at `698065fb`.

---

## TL;DR — to cut v6.0.0, do these in order

1. **Confirm the feature set is complete** (v6 capabilities 9/9) and the full
   suite is green: `python3 -m pytest -q -p no:cacheprovider`, plus
   `make test-coverage` (must pass `--cov-fail-under=85` locally / 80 in CI) and
   `make mutate-check`.
2. **Bump the single source of truth:** `miesc/__init__.py:14`
   `__version__ = "5.4.3"` -> `"6.0.0"`. `pyproject.toml` reads this dynamically
   (`version = {attr = "miesc.__version__"}`), so PyPI/wheel version follows
   automatically. This is the ONLY functionally-load-bearing version string.
3. **Update the hand-maintained mirrors** (none are read at runtime, but they are
   user-facing and must not lie — see the Version Strings table below):
   `CITATION.cff` (version + `date-released`), README `v5.4.3` mentions, all
   `docker/*` files and `docker/docker-compose*.yml`, `docs/INSTALLATION_ES.md`.
4. **Finalize the CHANGELOG:** promote the drafted `## [6.0.0] - UNRELEASED`
   section to `## [6.0.0] - <release-date>` and move anything still in
   `[Unreleased]` as appropriate.
5. **Run the paper freeze validator** before committing anything paper/benchmark
   adjacent: `sh .paper-freeze-local/validate_paper_reproducibility_freeze.sh`.
6. **Tag + GitHub Release.** Create the `v6.0.0` GitHub Release (published). This
   is the trigger for `release.yml` (PyPI + Sigstore) and `sbom.yml`. Pushing the
   `v6.0.0` tag independently also triggers `docker.yml` multi-arch publish.
7. **Enable the release-time repo variables** if not already set (see release.yml
   gaps): `RELEASE_WORKFLOW_BUILDS_DOCKER=true` (only if you want the release
   workflow to also build Docker — otherwise `docker.yml` handles it on the tag),
   and optionally `ENABLE_TEST_PYPI=true` for a Test PyPI dry-run first.
8. **Verify artifacts post-publish:** checksums + cosign per
   `docs/policies/RELEASE_VERIFICATION.md`; confirm the CycloneDX SBOM attached to
   the release; confirm `ghcr.io/fboiero/miesc:6.0.0` and `:6.0` multi-arch tags
   exist.

---

## 1. Version strings — ⚠️ needs-action (hand-maintained, scattered)

There is **no version-bump helper script**. The version is hand-copied into many
files, and some are already stale relative to `5.4.3` (demo scripts and one
benchmark still say `5.1.1`). Only `miesc/__init__.py` is functionally
load-bearing; everything else is documentation/packaging metadata that must be
updated by hand at release time.

| File:line | Current value | Action for v6.0.0 |
| --- | --- | --- |
| `miesc/__init__.py:14` | `__version__ = "5.4.3"` | ✅ **canonical** — bump to `"6.0.0"` (this is the release-cut action) |
| `pyproject.toml:175` | `version = {attr = "miesc.__version__"}` | ✅ no change — dynamic, follows `__init__.py` |
| `CITATION.cff:4-5` | `version: 5.4.3`, `date-released: "2026-05-16"` | bump version + date |
| `README.md:323` | `The current release is **v5.4.3**` | bump |
| `README.md:497` | pre-commit example `rev: v5.4.3` | bump |
| `docker/Dockerfile:1,70` | `# MIESC v5.4.3`, `ARG MIESC_VERSION=5.4.3` | bump |
| `docker/Dockerfile.full:1,40,211` | `5.4.3-full` (comment, `LABEL`, `ENV`) | bump |
| `docker/Dockerfile.x86:1,5,8,18,51,113,120,126` | header says `v5.3.1` (already stale) rest `5.4.3` | bump + fix the stale `v5.3.1` header |
| `docker/docker-compose.yml` (~15 refs) | `miesc:5.4.3` / `MIESC_VERSION=5.4.3` | bump all |
| `docker/docker-compose.prod-llm.yml:35,38,221,224` | `5.4.3` | bump |
| `docs/INSTALLATION_ES.md:1,277,278,284,285,321,448` | `v5.4.3` | bump |
| `demo/video_auto.sh` (52,149) | **`5.1.1` (already stale)** | bump to `6.0.0` |
| `demo/video_demo.sh` (3,15,59,65,207) | **`5.1.1` (already stale)** | bump to `6.0.0` |
| `benchmarks/evaluate_extended_exploits.py:188` | `"miesc_version": "5.1.1"` (already stale) | leave if benchmark is frozen-adjacent; otherwise bump |
| `grants/02_EF_ESP.md:20,42` | `v5.4.0` prose | optional prose refresh (non-blocking) |

**Recommendation (post-release, non-blocking):** add a `make bump VERSION=x.y.z`
target or a `scripts/bump_version.py` that rewrites this table from a single
input, so the release cut stops depending on grep discipline. The stale `5.1.1`
demo scripts and the `v5.3.1` Dockerfile.x86 header are evidence this is already
drifting.

---

## 2. CHANGELOG — ✅ ready (draft added)

- `CHANGELOG.md` exists, follows Keep a Changelog + SemVer, has an `[Unreleased]`
  section.
- A **`## [6.0.0] - UNRELEASED (draft)`** section has been added (additive) in
  this branch, summarizing the cycle-6 work: T1.1 baseline engine, T1.2 SARIF
  inline annotations, T1.3 webhook/Slack notifier, T2.1 code-actions, T3.1
  unified formal report, T3.3 versioned plugin API, T3.4 reference plugins, plus
  the coverage-gate lock (80%/81.12%), mutmut-3.x migration (75% score), and
  determinism work. The Makefile `src/`->`miesc/` fix from this branch is also
  logged under **Fixed**.
- **Action at cut time:** change the heading from `UNRELEASED (draft)` to the
  release date, and reconcile `[Unreleased]`.

---

## 3. `release.yml` workflow — ✅ mostly ready, ⚠️ two gated steps to enable

The workflow (`.github/workflows/release.yml`) triggers on `release: published`
(and `workflow_dispatch`) and runs: **test -> build -> sign -> publish -> docker
-> release-notes.** No stale `src/` references (the ci.yml `src/`->`miesc/` fix
from `f2109b4f` already landed; `example-miesc-action.yml` `src/**/*.sol` is a
Solidity contract path, not the Python package — correct as-is).

| Step | State | Notes |
| --- | --- | --- |
| `test` job | ✅ | runs `pytest tests/` then a coverage pass with `--cov=miesc --cov-fail-under=80` (we pass at 81.12%). Uses `codecov-action@v7` with `fail_ci_if_error: false`. |
| `build` job | ✅ | `make build` + `make build-check` (`python -m build` + `twine check`), generates SHA256SUMS, uploads dist artifact. Version flows dynamically from `__init__.py`. |
| `sign` job | ✅ | `sigstore/cosign-installer@v3` + `cosign sign-blob` producing `.sig` + `.pem` per artifact. |
| `publish` job | ✅ | `pypa/gh-action-pypi-publish` via OIDC trusted publishing (`environment: pypi`, `id-token: write`, `skip-existing: true`). **Requires the `pypi` environment + PyPI trusted-publisher config to exist.** |
| `publish-test` job | ⚠️ gated | only runs if repo var `ENABLE_TEST_PYPI == 'true'`. Optional dry-run — set it if you want a Test PyPI rehearsal first. |
| `docker` job | ⚠️ gated | only runs if repo var `RELEASE_WORKFLOW_BUILDS_DOCKER == 'true'`. Builds multi-arch (`linux/amd64,linux/arm64`) from `docker/Dockerfile`, semver + latest tags. **Redundant with `docker.yml`** which already publishes multi-arch on a `v*` tag push — decide which one owns Docker at release time to avoid double-publish. |
| `create-release-notes` job | ✅ | regenerates checksums, auto-changelog, attaches `.whl/.tar.gz/.sig/.pem/SHA256SUMS.txt` to the release, links `RELEASE_VERIFICATION.md`. |

**Gaps / decisions:**
- ⚠️ The `docker` job and the whole of `sbom.yml` require the release to be a
  **published GitHub Release** (not just a pushed tag) for the `release`-triggered
  paths. `docker.yml` additionally fires on the `v*` tag push itself.
- ⚠️ Confirm the `pypi` GitHub Environment exists and PyPI trusted publishing is
  configured for this workflow/repo, or `publish` will fail.
- ⚠️ Coverage step recomputes coverage separately from the first `pytest` run
  (two test executions). Not a blocker, just slower; could be merged later.

---

## 4. Docker — ✅ ready, ⚠️ version strings + one stale header

- Multi-arch build is handled by **`docker.yml`** (job `build-multiarch`,
  `platforms: linux/amd64,linux/arm64`, emits `type=semver {{version}}` and
  `{{major}}.{{minor}}` + `latest` on a `v*` tag / default branch) and,
  optionally, by the gated `docker` job in `release.yml`. Standard image is
  multi-arch; `Dockerfile.full` / `Dockerfile.x86` are amd64-oriented for full
  tool parity (matches the documented architecture).
- ✅ `docker/Dockerfile` uses `ARG MIESC_VERSION=5.4.3` — bump at release.
- ⚠️ **Version pinning to bump:** every `docker/*` file and both compose files
  hardcode `5.4.3` (see Version Strings table). These are cosmetic/label values,
  not build-breaking, but must be bumped so images self-report correctly.
- ⚠️ **Stale header:** `docker/Dockerfile.x86:1` says `MIESC v5.3.1` while the
  rest of the file is `5.4.3` — fix during the bump.
- ✅ No stale Python `src/` references in any Dockerfile (they install the built
  `miesc` package / wheel).

---

## 5. Sigstore / signing + SBOM — ✅ ready

- ✅ **Artifact signing:** `release.yml` `sign` job uses cosign keyless signing
  (Sigstore) producing `.sig` + `.pem`, attached to the release by
  `create-release-notes`.
- ✅ **Commit signing guidance:** `docs/guides/SIGNED_COMMITS.md` present.
- ✅ **Verification policy:** `docs/policies/RELEASE_VERIFICATION.md` present and
  linked from the auto-generated release notes (checksum + `cosign verify-blob`
  instructions).
- ✅ **SBOM:** `.github/workflows/sbom.yml` generates a CycloneDX JSON SBOM on
  every `release: published` (and weekly), via `cyclonedx-py environment`.
  `docs/policies/SBOM.md` + `SBOM_ES.md` document verification.
- **Action at release time:** nothing structural. Just confirm the release is
  *published* (so `sbom.yml` and the signing/notes jobs fire), the `pypi`
  environment/OIDC is wired, and then verify the attached `.sig/.pem`, SHA256SUMS,
  and `sbom.json` on the finished release.

---

## Fixes applied in this audit branch (safe, additive)

- **Makefile stale `src/` refs -> `miesc/`.** After the src->miesc unification,
  `src/` is only stale `.pyc` bytecode (untracked, 210 pyc files, no source).
  Several targets still pointed at it and were silently measuring/linting nothing
  real:
  - `test` (line 44) and `test-coverage` (line 337): `--cov=src` -> `--cov=miesc`
    (this restores real coverage measurement — same class of bug as the ci.yml
    `src/` fix in `f2109b4f`).
  - `lint` (55, 57), `format` (66): dropped dead `src/` arg.
  - `security-sast` (300, 302), `security-secrets` (312): `src/` -> `miesc/`.
- **CHANGELOG.md:** added the drafted `[6.0.0]` section.

### Not fixed (noted, out of scope / non-blocking)

- `Makefile:149` `sphinx-apidoc -o docs/api src/` and `Makefile:270`
  `cp -r src/*.py thesis/reproducibility/` still reference `src/`. The first
  generates empty API docs; the second is a thesis-reproducibility target and is
  frozen-adjacent — left untouched deliberately. Revisit outside the paper freeze.
- Version-string sprawl (Section 1) — recommend a bump script post-release.
- The `docker` job in `release.yml` overlapping with `docker.yml` — pick one
  owner before cutting to avoid double multi-arch publish.

---

## Readiness summary

| Dimension | Verdict |
| --- | --- |
| 1. Version strings | ⚠️ needs-action — bump `__init__.py` (canonical) + ~10 doc/docker/citation mirrors at cut time; some already stale |
| 2. CHANGELOG | ✅ ready — v6.0.0 draft added; finalize heading at cut |
| 3. release.yml | ✅ ready — enable `RELEASE_WORKFLOW_BUILDS_DOCKER` / `ENABLE_TEST_PYPI` vars as desired; confirm `pypi` env/OIDC |
| 4. Docker | ✅ ready — bump version labels + fix Dockerfile.x86 header |
| 5. Sigstore + SBOM | ✅ ready — no structural work; verify artifacts post-publish |

The only true blocker is **feature completeness (9/9) + the version bump**;
everything else is mechanical and pre-staged by this audit.
