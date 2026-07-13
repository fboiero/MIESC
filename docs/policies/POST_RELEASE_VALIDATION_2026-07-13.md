# Post-Release Validation - 2026-07-13

This note records validation performed after the published `v6.0.0` release —
the v6.0 major release that ships the full v6 feature set as a Digital Public
Good candidate. It is a handoff checkpoint for deciding whether the current
`main` head should remain post-release hardening or become a new patch release.

## Repository State

| Field | Value |
| --- | --- |
| Branch | `main` |
| Current head | `f1a81285 fix(tests): make 3 env-fragile tests robust for minimal CI` |
| Published release tag | `v6.0.0` |
| Tag commit | `f1a81285` |
| GitHub release status | Published, not draft, not prerelease |

The `v6.0.0` tag and GitHub release exist and point at `f1a81285`. Do not retag
or republish the same semantic version from a later post-release head. If the
current changes need publication, bump to the next patch version and create a
new release.

## Remote CI Verification

The release head was validated by GitHub Actions:

| Workflow | Result |
| --- | --- |
| MIESC CI/CD Pipeline (Lint, Unit Tests, Type Check, Security, Integration, Benchmarks) | `success` |
| OpenSSF Scorecard | `success` |
| Release to PyPI (test → build → sign → publish) | `success` |
| Docker Build and Publish (multi-arch) | `success` |
| SBOM Generation | `success` |

## Published Artifacts

| Channel | Value |
| --- | --- |
| PyPI | `miesc 6.0.0` (latest) |
| Container (ghcr) | `ghcr.io/fboiero/miesc:6.0.0`, `:6.0`, `:6.0.0-full`, `:6.0-full`, `:latest` (multi-arch amd64/arm64) |
| Release assets | `miesc-6.0.0-py3-none-any.whl`, `miesc-6.0.0.tar.gz`, matching Sigstore `.sig` + `.pem` for each, `sbom.json` (CycloneDX), `SHA256SUMS.txt`, `licenses.csv` |

## Verifying the Release

Wheel/sdist are keyless-signed with cosign (Sigstore). Users can verify:

```bash
cosign verify-blob \
  --certificate miesc-6.0.0-py3-none-any.whl.pem \
  --signature   miesc-6.0.0-py3-none-any.whl.sig \
  --certificate-identity-regexp "https://github.com/fboiero/MIESC.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  miesc-6.0.0-py3-none-any.whl
```

Checksums: `sha256sum -c SHA256SUMS.txt`. SBOM: `sbom.json` (CycloneDX).

## Release Provenance Note

The `v6.0.0` cut initially failed to publish: the release workflow's test gate
surfaced pre-existing failures that only appear in a minimal CI environment
(an unguarded `z3` import, ruff/black drift, and three tests that assumed
locally-installed tools). No broken artifact was published — the test gate
blocked the PyPI upload as designed. The blockers were fixed on `main`, the
`v6.0.0` tag was moved to the fixed commit before anything consumed the version,
and the release was re-published cleanly. This is why the tag points at
`f1a81285` rather than the original cut commit.

## Milestone Snapshot

`v6.0.0` shipped with: 9/9 v6 feature set (baseline & suppression, SARIF inline
PR annotations, structured code-action output, LSP diagnostics server, unified
formal-verification report with Scribble/Kontrol, plugin API versioning +
conformance, reference plugins, webhook/Slack notifier); 9/9 DPGA indicators
(self-assessed, application under review); 81% line coverage; 75% mutation score
on the core v6 modules; deterministic test suite.
