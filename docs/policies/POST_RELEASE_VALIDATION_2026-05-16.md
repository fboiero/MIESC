# Post-Release Validation - 2026-05-16

This note records validation performed after the published `v5.4.2` release.
It is a handoff checkpoint for deciding whether the current `main` head should
remain post-release hardening or become a new patch release.

## Repository State

| Field | Value |
| --- | --- |
| Branch | `main` |
| Current head | `76b31ad docs: Align paper publication instructions` |
| Published release tag | `v5.4.2` |
| GitHub release status | Published, not draft, not prerelease |
| Published at | `2026-05-09T19:44:54Z` |

The `v5.4.2` tag and GitHub release already exist. Do not retag or republish
the same semantic version from the current post-release head. If the current
changes need publication, bump to the next patch version and create a new
release.

## Remote CI Verification

The current head was validated by GitHub Actions:

| Workflow | Run | Result |
| --- | --- | --- |
| MIESC CI/CD Pipeline | `25972405474` | `success` |
| OpenSSF Scorecard | `25972405466` | `success` |

The CI/CD pipeline completed lint/format, security scan, type check, unit
tests, documentation build/link check, integration tests, benchmarks, Docker
build/test, and Trivy scan.

## Local Release Package Verification

Executed locally after CI was green:

```bash
make release
```

Result:

- Built `dist/miesc-5.4.2-py3-none-any.whl`
- Built `dist/miesc-5.4.2.tar.gz`
- `twine check dist/*`: passed
- `scripts/check_distribution_contents.py dist`: passed

The first attempt failed because the sandboxed build environment could not
download isolated build dependencies. The command passed after allowing network
access for the isolated Python build.

## Decision Gate

Current recommendation:

- Treat `main` after `v5.4.2` as validated post-release hardening.
- Do not publish the regenerated `5.4.2` artifacts over the existing PyPI or
  GitHub release artifacts.
- If these commits should reach users as a package release, prepare `5.4.3`
  with a changelog entry covering the cache hermeticity fix, public packaging
  alignment, documentation updates, CI/Docker alignment, and paper publication
  instruction update.
