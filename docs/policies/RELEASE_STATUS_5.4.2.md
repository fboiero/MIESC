# MIESC 5.4.2 Release Status

This note records the published artifacts and the minimum verification commands
for the 5.4.2 release surface.

## Published Artifacts

| Channel | Artifact |
| --- | --- |
| GitHub Release | https://github.com/fboiero/MIESC/releases/tag/v5.4.2 |
| PyPI | https://pypi.org/project/miesc/5.4.2/ |
| GHCR standard image | `ghcr.io/fboiero/miesc:5.4.2` |
| GHCR latest image | `ghcr.io/fboiero/miesc:latest` |

The standard Docker image tags `5.4.2` and `latest` currently resolve to:

```text
sha256:17c06605e44236a01237c7210a7734d08b801e6338872550d0fcf4070190b3d8
```

## Standard Docker Image Scope

The standard image is intended for portable smart-contract auditing on amd64 and
ARM64 workstations. It includes:

- MIESC CLI 5.4.2
- Slither
- Aderyn 0.6.8, installed from the official pinned release binary with checksum verification
- Solhint 5.0.3
- Foundry 1.7.1
- Solidity compiler access through native `solc` on amd64 and `solcjs` fallback on ARM64
- Built-in MIESC detectors, report generation, REST/API dependencies, and MCP support

The full researcher image remains the target for heavier optional tools such as
Mythril, Manticore, Halmos, Wake, Semgrep, ML/RAG dependencies, and licensed
formal verification workflows.

## Smoke Test Commands

```bash
docker pull ghcr.io/fboiero/miesc:5.4.2
docker run --rm ghcr.io/fboiero/miesc:5.4.2 --version
docker run --rm --entrypoint aderyn ghcr.io/fboiero/miesc:5.4.2 --version
docker run --rm --entrypoint forge ghcr.io/fboiero/miesc:5.4.2 --version
docker run --rm --entrypoint solhint ghcr.io/fboiero/miesc:5.4.2 --version
docker run --rm --entrypoint solc ghcr.io/fboiero/miesc:5.4.2 --version
docker run --rm ghcr.io/fboiero/miesc:5.4.2 doctor
```

Expected baseline:

- `miesc --version`: `MIESC version 5.4.2`
- `aderyn --version`: `aderyn 0.6.8`
- `solhint --version`: `5.0.3`
- `doctor`: loads 50 adapters and reports the standard-image tool subset as available

## Reproducibility Notes

- GitHub Release and PyPI artifacts are tied to the `v5.4.2` release artifacts.
- The standard Docker image was rebuilt from the current 5.4.2 release surface
  after replacing the previous in-image Aderyn source build with the pinned
  official binary download path.
- Benchmark result files were not modified as part of the Docker publication.
