# Researcher Packaging Guide

This is the recommended way to run MIESC as a security researcher or smart contract developer.

## Recommended Distribution Model

Use three tiers:

1. **PyPI package** for the stable CLI and API:
   `pip install miesc`

2. **Researcher bootstrap** for local full-tool installations:
   `scripts/bootstrap_researcher_tools.sh`

3. **Docker full image** for reproducible CI and external review:
   `ghcr.io/fboiero/miesc:full`

The PyPI package should remain lightweight. Heavy or conflicting tools such as Mythril, Manticore, Certora CLI, Wake, and Semgrep should be installed in isolated tool environments under `.tools/`, because they have dependency constraints that conflict with the main Python runtime.

## Local Full Setup

```bash
git clone https://github.com/fboiero/MIESC.git
cd MIESC
scripts/bootstrap_researcher_tools.sh
```

The bootstrap script creates `.venv` when needed, installs MIESC with the `researcher` and `pdf` extras, and then installs heavyweight tools in isolated environments under `.tools/`. If you need tighter control of the runtime environment, create `.venv` before running the script and install MIESC manually:

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e ".[researcher,dev,pdf]"
scripts/bootstrap_researcher_tools.sh
```

`researcher` includes the full application stack plus semantic RAG embeddings. For a lightweight CLI/API install, use `.[full]`; that intentionally excludes `sentence-transformers` so Linux Docker builds do not pull CUDA PyTorch wheels by default.

For Certora, keep credentials outside Git. A local `apik.sh` may define either:

```bash
export CERTORAKEY="..."
```

or:

```bash
export CERTORA_KEY="..."
```

`apik.sh` is ignored by Git.

## Reproducible Workstation Check

Use the diagnostic script as the source of truth for local tool availability:

```bash
export OLLAMA_HOST=http://127.0.0.1:11434
uv run python scripts/diagnose-adapters.py
```

A fully provisioned researcher workstation should report:

```text
Registered 50/50 adapters
Total adapters checked:  50
Available:               50
Not installed:           0
Configuration error:     0
License required:        0
Pass rate: 100.0%
```

The script writes `diagnostic-report.json` in the repository root. That file is generated evidence for the local run and is ignored by Git.

Local environment files are intentionally excluded from version control:

| Path | Reason |
|------|--------|
| `.venv/` | Main Python runtime |
| `.tools/` | Isolated heavyweight tool runtimes |
| `apik.sh` | Optional local credentials |
| `diagnostic-report.json` | Generated diagnostic result |
| `.paper-freeze-local/` | Local reproducibility freeze checks |

Do not use `ollama list` as the only Ollama health check on macOS. Some native Ollama CLI builds can fail before listing models because of MLX/Metal initialization, while the running HTTP service remains healthy. Prefer:

```bash
curl -s http://127.0.0.1:11434/api/tags
```

## Verification

```bash
.venv/bin/python -m miesc.cli.main doctor
.venv/bin/python -m miesc.cli.main audit full tests/fixtures/reentrancy.sol \
  -o /tmp/miesc-full-smoke.json \
  -f json \
  -t 5 \
  --skip-unavailable \
  --no-ml \
  --no-correlate
```

Expected for a fully provisioned local workstation:

- `scripts/diagnose-adapters.py`: `50/50 adapters available`
- full smoke: all core tools execute; project-specific tools may report clean skips when the fixture lacks a Hardhat project, Foundry tests, ZK circuit source, or Certora CVL spec.

## External Project Quickstart

For a Solidity project outside the MIESC repository:

```bash
cd /path/to/solidity-project
export OLLAMA_HOST=http://127.0.0.1:11434
/path/to/MIESC/.venv/bin/miesc audit full contracts/MyContract.sol \
  -o miesc-full-audit.json \
  -f json \
  -t 120 \
  --skip-unavailable
```

Then generate a report:

```bash
/path/to/MIESC/.venv/bin/miesc report miesc-full-audit.json \
  -t premium \
  -f pdf \
  -o miesc-audit-report.pdf
```

For projects with Foundry, Hardhat, Certora specs, or ZK circuits, run MIESC from the project root so adapters can discover project-level configuration and tests.

## Docker Full Image

The Docker full image is the preferred handoff for external reviewers because it avoids workstation-specific Python, Node, Rust, and Solidity compiler drift.

Plan for at least 30 GB of free Docker storage for a clean standard + full build. The standard image intentionally excludes embedding/ML dependencies; the full image installs CPU-only PyTorch before `sentence-transformers` so semantic RAG remains reproducible without GPU packages.

On ARM/Apple Silicon, native full builds skip Echidna, Medusa, Mythril, Manticore, Halmos, and Semgrep by default because upstream releases are amd64-only, require long Z3 source builds, or ship ARM wheels that are not reliable in Docker. For complete ARM workstation parity, use `scripts/bootstrap_researcher_tools.sh`. For reproducible external review, prefer the amd64 full image. To force Mythril, Manticore, Halmos, or Semgrep inside a native ARM full Docker build, pass the matching build arg such as `--build-arg MIESC_BUILD_MYTHRIL=true`, `--build-arg MIESC_BUILD_MANTICORE=true`, `--build-arg MIESC_BUILD_HALMOS=true`, or `--build-arg MIESC_BUILD_SEMGREP=true`; when using `scripts/build-images.sh`, set the matching `MIESC_BUILD_*` environment variable to `true`.

If Docker runs out of space, prune build cache before rebuilding:

```bash
docker builder prune
```

Build the full image from the repository root:

```bash
docker compose -f docker/docker-compose.yml build miesc
docker compose -f docker/docker-compose.yml --profile full build miesc-full
```

Run a full smoke:

```bash
docker compose -f docker/docker-compose.yml --profile full run --rm miesc-full \
  miesc doctor

docker compose -f docker/docker-compose.yml --profile full run --rm miesc-full \
  miesc audit full /app/contracts/MyContract.sol \
    -o /data/miesc-full.json \
    -f json \
    -t 120 \
    --skip-unavailable
```

For Certora, pass credentials at run time instead of baking them into the image:

```bash
docker compose -f docker/docker-compose.yml --profile full run --rm \
  -e CERTORAKEY \
  miesc-full \
  miesc doctor
```

Do not run `docker compose config` in a terminal or CI log that may be shared while secrets are exported in the environment. Compose expands environment values in rendered configuration output.

## How Users Should Run It

For every commit or pull request:

```bash
miesc scan contracts/ --recursive -o miesc-scan.json
miesc export miesc-scan.json -f sarif -o miesc.sarif
```

Before deployment or release:

```bash
miesc audit full contracts/MyContract.sol -o miesc-full.json -f json -t 120
miesc report miesc-full.json -t premium -f pdf -o miesc-audit.pdf
```

For remediation evidence:

```bash
miesc remediate miesc-scan.json \
  -c contracts/MyContract.sol \
  -o contracts/MyContract.patched.sol \
  --compile \
  --rescan \
  --evidence remediation-evidence.json
```

## Packaging Decision

The best public packaging is:

- Publish `miesc` as a normal Python package.
- Publish and maintain `ghcr.io/fboiero/miesc:full` as the one-command researcher image.
- Keep `scripts/bootstrap_researcher_tools.sh` for local workstation parity with the full image.
- Treat Certora as optional but supported: installed by bootstrap, activated only when `CERTORAKEY` or `CERTORA_KEY` is present.

This avoids forcing every user to install heavyweight formal-verification and symbolic-execution dependencies, while still giving reviewers a reproducible full-tool path.
