# Testing MIESC Docker Images v5.0.3

**[Versión en Español](DOCKER_TESTING_GUIDE_ES.md)**

Instructions to pull and verify the latest Docker images.

---

## 1. Clean old cached images (optional)

```bash
docker rmi ghcr.io/fboiero/miesc:latest ghcr.io/fboiero/miesc:full 2>/dev/null
```

## 2. Pull and verify

```bash
# Standard (~2GB, multi-arch: works natively on x86_64 and ARM)
docker pull ghcr.io/fboiero/miesc:latest
docker run --rm ghcr.io/fboiero/miesc:latest --version
docker run --rm ghcr.io/fboiero/miesc:latest doctor

# Full (~3GB, amd64-only in registry)
docker pull ghcr.io/fboiero/miesc:full
docker run --rm ghcr.io/fboiero/miesc:full --version
docker run --rm ghcr.io/fboiero/miesc:full doctor
```

Both commands should show **MIESC version 5.0.3**.

## 3. Run a test scan

```bash
docker run --rm -v $(pwd):/contracts ghcr.io/fboiero/miesc:latest scan /contracts/MyContract.sol
```

## 4. Available tags

| Tag | Contents |
|-----|----------|
| `miesc:latest` / `miesc:5.0.3` | Standard: Slither, Aderyn, Solhint, Foundry (~15 tools) |
| `miesc:full` / `miesc:5.0.3-full` | Full: + Mythril, Manticore, Echidna, Halmos, PyTorch (~30 tools) |

> **Note:** Ignore any older versions (pre-5.0.3) that may appear in the registry. Always use the tags listed above.

## 5. ARM / Apple Silicon

The `:latest` (standard) image is multi-arch and runs natively on ARM.

The `:full` image in the registry is amd64-only. On ARM it runs under QEMU emulation (~3-5x slower). For native performance, build locally:

```bash
git clone https://github.com/fboiero/MIESC.git
cd MIESC
./scripts/build-images.sh full
```

The build script will detect ARM and ask for confirmation (z3-solver compilation takes ~30-60 min). The resulting image runs at native speed.

Alternatively, use the setup wizard which guides you through all options:

```bash
./scripts/docker-setup.sh
```
