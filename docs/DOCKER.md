# Docker Deployment Guide for MIESC

This guide explains how to build, test, and run MIESC in Docker containers for reproducible environments.

---

## 🐳 Quick Start

### Prerequisites

- Docker 20.10+ installed
- Docker Compose 2.0+ (optional, for orchestration)
- 4GB+ RAM available for container
- 10GB+ disk space for image

### Build the Image

```bash
docker build -t miesc:latest .
```

Expected build time: ~15-20 minutes (depending on internet speed)

### Verify Installation

```bash
docker run --rm miesc:latest python3 scripts/verify_installation.py
```

---

## 📋 Usage Examples

### 1. Run Installation Verification

```bash
docker run --rm miesc:latest
```

This runs the default command: `python3 scripts/verify_installation.py`

### 2. Run Regression Tests

```bash
docker run --rm miesc:latest python3 scripts/run_regression_tests.py
```

### 3. Analyze a Contract

```bash
# Analyze example contract
docker run --rm miesc:latest \
  python3 xaudit.py --target examples/reentrancy.sol --mode fast

# Analyze your own contract (mount volume)
docker run --rm \
  -v $(pwd)/my_contracts:/contracts \
  miesc:latest \
  python3 xaudit.py --target /contracts/MyToken.sol
```

### 4. Interactive Shell

```bash
docker run -it --rm miesc:latest /bin/bash
```

Inside the container:
```bash
# Run any command
python3 scripts/verify_installation.py
slither --version
forge --version
```

### 5. Persist Outputs

```bash
docker run --rm \
  -v $(pwd)/outputs:/app/outputs \
  miesc:latest \
  python3 xaudit.py --target examples/reentrancy.sol
```

Results will be saved to `./outputs/` on your host machine.

---

## 🎼 Docker Compose

Docker Compose provides easier orchestration for common tasks.

### Available Services

1. **miesc** - Verification service
2. **miesc-dev** - Development shell
3. **miesc-test** - Test runner

### Commands

```bash
# Run verification
docker-compose up miesc

# Run tests
docker-compose up miesc-test

# Development shell
docker-compose run miesc-dev

# Analyze contract
docker-compose run miesc python3 xaudit.py --target examples/reentrancy.sol

# Clean up
docker-compose down
```

---

## 🔧 Configuration

### Environment Variables

Set in `docker-compose.yml` or pass with `-e`:

```bash
docker run --rm \
  -e OPENAI_API_KEY="sk-..." \
  miesc:latest \
  python3 xaudit.py --target examples/complex.sol --enable-ai-triage
```

### Volume Mounts

Common mount points:

| Host Path | Container Path | Purpose |
|-----------|----------------|---------|
| `./examples` | `/app/examples` | Example contracts |
| `./outputs` | `/app/outputs` | Analysis results |
| `./config` | `/app/config` | Configuration files |
| `./my_contracts` | `/contracts` | Your contracts |

---

## 🧪 Testing the Docker Setup

Use the provided test script:

```bash
./scripts/docker_test.sh
```

This script:
1. ✅ Builds the Docker image
2. ✅ Runs installation verification
3. ✅ Runs regression tests
4. ✅ Tests example contract analysis

---

## 📊 Image Details

### Installed Tools

**Layer 1 (Static)**:
- Slither v0.10.3
- Aderyn v0.6.4 (Rust-based, ultra-fast)
- Solhint v4.1.1 (via npm)

**Layer 2 (Dynamic)**:
- Echidna v2.2.4
- Foundry (forge, cast, anvil)

**Layer 3 (Symbolic)**:
- Mythril v0.24.2
- Manticore v0.3.7

**Layer 4 (Formal)**:
- SMTChecker (via solc 0.8.20+)
- Wake v4.20.1

**Core Dependencies**:
- Python 3.9
- Node.js 16+
- Rust/Cargo (for Aderyn)
- Solidity compiler (solc)

### Image Size

Approximate size: **2.5-3GB**

Breakdown:
- Base Ubuntu: ~100MB
- Python + dependencies: ~800MB
- Node.js + tools: ~300MB
- Rust toolchain: ~500MB
- Security tools: ~800MB

---

## 🔍 Troubleshooting

### Build Fails

**Issue**: Rust compilation errors for Aderyn
```bash
error: failed to compile aderyn
```

**Solution**: Update Rust toolchain in Dockerfile
```dockerfile
RUN rustup update stable
RUN cargo install aderyn --locked
```

### Container Runs Out of Memory

**Issue**: Docker container crashes during analysis

**Solution**: Increase Docker memory limit
```bash
# Docker Desktop: Settings > Resources > Memory > 4GB+
# Docker CLI:
docker run --memory=4g --rm miesc:latest
```

### Permission Errors on Outputs

**Issue**: Cannot write to mounted volume

**Solution**: Run with proper user permissions
```bash
docker run --rm \
  -v $(pwd)/outputs:/app/outputs \
  --user $(id -u):$(id -g) \
  miesc:latest
```

### Echidna Not Found

**Issue**: `echidna: command not found`

**Solution**: Verify Echidna installation in Dockerfile
```dockerfile
RUN wget https://github.com/crytic/echidna/releases/download/v2.2.4/echidna-2.2.4-Linux.tar.gz && \
    tar -xzf echidna-2.2.4-Linux.tar.gz && \
    mv echidna /usr/local/bin/ && \
    chmod +x /usr/local/bin/echidna
```

---

## 🚀 CI/CD Integration

### GitHub Actions

```yaml
name: Docker Test
on: [push, pull_request]

jobs:
  docker-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build Docker image
        run: docker build -t miesc:ci .

      - name: Run verification
        run: docker run --rm miesc:ci python3 scripts/verify_installation.py

      - name: Run tests
        run: docker run --rm miesc:ci python3 scripts/run_regression_tests.py
```

### GitLab CI

```yaml
docker-test:
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker build -t miesc:ci .
    - docker run --rm miesc:ci python3 scripts/verify_installation.py
    - docker run --rm miesc:ci python3 scripts/run_regression_tests.py
```

---

## 📚 Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [MIESC Main Documentation](../README.md)
- [Installation Troubleshooting](./INSTALLATION.md)

---

## 🤝 Contributing

If you improve the Dockerfile or add new tools, please:

1. Test with `./scripts/docker_test.sh`
2. Update this documentation
3. Submit a pull request

See [CONTRIBUTING.md](../CONTRIBUTING.md) for details.

---

**Last Updated**: October 2024
**Docker Version**: 2.2.0
**Maintainer**: Fernando Boiero (fboiero@frvm.utn.edu.ar)
