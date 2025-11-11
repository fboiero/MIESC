# MIESC v3.3.0 - Docker Deployment Guide

**Multi-layer Intelligent Evaluation for Smart Contracts**

Complete guide for deploying MIESC in Docker containers for reproducible, isolated security analysis.

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Quick Start](#quick-start)
4. [Docker Files Reference](#docker-files-reference)
5. [Usage Examples](#usage-examples)
6. [Deployment Methods](#deployment-methods)
7. [Configuration](#configuration)
8. [Troubleshooting](#troubleshooting)
9. [Performance Optimization](#performance-optimization)
10. [Security Considerations](#security-considerations)

---

## Overview

This Docker deployment provides a complete, self-contained environment for MIESC with:

- **Python 3.11** runtime
- **Security Tools**: Slither, Mythril, Manticore, Aderyn
- **Blockchain Tools**: Foundry (forge, anvil, cast, chisel), Solc compiler
- **All Dependencies**: Pre-installed and configured
- **Multi-stage Build**: Optimized image size
- **Non-root User**: Enhanced security
- **Health Checks**: Container monitoring

### Included Tools

| Tool | Version | Purpose |
|------|---------|---------|
| Slither | ≥0.10.0 | Static analysis |
| Mythril | ≥0.24.0 | Symbolic execution |
| Manticore | Latest | Deep symbolic execution |
| Aderyn | Latest | Rust-based analyzer |
| Foundry | Latest | Solidity development framework |
| solc | 0.8.0, 0.8.17, 0.8.20 | Solidity compiler |

---

## Prerequisites

### System Requirements

- **OS**: Linux, macOS, or Windows with WSL2
- **RAM**: Minimum 4GB, recommended 8GB+
- **Disk**: 5GB free space for image and containers
- **CPU**: 2+ cores recommended

### Required Software

1. **Docker** (version 20.10+)
   ```bash
   # Check Docker version
   docker --version
   ```

2. **Docker Compose** (version 1.29+ or 2.0+)
   ```bash
   # Check Docker Compose version
   docker-compose --version
   ```

### Installation

#### macOS
```bash
# Install Docker Desktop
brew install --cask docker

# Or download from: https://www.docker.com/products/docker-desktop
```

#### Linux
```bash
# Install Docker Engine
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

#### Windows
- Install Docker Desktop for Windows
- Enable WSL2 backend
- Download from: https://www.docker.com/products/docker-desktop

---

## Quick Start

### Method 1: Using Build Script (Recommended)

```bash
# 1. Start Docker (if not running)
open -a Docker  # macOS
# or: sudo systemctl start docker  # Linux

# 2. Build the image
chmod +x docker-build.sh
./docker-build.sh

# 3. Run tests
chmod +x docker-run.sh
./docker-run.sh test

# 4. Interactive shell
./docker-run.sh shell
```

### Method 2: Using Docker Compose

```bash
# Build and run tests
docker-compose up --build

# Run specific service
docker-compose --profile api up miesc-api

# Interactive shell
docker-compose --profile dev run miesc-shell
```

### Method 3: Manual Docker Commands

```bash
# Build image
docker build -t miesc:3.3.0 .

# Run tests
docker run --rm miesc:3.3.0

# Interactive shell
docker run --rm -it miesc:3.3.0 /bin/bash
```

---

## Docker Files Reference

### 1. Dockerfile

Multi-stage build configuration:

**Stage 1 (Builder)**:
- Installs Rust (for Aderyn)
- Installs Foundry (solc, forge, etc.)
- Compiles Aderyn from source

**Stage 2 (Runtime)**:
- Python 3.11 slim base
- Copies binaries from builder
- Installs Python dependencies
- Creates non-root user
- Sets up health checks

**Key Features**:
- Optimized layer caching
- Minimal attack surface
- Non-root execution
- Health monitoring

### 2. docker-compose.yml

Service definitions:

| Service | Purpose | Profile | Port |
|---------|---------|---------|------|
| `miesc` | Default (runs tests) | default | - |
| `miesc-test` | Test suite | test | - |
| `miesc-api` | FastAPI server | api | 8000 |
| `miesc-shell` | Interactive shell | dev | - |
| `miesc-analyzer` | Contract analyzer | analyze | - |

### 3. .dockerignore

Excludes from build context:
- Python cache (`__pycache__`, `*.pyc`)
- Virtual environments
- Test artifacts
- IDE files
- Git files
- Documentation builds

### 4. Scripts

**docker-build.sh**:
- Builds Docker image
- Tags as `miesc:3.3.0` and `miesc:latest`
- Enables BuildKit caching
- Logs build output
- Displays next steps

**docker-run.sh**:
- Simplified container execution
- Modes: test, api, shell, analyze, version
- Automatic image detection
- Error handling

---

## Usage Examples

### Running Tests

```bash
# All tests
./docker-run.sh test

# Using Docker Compose
docker-compose run miesc-test

# Specific test module
docker run --rm miesc:3.3.0 \
  python -m pytest tests/mcp/ -v
```

### Starting API Server

```bash
# Using run script
./docker-run.sh api

# Using Docker Compose
docker-compose --profile api up miesc-api

# Access at: http://localhost:8000
# API docs at: http://localhost:8000/docs
```

### Interactive Development

```bash
# Using run script
./docker-run.sh shell

# Using Docker Compose
docker-compose --profile dev run miesc-shell

# Inside container:
# python -m pytest tests/
# python -m src.cli.miesc_cli --help
```

### Analyzing Smart Contracts

```bash
# Analyze a contract
./docker-run.sh analyze /app/contracts/MyToken.sol

# Using Docker Compose
CONTRACT_PATH=/app/contracts/MyToken.sol \
  docker-compose --profile analyze run miesc-analyzer

# With volume mount
docker run --rm \
  -v "$(pwd)/contracts:/app/contracts:ro" \
  miesc:3.3.0 \
  python -m src.cli.miesc_cli analyze /app/contracts/MyToken.sol
```

### Checking Tool Versions

```bash
# Using run script
./docker-run.sh version

# Manual check
docker run --rm miesc:3.3.0 \
  sh -c "slither --version && myth version && aderyn --version"
```

---

## Deployment Methods

### Development Deployment

For local development with hot-reload:

```yaml
# docker-compose.override.yml
version: '3.8'
services:
  miesc-api:
    volumes:
      - ./src:/app/src  # Hot-reload source code
      - ./tests:/app/tests
    command: uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload
```

```bash
docker-compose --profile api up
```

### Production Deployment

For production use:

```bash
# Build production image
docker build -t miesc:3.3.0-prod \
  --build-arg BUILDKIT_INLINE_CACHE=1 \
  .

# Run without development volumes
docker run -d \
  --name miesc-api-prod \
  -p 8000:8000 \
  --restart unless-stopped \
  --memory 2g \
  --cpus 2 \
  miesc:3.3.0-prod
```

### CI/CD Integration

#### GitHub Actions

```yaml
# .github/workflows/docker.yml
name: Docker Build and Test

on: [push, pull_request]

jobs:
  docker-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build Docker image
        run: docker build -t miesc:test .

      - name: Run tests in Docker
        run: docker run --rm miesc:test python -m pytest tests/ -v
```

#### GitLab CI

```yaml
# .gitlab-ci.yml
docker-build:
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker build -t miesc:$CI_COMMIT_SHA .
    - docker run --rm miesc:$CI_COMMIT_SHA python -m pytest tests/
```

---

## Configuration

### Environment Variables

```bash
# In docker-compose.yml or docker run -e
MIESC_VERSION=3.3.0          # MIESC version
MIESC_ENV=docker             # Environment (docker/dev/prod)
PYTHONUNBUFFERED=1           # Real-time output
CONTRACT_PATH=/app/contracts # Contract directory
```

### Volume Mounts

```bash
# Analysis results
docker run --rm \
  -v miesc-data:/data \
  miesc:3.3.0

# Smart contracts
docker run --rm \
  -v "$(pwd)/contracts:/app/contracts:ro" \
  miesc:3.3.0

# Persistent cache
docker run --rm \
  -v miesc-cache:/home/miesc/.cache \
  miesc:3.3.0
```

### Resource Limits

```bash
# Memory and CPU limits
docker run --rm \
  --memory=2g \
  --memory-swap=2g \
  --cpus=2 \
  miesc:3.3.0

# In docker-compose.yml
services:
  miesc:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '1'
          memory: 1G
```

---

## Troubleshooting

### Docker Daemon Not Running

**Error**: `Cannot connect to the Docker daemon`

**Solution**:
```bash
# macOS
open -a Docker

# Linux
sudo systemctl start docker
sudo systemctl enable docker

# Verify
docker info
```

### Build Failures

**Error**: Rust installation fails

**Solution**:
```bash
# Clean build cache
docker system prune -a

# Rebuild without cache
docker build --no-cache -t miesc:3.3.0 .
```

### Permission Denied

**Error**: Permission denied in container

**Solution**:
```bash
# Check file ownership
docker run --rm miesc:3.3.0 ls -la /app

# Run as root (debugging only)
docker run --rm --user root miesc:3.3.0 /bin/bash
```

### Out of Memory

**Error**: Container killed due to OOM

**Solution**:
```bash
# Increase memory limit
docker run --rm --memory=4g miesc:3.3.0

# Check Docker resources
docker info | grep -i memory
```

### Network Issues

**Error**: Cannot pull base images

**Solution**:
```bash
# Use Docker Hub mirror
# In Dockerfile:
FROM --platform=linux/amd64 python:3.11-slim-bookworm

# Configure Docker daemon with DNS
# /etc/docker/daemon.json
{
  "dns": ["8.8.8.8", "8.8.4.4"]
}
```

---

## Performance Optimization

### Build Performance

```bash
# Enable BuildKit (faster builds)
export DOCKER_BUILDKIT=1

# Multi-core builds
docker build --cpuset-cpus="0-3" -t miesc:3.3.0 .

# Cache from registry
docker build \
  --cache-from miesc:3.3.0 \
  --build-arg BUILDKIT_INLINE_CACHE=1 \
  -t miesc:3.3.0 .
```

### Runtime Performance

```bash
# Allocate more resources
docker run --rm \
  --memory=4g \
  --cpus=4 \
  --shm-size=1g \
  miesc:3.3.0

# Use tmpfs for temp files
docker run --rm \
  --tmpfs /tmp:rw,size=1g \
  miesc:3.3.0
```

### Image Size Reduction

Current image size: ~1.5GB (optimized)

Further optimization:
```dockerfile
# Use multi-stage builds (already implemented)
# Remove build dependencies in final stage
# Use .dockerignore effectively
# Combine RUN commands
```

---

## Security Considerations

### Best Practices

1. **Non-root User**: Container runs as `miesc` (UID 1000)
   ```bash
   # Verify
   docker run --rm miesc:3.3.0 whoami
   # Output: miesc
   ```

2. **Read-only Filesystems**: Mount contracts as read-only
   ```bash
   docker run --rm \
     -v "$(pwd)/contracts:/app/contracts:ro" \
     miesc:3.3.0
   ```

3. **Resource Limits**: Prevent DoS attacks
   ```bash
   docker run --rm \
     --memory=2g \
     --cpus=2 \
     --pids-limit=100 \
     miesc:3.3.0
   ```

4. **Network Isolation**: Use custom networks
   ```bash
   docker network create miesc-network
   docker run --rm --network miesc-network miesc:3.3.0
   ```

5. **Secrets Management**: Never commit secrets
   ```bash
   # Use Docker secrets
   docker run --rm \
     --env-file .env.secure \
     miesc:3.3.0
   ```

### Scanning for Vulnerabilities

```bash
# Scan image with Docker Scout
docker scout cves miesc:3.3.0

# Scan with Trivy
trivy image miesc:3.3.0

# Scan with Grype
grype miesc:3.3.0
```

---

## Advanced Topics

### Custom Solc Versions

```bash
# Inside container
docker run --rm -it miesc:3.3.0 /bin/bash

# Install additional solc version
solc-select install 0.7.6
solc-select use 0.7.6
```

### Persistent Analysis Cache

```bash
# Create volume for Slither cache
docker volume create slither-cache

# Mount in container
docker run --rm \
  -v slither-cache:/home/miesc/.slither \
  miesc:3.3.0
```

### Integration with External Services

```bash
# Connect to external blockchain node
docker run --rm \
  --network host \
  -e RPC_URL=http://localhost:8545 \
  miesc:3.3.0
```

---

## Maintenance

### Updating the Image

```bash
# Pull latest changes
git pull origin main

# Rebuild image
./docker-build.sh

# Verify version
./docker-run.sh version
```

### Cleaning Up

```bash
# Remove containers
docker container prune

# Remove images
docker image prune -a

# Remove volumes
docker volume prune

# Full cleanup
docker system prune -a --volumes
```

### Monitoring

```bash
# Container stats
docker stats miesc-api

# Container logs
docker logs -f miesc-api

# Health check
docker inspect --format='{{.State.Health.Status}}' miesc-api
```

---

## Support

### Getting Help

1. **Documentation**: https://fboiero.github.io/MIESC
2. **Issues**: https://github.com/fboiero/MIESC/issues
3. **Docker Logs**: Check `/tmp/docker_build_v3.log`

### Reporting Issues

When reporting Docker-related issues, include:
```bash
# System information
docker version
docker info
uname -a

# Build logs
cat /tmp/docker_build_v3.log

# Runtime logs
docker logs <container-name>
```

---

## Changelog

### v3.3.0 (November 8, 2025)

- ✅ Initial Docker deployment
- ✅ Multi-stage build optimization
- ✅ Complete tool stack (Slither, Mythril, Manticore, Aderyn)
- ✅ Docker Compose configuration
- ✅ Build and run scripts
- ✅ Health checks
- ✅ Non-root user security
- ✅ Comprehensive documentation

---

**Generated**: November 8, 2025
**Author**: Fernando Boiero <fboiero@frvm.utn.edu.ar>
**Version**: MIESC v3.3.0
**License**: AGPL v3
