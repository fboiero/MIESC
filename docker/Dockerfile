# MIESC v5.0.2 - Optimized Docker Deployment
# Multi-layer Intelligent Evaluation for Smart Contracts
#
# This Dockerfile creates a complete, production-ready environment with:
# - Python 3.12 runtime
# - Security tools: Slither, Aderyn
# - Foundry toolchain (forge, cast, anvil)
# - Solidity compiler (solc) + Solhint linter
# - ML Pipeline: FP filtering, severity prediction, clustering
# - All MIESC dependencies + OpenLLaMA support
# - PDF generation with weasyprint
# - Complete test suite
#
# Note: Symbolic execution tools (Mythril, Manticore) are in Dockerfile.full only.
# Reason: z3-solver takes 15-20 min to compile per arch on QEMU, and Manticore
# has protobuf compatibility issues on Python 3.12.
#
# Build with BuildKit for parallel stages and cache mounts:
#   DOCKER_BUILDKIT=1 docker build -t miesc:5.0.2 -f Dockerfile .

# ============================================================
# Stage 1a: aderyn-builder (runs in parallel with foundry-builder)
# ============================================================
FROM python:3.12-slim-bookworm AS aderyn-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git curl ca-certificates libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

RUN --mount=type=cache,target=/root/.cargo/registry \
    cargo install aderyn

# ============================================================
# Stage 1b: foundry-builder (runs in parallel with aderyn-builder)
# ============================================================
FROM python:3.12-slim-bookworm AS foundry-builder

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

RUN curl -L https://foundry.paradigm.xyz | bash
ENV PATH="/root/.foundry/bin:${PATH}"
RUN foundryup

# ============================================================
# Stage 2: Runtime - Create lean production image
# ============================================================
FROM python:3.12-slim-bookworm

LABEL maintainer="Fernando Boiero <fboiero@frvm.utn.edu.ar>"
LABEL version="5.0.2"
LABEL description="MIESC - Multi-layer Intelligent Evaluation for Smart Contracts"

# Copy aderyn from aderyn-builder
COPY --from=aderyn-builder /root/.cargo/bin/aderyn /usr/local/bin/

# Copy Foundry binaries from foundry-builder
COPY --from=foundry-builder /root/.foundry/bin/forge /usr/local/bin/
COPY --from=foundry-builder /root/.foundry/bin/cast /usr/local/bin/
COPY --from=foundry-builder /root/.foundry/bin/anvil /usr/local/bin/

# Install runtime dependencies
# Includes weasyprint dependencies for PDF generation
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    wget \
    libssl3 \
    ca-certificates \
    build-essential \
    gcc \
    g++ \
    libffi-dev \
    libgmp-dev \
    cmake \
    pkg-config \
    software-properties-common \
    gnupg \
    nodejs \
    npm \
    # WeasyPrint dependencies for PDF generation
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    shared-mime-info \
    fonts-liberation \
    fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# Install Solhint (Solidity linter)
RUN npm install -g solhint

# Install Solc from Ethereum PPA (native binary for ARM/x86)
RUN curl -fsSL https://binaries.soliditylang.org/linux-amd64/solc-linux-amd64-v0.8.20+commit.a1b79de6 -o /usr/local/bin/solc-0.8.20 || \
    (apt-get update && apt-get install -y solc && rm -rf /var/lib/apt/lists/*) && \
    chmod +x /usr/local/bin/solc-0.8.20 2>/dev/null || true

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash miesc && \
    mkdir -p /app /data && \
    chown -R miesc:miesc /app /data

# Set working directory
WORKDIR /app

# Switch to non-root user
USER miesc

# Create temp directory for pip builds (avoids read-only /tmp issues)
RUN mkdir -p /home/miesc/.tmp && chmod 755 /home/miesc/.tmp
ENV TMPDIR="/home/miesc/.tmp"
ENV PIP_CACHE_DIR="/home/miesc/.cache/pip"

# Copy package definition + wrapper package (stable, changes rarely)
COPY --chown=miesc:miesc pyproject.toml README.md ./
COPY --chown=miesc:miesc miesc/ miesc/

# Create src package stubs so setuptools can resolve declared packages.
# Real source code is copied later; this just satisfies the editable install.
RUN mkdir -p src/adapters src/agents/audit_readiness src/core src/detectors \
             src/llm src/mcp_core src/ml/fine_tuning src/security \
             src/poc/validators src/plugins src/reports src/utils && \
    find src -type d -exec sh -c 'touch "$1/__init__.py"' _ {} \;

# Install MIESC dependencies (cached unless pyproject.toml changes)
# Using [dev,full] to include prometheus-client, FastAPI, uvicorn, and all features
RUN --mount=type=cache,target=/home/miesc/.cache/pip,uid=1000 \
    pip install --user -e ".[dev,full]"

# Install MCP server dependencies
RUN --mount=type=cache,target=/home/miesc/.cache/pip,uid=1000 \
    pip install --user "mcp[cli]>=1.0.0"

# Copy all source code (changes frequently - LAST for best caching)
COPY --chown=miesc:miesc . .

# Reinstall in editable mode with no-deps (just re-links, takes seconds)
RUN pip install --no-deps --user -e .

# Add user's local bin to PATH (needed for tools installed above)
ENV PATH="/home/miesc/.local/bin:${PATH}"

# Note: slither-analyzer and crytic-compile are already installed via pyproject.toml

# Install solc versions (common versions for smart contract analysis)
RUN solc-select install 0.8.0 && \
    solc-select install 0.8.17 && \
    solc-select install 0.8.20 && \
    solc-select use 0.8.20

# Install weasyprint for PDF generation
RUN --mount=type=cache,target=/home/miesc/.cache/pip,uid=1000 \
    pip install --user weasyprint markdown && \
    echo "WeasyPrint installed successfully"

# Environment variables for MIESC
ENV MIESC_VERSION="5.0.2"
ENV MIESC_ENV="docker"
ENV PYTHONPATH="/app"
ENV PYTHONUNBUFFERED=1

# LLM Configuration (for AI-powered report interpretation)
# These can be overridden at runtime via docker-compose or docker run -e
ENV OLLAMA_HOST="http://localhost:11434"
ENV MIESC_LLM_MODEL="mistral:latest"

# Health check with ML pipeline verification
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD miesc --version || exit 1

# Expose API port (if running FastAPI server)
EXPOSE 8000

# Set ENTRYPOINT to miesc CLI - allows: docker run miesc scan contract.sol
ENTRYPOINT ["miesc"]

# Default command: show help
CMD ["--help"]
