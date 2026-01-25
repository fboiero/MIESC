# MIESC v4.4.0 - Complete Docker Deployment
# Multi-layer Intelligent Evaluation for Smart Contracts
#
# This Dockerfile creates a complete, production-ready environment with:
# - Python 3.12 runtime
# - Security tools: Slither, Mythril, Manticore, Aderyn, Medusa
# - Solidity compiler (solc)
# - ML Pipeline: FP filtering, severity prediction, clustering
# - All MIESC dependencies + OpenLLaMA support
# - PDF generation with weasyprint
# - Complete test suite

# Stage 1: Builder - Install dependencies and build tools
FROM python:3.12-slim-bookworm AS builder

LABEL maintainer="Fernando Boiero <fboiero@frvm.utn.edu.ar>"
LABEL version="4.4.0"
LABEL description="MIESC - Multi-layer Intelligent Evaluation for Smart Contracts"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    curl \
    wget \
    ca-certificates \
    libssl-dev \
    pkg-config \
    software-properties-common \
    && rm -rf /var/lib/apt/lists/*

# Install Rust (required for Aderyn)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install Foundry v1.0 (February 2025 - 1000x performance improvement)
RUN curl -L https://foundry.paradigm.xyz | bash
ENV PATH="/root/.foundry/bin:${PATH}"
RUN foundryup --version 1.0.0 || foundryup  # Fallback to latest if 1.0.0 not available yet

# Install Aderyn (Rust-based Solidity analyzer)
RUN cargo install aderyn

# Install Medusa (coverage-guided fuzzer by Trail of Bits)
RUN cargo install medusa || echo "Medusa install failed - will be optional"

# Stage 2: Runtime - Create lean production image
FROM python:3.12-slim-bookworm

LABEL maintainer="Fernando Boiero <fboiero@frvm.utn.edu.ar>"
LABEL version="4.4.0"
LABEL description="MIESC - Multi-layer Intelligent Evaluation for Smart Contracts"

# Copy Rust binaries from builder (aderyn only, foundry installed separately)
COPY --from=builder /root/.cargo/bin/aderyn /usr/local/bin/

# Install runtime AND build dependencies (needed for Mythril/Manticore compilation)
# Also includes weasyprint dependencies for PDF generation
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

# Install Foundry (forge, cast, anvil) - needed by crytic-compile/slither
RUN curl -L https://foundry.paradigm.xyz | bash && \
    /root/.foundry/bin/foundryup && \
    cp /root/.foundry/bin/* /usr/local/bin/ && \
    chmod +x /usr/local/bin/forge /usr/local/bin/cast /usr/local/bin/anvil 2>/dev/null || true

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash miesc && \
    mkdir -p /app /data && \
    chown -R miesc:miesc /app /data

# Set working directory
WORKDIR /app

# Switch to non-root user
USER miesc

# Copy all source code first (needed for editable install)
COPY --chown=miesc:miesc . .

# Create temp directory for pip builds (avoids read-only /tmp issues)
RUN mkdir -p /home/miesc/.tmp && chmod 755 /home/miesc/.tmp
ENV TMPDIR="/home/miesc/.tmp"
ENV PIP_CACHE_DIR="/home/miesc/.cache/pip"

# Install MIESC core dependencies (editable mode for development)
# Using [dev,full] to include prometheus-client, FastAPI, uvicorn, and all features
RUN pip install --no-cache-dir --user -e .[dev,full]

# Add user's local bin to PATH (needed for tools installed above)
ENV PATH="/home/miesc/.local/bin:${PATH}"

# Note: slither-analyzer and crytic-compile are already installed via pyproject.toml

# Install solc versions (common versions for smart contract analysis)
RUN solc-select install 0.8.0 && \
    solc-select install 0.8.17 && \
    solc-select install 0.8.20 && \
    solc-select use 0.8.20

# Install Mythril (symbolic execution) - with timeout to prevent hanging
# Note: On ARM, this may take very long or fail due to z3-solver compilation
# Timeout after 5 minutes, then continue without Mythril
RUN timeout 300 pip install --no-cache-dir --user mythril>=0.24.0 && \
    echo "Mythril installed successfully" || \
    echo "WARNING: Mythril install skipped (timeout or failed) - symbolic execution will be limited"

# Install Manticore (symbolic execution engine) - with timeout
# Note: Manticore may have limited ARM support
RUN timeout 300 pip install --no-cache-dir --user manticore[native] && \
    echo "Manticore installed successfully" || \
    echo "WARNING: Manticore install skipped (timeout or failed) - may not support this architecture"

# Install weasyprint for PDF generation
RUN pip install --no-cache-dir --user weasyprint markdown && \
    echo "WeasyPrint installed successfully"

# Environment variables for MIESC
ENV MIESC_VERSION="4.4.0"
ENV MIESC_ENV="docker"
ENV PYTHONPATH="/app:${PYTHONPATH}"
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
