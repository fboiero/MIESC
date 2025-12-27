# MIESC v4.0.0 - Complete Docker Deployment
# Multi-layer Intelligent Evaluation for Smart Contracts
#
# This Dockerfile creates a complete, production-ready environment with:
# - Python 3.11 runtime
# - Security tools: Slither, Mythril, Manticore, Aderyn, Medusa
# - Solidity compiler (solc)
# - ML Pipeline: FP filtering, severity prediction, clustering
# - All MIESC dependencies + OpenLLaMA support
# - Complete test suite

# Stage 1: Builder - Install dependencies and build tools
FROM python:3.11-slim-bookworm AS builder

LABEL maintainer="Fernando Boiero <fboiero@frvm.utn.edu.ar>"
LABEL version="4.2.2"
LABEL description="MIESC - ML-enhanced MCP-compatible blockchain security framework"

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
FROM python:3.11-slim-bookworm

LABEL maintainer="Fernando Boiero <fboiero@frvm.utn.edu.ar>"
LABEL version="4.2.2"
LABEL description="MIESC - ML-enhanced MCP-compatible blockchain security framework"

# Copy Rust binaries from builder
COPY --from=builder /root/.cargo/bin/aderyn /usr/local/bin/
COPY --from=builder /root/.foundry/bin/* /usr/local/bin/

# Install runtime AND build dependencies (needed for Mythril/Manticore compilation)
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
    && rm -rf /var/lib/apt/lists/*

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

# Copy all source code first (needed for editable install)
COPY --chown=miesc:miesc . .

# Install MIESC core dependencies (editable mode for development)
RUN pip install --no-cache-dir --user -e .[dev,all-tools]

# Add user's local bin to PATH (needed for tools installed above)
ENV PATH="/home/miesc/.local/bin:${PATH}"

# Note: slither-analyzer and crytic-compile are already installed via pyproject.toml

# Install solc versions (common versions for smart contract analysis)
RUN solc-select install 0.8.0 && \
    solc-select install 0.8.17 && \
    solc-select install 0.8.20 && \
    solc-select use 0.8.20

# Install Mythril (symbolic execution) - with build dependencies available
# Note: On ARM, this may take longer due to compilation
RUN pip install --no-cache-dir --user mythril>=0.24.0 && \
    echo "Mythril installed successfully" || \
    echo "WARNING: Mythril install failed - check build dependencies"

# Install Manticore (symbolic execution engine)
# Note: Manticore may have limited ARM support
RUN pip install --no-cache-dir --user manticore[native] && \
    echo "Manticore installed successfully" || \
    echo "WARNING: Manticore install failed - may not support this architecture"

# Environment variables for MIESC
ENV MIESC_VERSION="4.2.2"
ENV MIESC_ENV="docker"
ENV PYTHONPATH="/app:${PYTHONPATH}"
ENV PYTHONUNBUFFERED=1

# Health check with ML pipeline verification
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "from src.core import get_ml_orchestrator; print('MIESC v4.2.2 ML OK')" || exit 1

# Expose API port (if running FastAPI server)
EXPOSE 8000

# Default command: Show MIESC version and run tests
CMD ["sh", "-c", "echo '=== MIESC v4.2.2 - Docker Deployment ===' && \
     echo 'Python version:' && python --version && \
     echo 'Installed tools:' && \
     echo '- Slither:' && slither --version 2>&1 | head -1 && \
     echo '- Mythril:' && (myth version 2>&1 | head -1 || echo 'Not installed (optional)') && \
     echo '- Aderyn:' && (aderyn --version 2>&1 | head -1 || echo 'Not installed') && \
     echo '- Solc:' && solc --version | head -1 && \
     echo '- Manticore:' && (manticore --version 2>&1 | head -1 || echo 'Not installed (optional)') && \
     echo '' && \
     echo 'Running MIESC test suite...' && \
     python -m pytest tests/ -v --tb=short --maxfail=3"]

# Alternative entry points (uncomment as needed):
# Run API server:
# CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

# Run CLI:
# ENTRYPOINT ["python", "-m", "src.cli.miesc_cli"]

# Interactive shell:
# CMD ["/bin/bash"]
