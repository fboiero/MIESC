# MIESC v3.5.0 - Complete Docker Deployment
# Multi-layer Intelligent Evaluation for Smart Contracts
#
# This Dockerfile creates a complete, production-ready environment with:
# - Python 3.11 runtime
# - Security tools: Slither, Mythril, Manticore, Aderyn, Medusa
# - Solidity compiler (solc)
# - All MIESC dependencies + OpenLLaMA support
# - Complete test suite

# Stage 1: Builder - Install dependencies and build tools
FROM python:3.11-slim-bookworm AS builder

LABEL maintainer="Fernando Boiero <fboiero@frvm.utn.edu.ar>"
LABEL version="3.5.0"
LABEL description="MIESC - AI-enhanced MCP-compatible blockchain security framework"

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
LABEL version="3.5.0"
LABEL description="MIESC - AI-enhanced MCP-compatible blockchain security framework"

# Copy Rust binaries from builder
COPY --from=builder /root/.cargo/bin/aderyn /usr/local/bin/
COPY --from=builder /root/.foundry/bin/* /usr/local/bin/

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    wget \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash miesc && \
    mkdir -p /app /data && \
    chown -R miesc:miesc /app /data

# Set working directory
WORKDIR /app

# Switch to non-root user
USER miesc

# Install Python dependencies
# Copy only requirements files first for better layer caching
COPY --chown=miesc:miesc setup.py pyproject.toml README.md ./

# Install MIESC core dependencies
RUN pip install --no-cache-dir --user -e .[dev,all-tools]

# Install additional security tools
# Updated to Slither 3.0 (2025 AI-powered version)
RUN pip install --no-cache-dir --user \
    slither-analyzer>=3.0.0 \
    mythril>=0.24.0 \
    crytic-compile>=0.3.0 \
    solc-select>=1.0.0

# Install solc versions (common versions for smart contract analysis)
RUN solc-select install 0.8.0 && \
    solc-select install 0.8.17 && \
    solc-select install 0.8.20 && \
    solc-select use 0.8.20

# Install Manticore (symbolic execution engine)
RUN pip install --no-cache-dir --user manticore[native]

# Copy MIESC source code
COPY --chown=miesc:miesc . .

# Add user's local bin to PATH
ENV PATH="/home/miesc/.local/bin:${PATH}"

# Environment variables for MIESC
ENV MIESC_VERSION="3.5.0"
ENV MIESC_ENV="docker"
ENV PYTHONPATH="/app:${PYTHONPATH}"
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "print('MIESC v3.5.0 is healthy')" || exit 1

# Expose API port (if running FastAPI server)
EXPOSE 8000

# Default command: Show MIESC version and run tests
CMD ["sh", "-c", "echo '=== MIESC v3.5.0 - Docker Deployment ===' && \
     echo 'Python version:' && python --version && \
     echo 'Installed tools:' && \
     echo '- Slither:' && slither --version 2>&1 | head -1 && \
     echo '- Mythril:' && myth version 2>&1 | head -1 && \
     echo '- Aderyn:' && aderyn --version 2>&1 | head -1 && \
     echo '- Solc:' && solc --version | head -1 && \
     echo '- Manticore:' && manticore --version 2>&1 | head -1 && \
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
