# MIESC - Multi-Agent Security Framework for Smart Contracts
# Dockerfile for clean environment testing and deployment

FROM ubuntu:22.04

# Prevent interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    # Python and pip
    python3.9 \
    python3-pip \
    python3-venv \
    # Node.js and npm (for Solhint)
    nodejs \
    npm \
    # Foundry dependencies
    curl \
    git \
    build-essential \
    # CMake for z3-solver
    cmake \
    # Solidity compiler
    software-properties-common \
    # Additional utilities
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Rust via rustup (for Aderyn - requires recent Cargo)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install newer CMake from Kitware repository (for z3-solver)
RUN wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - | tee /usr/share/keyrings/kitware-archive-keyring.gpg >/dev/null && \
    echo 'deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ jammy main' | tee /etc/apt/sources.list.d/kitware.list >/dev/null && \
    apt-get update && \
    apt-get install -y cmake && \
    rm -rf /var/lib/apt/lists/*

# Install Foundry (forge, cast, anvil)
RUN curl -L https://foundry.paradigm.xyz | bash && \
    /root/.foundry/bin/foundryup

# Add Foundry to PATH
ENV PATH="/root/.foundry/bin:${PATH}"

# Install Solidity compiler (solc) - ARM64 compatible via solc-select
RUN pip3 install solc-select && \
    solc-select install 0.8.20 && \
    solc-select use 0.8.20

# Install global Node.js tools
RUN npm install -g solhint

# Install Rust-based tools (Aderyn for ultra-fast static analysis)
# Note: This step takes ~5-10 minutes on first build
RUN cargo install aderyn --version 0.6.4

# Copy requirements files first (for layer caching)
COPY requirements_core.txt requirements.txt ./

# Install Python dependencies
RUN pip3 install --upgrade pip && \
    pip3 install --no-cache-dir -r requirements_core.txt && \
    pip3 install --no-cache-dir slither-analyzer mythril manticore eth-wake

# Install Echidna (property-based fuzzer)
RUN wget https://github.com/crytic/echidna/releases/download/v2.2.4/echidna-2.2.4-Linux.tar.gz && \
    tar -xzf echidna-2.2.4-Linux.tar.gz && \
    mv echidna /usr/local/bin/ && \
    rm echidna-2.2.4-Linux.tar.gz

# Copy the rest of the application
COPY . .

# Create outputs directory
RUN mkdir -p outputs

# Run verification script on build
RUN python3 scripts/verify_installation.py || echo "Some optional tools not installed"

# Set default command
CMD ["python3", "scripts/verify_installation.py"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import sys; sys.exit(0)"

# Metadata
LABEL maintainer="Fernando Boiero <fboiero@frvm.utn.edu.ar>"
LABEL version="2.2.0"
LABEL description="MIESC - Multi-Agent Integrated Security Assessment Framework for Smart Contracts"
LABEL org.opencontainers.image.source="https://github.com/fboiero/MIESC"
