# MIESC Web Demo

**Interactive Smart Contract Security Auditor**

An intuitive web interface for the MIESC framework that enables security researchers, developers, and auditors to analyze Solidity smart contracts through a modern, user-friendly interface.

---

## 🚀 Features

- **📝 Multiple Input Methods**
  - Paste Solidity code directly
  - Upload `.sol` files
  - Load pre-configured vulnerable examples

- **🛠️ Multi-Tool Analysis**
  - **Slither**: Static analysis with 90+ detectors
  - **Mythril**: Symbolic execution & taint analysis
  - **Aderyn**: Rust-based static analyzer

- **🤖 AI-Powered Features**
  - GPT-4o correlation to reduce false positives (43% reduction)
  - Intelligent finding prioritization
  - Natural language explanations

- **📊 Rich Visualization**
  - Interactive severity distribution charts
  - Real-time progress tracking
  - Comprehensive findings dashboard

- **⚖️ Risk Assessment**
  - Multi-dimensional risk scoring
  - CVSS-based severity calculation
  - Exploitability analysis

- **📋 Compliance Mapping**
  - NIST SSDF controls
  - ISO 27001 mappings
  - OWASP SAMM levels

- **💾 Export Capabilities**
  - JSON reports with full metadata
  - Markdown-formatted summaries
  - Downloadable audit reports

---

## 📋 Prerequisites

### System Requirements

- **Python**: 3.9 or higher
- **Memory**: Minimum 4GB RAM (8GB recommended)
- **Storage**: 2GB free space for dependencies

### Required Tools

Install the security analysis tools used by MIESC:

```bash
# Slither (Python-based)
pip install slither-analyzer

# Mythril (Python-based)
pip install mythril

# Aderyn (Rust-based - install via Cargo)
cargo install aderyn
# Or download binary from: https://github.com/Cyfrin/aderyn/releases
```

---

## 🔧 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/fboiero/MIESC.git
cd MIESC
```

### 2. Install Dependencies

```bash
# Core dependencies
pip install -r requirements.txt

# Webapp dependencies
pip install -r requirements-webapp.txt

# Or install all at once
make install-webapp
```

### 3. Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit .env and add your API keys (optional, for AI features)
# OPENAI_API_KEY=your_key_here
# ANTHROPIC_API_KEY=your_key_here (optional)
```

---

## 🚀 Quick Start

### Launch the Web Demo

```bash
# Using the Makefile (recommended)
make webapp

# Or run Streamlit directly
streamlit run webapp/app.py

# With custom port
streamlit run webapp/app.py --server.port 8501
```

The application will automatically open in your default browser at:
- **Local URL**: http://localhost:8501
- **Network URL**: http://<your-ip>:8501

### Using Docker

```bash
# Build the webapp image
docker build -t miesc-webapp -f docker/Dockerfile.webapp .

# Run the container
docker run -p 8501:8501 -e OPENAI_API_KEY=your_key miesc-webapp

# Access at http://localhost:8501
```

---

## 📖 Usage Guide

### Step 1: Input Your Contract

Choose your preferred input method:

1. **Paste Code**: Copy-paste your Solidity contract
2. **Upload File**: Select a `.sol` file from your filesystem
3. **Load Example**: Test with pre-configured vulnerable contracts

### Step 2: Configure Analysis

In the sidebar, customize your analysis:

- **🛠️ Security Tools**: Select which tools to run (Slither, Mythril, Aderyn)
- **🤖 AI Features**: Enable AI correlation for smarter results
- **⚖️ Risk Scoring**: Calculate comprehensive risk scores
- **📋 Policy Mapping**: Map findings to compliance frameworks
- **⏱️ Timeout**: Adjust analysis timeout (60-600 seconds)

### Step 3: Run Analysis

Click **🚀 Run Security Audit** to start the analysis.

You'll see real-time progress through 4 phases:
1. Multi-tool security scanning
2. AI correlation (if enabled)
3. Risk scoring (if enabled)
4. Policy mapping (if enabled)

### Step 4: Review Results

The dashboard displays:

- **Summary Metrics**: Total findings, critical/high/medium/low counts, risk score
- **Severity Chart**: Interactive visualization of finding distribution
- **Detailed Findings**: Expandable cards with:
  - Vulnerability description
  - Affected code location
  - AI analysis and recommendations
  - Risk assessment
  - Compliance mappings

### Step 5: Export Report

Download your audit results:

- **📥 JSON Report**: Complete data with metadata for programmatic use
- **📥 Markdown Report**: Human-readable summary for documentation

---

## 🎯 Example Contracts

The webapp includes three pre-loaded vulnerable examples:

### 1. Reentrancy Vulnerability

Classic reentrancy bug where external calls happen before state updates.

**Vulnerability**: State updated after external call
**Severity**: Critical
**Impact**: Loss of all contract funds

### 2. Integer Overflow

Integer overflow in Solidity <0.8.0 without SafeMath.

**Vulnerability**: Unchecked arithmetic operations
**Severity**: High
**Impact**: Token minting, balance manipulation

### 3. Unchecked Call

Low-level call return values not checked.

**Vulnerability**: Ignored call failures
**Severity**: High
**Impact**: Silent failures, fund loss

---

## 🔐 Security & Privacy

### API Key Management

- **Environment Variables**: Store API keys in `.env` file (never commit!)
- **Session Isolation**: Each analysis runs in isolation
- **Temporary Files**: Contracts stored temporarily, deleted after analysis

### Data Privacy

- ✅ **No data collection**: Your contracts are not stored or transmitted
- ✅ **Local processing**: Static analysis runs entirely locally
- ⚠️ **AI features**: If enabled, contract code sent to OpenAI API
  - Only vulnerability snippets, not full contracts
  - Use `--no-ai` flag for fully offline analysis

### Production Deployment

For production deployments:

```bash
# Use HTTPS with SSL certificates
streamlit run webapp/app.py --server.enableCORS false --server.enableXsrfProtection true

# Set authentication (example with streamlit-authenticator)
# See: https://github.com/mkhorasani/Streamlit-Authenticator
```

---

## 🛠️ Troubleshooting

### Common Issues

#### 1. Import Errors

**Error**: `ModuleNotFoundError: No module named 'miesc_core'`

**Solution**:
```bash
# Ensure you're in the MIESC root directory
cd /path/to/MIESC

# Install dependencies
pip install -r requirements.txt

# Run from root directory
streamlit run webapp/app.py
```

#### 2. Tool Not Found

**Error**: `Tool 'slither' not found in PATH`

**Solution**:
```bash
# Install missing tool
pip install slither-analyzer

# Verify installation
which slither
slither --version
```

#### 3. API Key Errors

**Error**: `OpenAI API key not found`

**Solution**:
```bash
# Set environment variable
export OPENAI_API_KEY="your-api-key-here"

# Or add to .env file
echo "OPENAI_API_KEY=your-api-key-here" >> .env
```

#### 4. Port Already in Use

**Error**: `Port 8501 is already in use`

**Solution**:
```bash
# Use a different port
streamlit run webapp/app.py --server.port 8502

# Or kill the existing process
lsof -ti:8501 | xargs kill -9
```

### Performance Optimization

For large contracts or slow analysis:

1. **Increase timeout**: Adjust slider in sidebar (up to 600 seconds)
2. **Disable heavy tools**: Uncheck Mythril if analysis is slow
3. **Run tools separately**: Analyze with one tool at a time
4. **Use Docker**: Container isolation can improve performance

---

## 🧪 Development

### Running in Development Mode

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run with hot-reload
streamlit run webapp/app.py --server.runOnSave true

# Enable debugging
streamlit run webapp/app.py --logger.level debug
```

### Testing

```bash
# Run webapp tests
pytest tests/webapp/ -v

# Test with sample contracts
python -m pytest tests/webapp/test_app.py::test_reentrancy_example
```

### Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines on:
- Code style (Black, Ruff, MyPy)
- Testing requirements
- Pull request process

---

## 📊 Architecture

```
webapp/
├── app.py                  # Main Streamlit application
├── README.md              # This file
├── requirements.txt       # Webapp-specific dependencies
├── components/            # Reusable UI components
│   ├── __init__.py
│   ├── input_panel.py    # Contract input widgets
│   ├── results_panel.py  # Results visualization
│   └── config_panel.py   # Configuration sidebar
├── utils/                # Utility functions
│   ├── __init__.py
│   ├── formatters.py     # Report formatters
│   └── validators.py     # Input validation
└── static/               # Static assets
    ├── logo.png
    ├── screenshots/      # Demo screenshots
    └── styles.css        # Custom CSS
```

---

## 🔗 Related Documentation

- **[Main README](../README.md)**: Overview of MIESC framework
- **[Installation Guide](../docs/02_SETUP_AND_USAGE.md)**: Detailed setup instructions
- **[Demo Guide](../docs/03_DEMO_GUIDE.md)**: CLI demo walkthrough
- **[API Documentation](https://fboiero.github.io/MIESC)**: Complete API reference
- **[Developer Guide](../docs/DEVELOPER_GUIDE.md)**: Architecture and development

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/fboiero/MIESC/issues)
- **Discussions**: [GitHub Discussions](https://github.com/fboiero/MIESC/discussions)
- **Email**: fboiero@frvm.utn.edu.ar

---

## 📄 License

GPL-3.0 License - see [LICENSE](../LICENSE) for details.

---

## 🙏 Acknowledgments

- **Thesis Advisors**: UNDEF - Universidad de la Defensa Nacional
- **Security Tools**: Trail of Bits (Slither), ConsenSys (Mythril), Cyfrin (Aderyn)
- **Framework**: Streamlit for the excellent web framework
- **Community**: OpenZeppelin, Ethereum Foundation, Security Research Community

---

**Built with ❤️ by Fernando Boiero | Master's Thesis in Cyberdefense | UNDEF - IUA Córdoba**
