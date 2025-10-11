# 🔍 Xaudit: Smart Contract Audit Tool with LLMs

**Xaudit** represents a novel approach to Ethereum smart contract security auditing that synthesizes traditional static analysis methodologies with state-of-the-art artificial intelligence techniques. This framework addresses the growing complexity of decentralized application security by leveraging the complementary strengths of established vulnerability detection tools (Slither, Mythril) and advanced Large Language Models (GPT-4, Llama 2).

The primary objective of this research tool is to generate comprehensive, AI-augmented security audit reports that combine the precision of automated static analysis with the contextual reasoning capabilities of large-scale language models. By bridging the gap between rule-based security checking and AI-driven code comprehension, Xaudit facilitates a more thorough examination of smart contract vulnerabilities, particularly those requiring semantic understanding of business logic and contract interactions within the Ethereum ecosystem.

---

## ✨ Key Features

- **Multi-Tool Integration**  
  Combines results from industry-recognized security tools (e.g., **Slither**, **Mythril**).

- **AI-Powered Analysis**  
  Uses LLMs such as **GPT-4**, **Llama 2**, and **GPTLens** to detect vulnerabilities and provide deeper insights.

- **Flexible Configuration**  
  Choose which tools and models to enable through a simple config file.

- **Customizable Reports**  
  Generate detailed **PDF** and **TXT reports**, including raw tool outputs, summaries, and conclusions.

- **Unit Test Suggestions** *(optional)*  
  Automatically generate suggested unit tests to validate contracts.

- **Report Sections Control**  
  Decide whether to include introduction, tools output, summaries, unit test suggestions, or conclusions.

---

## ⚙️ How It Works

1. The main script `main.py` orchestrates the audit.  
2. Reads the **Solidity contract** and its version.  
3. Sends it to the enabled tools and LLMs defined in `config.py`.  
4. Collects and merges outputs.  
5. Generates:
   - Raw outputs (`.txt`)
   - A consolidated **summary**
   - An optional **PDF report**

---

## 📦 Requirements

- Python **3.x**
- Project dependencies (`requirements.txt`)
- *(Optional)* GPU with enough VRAM for running LLMs locally

---

## 🚀 Quick Start

### Automated Setup

```bash
# Clone repo
git clone https://github.com/fboiero/xaudit.git
cd xaudit

# Run automated setup
./setup.sh
```

The setup script will:
- Create virtual environment
- Install dependencies
- Generate configuration files
- Create `.env` template

### Manual Installation

```bash
# Create and activate virtual environment
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate

# Install core dependencies (recommended)
pip install -r requirements_minimal.txt

# Or install all dependencies (includes AI/ML tools)
pip install -r requirements.txt
```

### Configuration

1. **Edit `.env` file** and add your OpenAI API key:
```bash
OPENAI_API_KEY=sk-your-key-here
```

2. **Configure tools** in `config.py`:
```python
class ModelConfig:
    use_slither = True    # Fast static analysis
    use_mythril = False   # Symbolic execution (slow)
    use_GPTLens = True    # AI-powered analysis
```

### Run Your First Audit

```bash
# Using the convenience script
./run_audit.sh examples/voting.sol 0.8.0 my_first_audit

# Or directly with Python
python main.py examples/voting.sol my_first_audit
```

Results will be in:
- `output.pdf` - Consolidated PDF report
- `output/my_first_audit/` - Individual tool outputs

---

## 📚 Documentation

- **[Usage Guide](docs/USAGE.md)** - Detailed usage examples and workflows
- **[Architecture](docs/ARCHITECTURE.md)** - System design and extension points
- **Examples** - See `examples/` directory for sample contracts

---

## 🔬 Research & Academic Use

This tool is designed for academic research and professional security auditing. If you use Xaudit in your research, please cite:

```bibtex
@software{xaudit2024,
  author = {Boiero, Fernando},
  title = {Xaudit: AI-Augmented Smart Contract Security Auditing},
  year = {2024},
  url = {https://github.com/fboiero/xaudit}
}
```

---

## 🤝 Contributing

Contributions are welcome! Areas for contribution:
- New analysis tools integration
- Improved AI prompts
- Additional report formats
- Performance optimizations
- Documentation improvements

---

## 📄 License

GPL-3.0 License - See [LICENSE](LICENSE) for details.

---

## ⚠️ Disclaimer

Xaudit is a research tool to assist in security auditing. It does not guarantee the absence of vulnerabilities. Always:
- Manually review all findings
- Conduct comprehensive testing
- Engage professional auditors for production contracts
- Never rely solely on automated tools

---

## 📞 Contact & Support

- **Issues**: [GitHub Issues](https://github.com/fboiero/xaudit/issues)
- **Discussions**: [GitHub Discussions](https://github.com/fboiero/xaudit/discussions)
- **Author**: Fernando Boiero (fboiero@frvm.utn.edu.ar)
