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

## 🚀 Installation

```bash
# Clone repo
git clone https://github.com/fboiero/xaudit.git
cd xaudit

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
