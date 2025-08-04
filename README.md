# 🔍 Xaudit: Smart Contract Audit Tool with LLMs

**Xaudit** is a security audit tool for blockchain smart contracts that integrates the results of **traditional static analysis tools** with the capabilities of **Large Language Models (LLMs)**.  
The goal is to provide a **comprehensive and consolidated audit report**, combining the strengths of tools like Slither and Mythril with advanced models such as GPT-4 and Llama 2.

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
