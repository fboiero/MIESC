# MIESC MCP Setup Guide
## Integrate MIESC with Claude Desktop in 5 Minutes

This guide shows you how to configure MIESC as a Model Context Protocol (MCP) server for Claude Desktop, enabling AI-assisted smart contract security analysis through natural conversation.

---

## 📋 Prerequisites

**Required:**
- Python 3.9+ installed
- Claude Desktop app ([download here](https://claude.ai/download))
- MIESC repository cloned locally
- Basic security tools installed (Slither minimum)

**Recommended:**
- All 15 security tools installed (see [INSTALLATION.md](../README.md#installation))
- Docker installed (for reproducible environment)
- 8GB+ RAM for symbolic execution tools

---

## 🚀 Quick Setup (30 Seconds)

### Step 1: Locate Claude Desktop Config File

**macOS:**
```bash
~/Library/Application Support/Claude/claude_desktop_config.json
```

**Windows:**
```bash
%APPDATA%\Claude\claude_desktop_config.json
```

**Linux:**
```bash
~/.config/Claude/claude_desktop_config.json
```

### Step 2: Edit Configuration

Open the config file and add MIESC as an MCP server:

```json
{
  "mcpServers": {
    "miesc": {
      "command": "python",
      "args": [
        "/absolute/path/to/MIESC/src/mcp/server.py"
      ],
      "env": {
        "PYTHONPATH": "/absolute/path/to/MIESC",
        "MIESC_MODE": "interactive"
      }
    }
  }
}
```

**Important:** Replace `/absolute/path/to/MIESC` with your actual path!

**Example (macOS):**
```json
{
  "mcpServers": {
    "miesc": {
      "command": "python",
      "args": [
        "/Users/fboiero/Documents/GitHub/MIESC/src/mcp/server.py"
      ],
      "env": {
        "PYTHONPATH": "/Users/fboiero/Documents/GitHub/MIESC"
      }
    }
  }
}
```

**Example (Windows):**
```json
{
  "mcpServers": {
    "miesc": {
      "command": "python",
      "args": [
        "C:\\Users\\Fernando\\MIESC\\src\\mcp\\server.py"
      ],
      "env": {
        "PYTHONPATH": "C:\\Users\\Fernando\\MIESC"
      }
    }
  }
}
```

### Step 3: Restart Claude Desktop

1. Quit Claude Desktop completely (⌘+Q on macOS, Alt+F4 on Windows)
2. Reopen Claude Desktop
3. Look for a green status indicator showing "MIESC connected"

### Step 4: Verify Connection

In Claude Desktop, try:

```
Are you connected to MIESC?
```

Claude should respond confirming the MCP connection and available tools.

---

## 🎯 Usage Examples

### Example 1: Quick Audit

**You:**
> Audit this contract for critical vulnerabilities: `/path/to/MyToken.sol`

**Claude (using MIESC):**
> I'll run a comprehensive security audit using MIESC...
>
> ✅ **Analysis Complete**
>
> **CRITICAL (1):**
> - Reentrancy in `withdraw()` at line 47
>   - External call before state update
>   - Exploitable via recursive callback
>
> **HIGH (2):**
> - Missing access control on `setPrice()`
> - Unchecked return value in `transfer()`
>
> Would you like me to generate patches for these issues?

### Example 2: Explain Vulnerability

**You:**
> Explain the reentrancy vulnerability in detail. How would an attacker exploit it?

**Claude:**
> The reentrancy vulnerability in your `withdraw()` function occurs because...
>
> [Claude provides detailed explanation using MIESC's AI analysis]

### Example 3: Generate Fix

**You:**
> Generate a secure version of the withdraw function.

**Claude:**
> Here's a secure implementation using the Checks-Effects-Interactions pattern...
>
> ```solidity
> function withdraw() public {
>     uint256 amount = balances[msg.sender];
>     require(amount > 0, "No balance");
>
>     // Effects: Update state BEFORE external call
>     balances[msg.sender] = 0;
>
>     // Interactions: External call AFTER state update
>     (bool success, ) = msg.sender.call{value: amount}("");
>     require(success, "Transfer failed");
> }
> ```

### Example 4: Compliance Check

**You:**
> Check if this contract complies with ISO 27001 and OWASP smart contract standards.

**Claude (using MIESC PolicyAgent):**
> I'll run a compliance analysis...
>
> **ISO/IEC 27001:2022:**
> - ✅ A.8.8 - Vulnerability management: Implemented
> - ❌ A.8.15 - Logging: Missing event emissions
> - ✅ A.8.30 - Security testing: Tools integrated
>
> **OWASP SC Top 10:**
> - ❌ SC01 - Reentrancy: Vulnerable (Critical)
> - ❌ SC02 - Access Control: Missing checks
> - ✅ SC03 - Integer Overflow: Solidity 0.8+ safe
>
> [Full compliance report available]

### Example 5: Compare Tools

**You:**
> What would Slither, Mythril, and Aderyn each find in this contract?

**Claude (using MIESC):**
> Let me run all three tools and compare...
>
> **Slither (87 detectors):**
> - Reentrancy: ✅ Detected
> - Access Control: ✅ Detected
> - Gas optimizations: ✅ 12 suggestions
>
> **Mythril (symbolic execution):**
> - Reentrancy exploit: ✅ Confirmed exploitable
> - Integer overflow: ⚠️  False positive (0.8+ safe)
>
> **Aderyn (Rust-based):**
> - Reentrancy: ✅ Detected (fastest)
> - Missing events: ✅ Detected
>
> **Consensus (3/3 tools agree):**
> - Reentrancy is CRITICAL priority

---

## 🔧 Advanced Configuration

### Custom Tool Selection

Run only specific security tools:

```json
{
  "mcpServers": {
    "miesc": {
      "command": "python",
      "args": ["/path/to/MIESC/src/mcp/server.py"],
      "env": {
        "MIESC_TOOLS": "slither,mythril,aderyn",
        "MIESC_MODE": "fast"
      }
    }
  }
}
```

### Enable AI Triage

Filter false positives with AI:

```json
{
  "env": {
    "MIESC_AI_TRIAGE": "true",
    "OPENAI_API_KEY": "sk-..."
  }
}
```

### Timeout Configuration

Adjust timeout for slow tools:

```json
{
  "env": {
    "MIESC_TIMEOUT": "600",
    "MIESC_SYMBOLIC_TIMEOUT": "300"
  }
}
```

### Output Directory

Custom output location:

```json
{
  "env": {
    "MIESC_OUTPUT_DIR": "/path/to/reports"
  }
}
```

---

## 🐛 Troubleshooting

### Issue 1: "MIESC not connected"

**Cause:** Claude can't find the MCP server

**Solution:**
1. Check absolute path is correct in config
2. Verify Python is in PATH: `which python` (macOS/Linux) or `where python` (Windows)
3. Test server manually: `python src/mcp/server.py`
4. Check Claude logs: `~/Library/Logs/Claude/` (macOS)

### Issue 2: "Module not found" errors

**Cause:** PYTHONPATH not set correctly

**Solution:**
```json
{
  "env": {
    "PYTHONPATH": "/absolute/path/to/MIESC",
    "PATH": "/usr/local/bin:/usr/bin:/bin"
  }
}
```

### Issue 3: Tools not found (Slither, Mythril, etc.)

**Cause:** Security tools not installed or not in PATH

**Solution:**
```bash
# Install core tools
pip install slither-analyzer mythril

# Verify installation
which slither
which mythril

# Add to config if needed
{
  "env": {
    "PATH": "/usr/local/bin:/opt/homebrew/bin:$PATH"
  }
}
```

### Issue 4: Slow performance

**Cause:** Symbolic execution tools are slow

**Solution:**
```json
{
  "env": {
    "MIESC_MODE": "fast",
    "MIESC_SKIP_TOOLS": "mythril,manticore"
  }
}
```

### Issue 5: Permission denied

**Cause:** Script not executable

**Solution:**
```bash
chmod +x src/mcp/server.py
```

---

## 📊 Available MCP Tools

MIESC exposes these tools to Claude Desktop:

| Tool Name | Description | Parameters |
|-----------|-------------|------------|
| `audit_contract()` | Run full security audit | `path`, `mode` (fast/standard/full) |
| `explain_vulnerability()` | AI explanation of finding | `finding_id`, `contract_path` |
| `suggest_fix()` | Generate patch for issue | `finding_id`, `contract_path` |
| `compare_tools()` | Compare tool outputs | `contract_path`, `tools` (array) |
| `check_compliance()` | Compliance verification | `contract_path`, `standards` (array) |
| `generate_report()` | Create formatted report | `contract_path`, `format` (html/pdf/json) |

---

## 🎬 Video Tutorial

Watch the 90-second setup video: [Coming Soon]

---

## 📖 Example Conversation Flow

```
You: Hi Claude! Can you help me audit a smart contract?

Claude: Of course! I have access to MIESC, which integrates 15 security
tools including Slither, Mythril, and Aderyn. Just provide the contract
path and I'll run a comprehensive analysis.

You: Great! Check this contract: examples/demo_vulnerable.sol

Claude: [Running audit_contract("examples/demo_vulnerable.sol", "standard")]

I've completed the security audit. Here are the findings:

🔴 CRITICAL (1):
   - Reentrancy vulnerability in withdraw() function (Line 28)
     Tools: Slither, Mythril, Manticore (3/3 agree)
     Confidence: 98%

🟠 HIGH (2):
   - Missing access control on setBalance() (Line 40)
   - Unsafe transfer in emergencyWithdraw() (Line 54)

🟡 MEDIUM (3):
   - No recipient validation
   - Missing zero address checks
   - Unchecked return values

✅ 139 false positives filtered by AI

Would you like me to:
1. Explain the reentrancy vulnerability in detail?
2. Generate a secure version of the contract?
3. Create a compliance report?

You: Yes, generate a secure version.

Claude: [Running suggest_fix(finding_id="1", contract_path="...")]

Here's a secure implementation...

[Claude provides patched code with explanations]
```

---

## 🚀 Next Steps

1. **Try the demo contract:** `examples/demo_vulnerable.sol`
2. **Read the full documentation:** [docs/README.md](README.md)
3. **Watch video tutorials:** [Coming Soon]
4. **Join the community:** [Discord](#) | [Twitter](#)
5. **Contribute:** [CONTRIBUTING.md](../CONTRIBUTING.md)

---

## 💡 Tips for Best Results

**Do:**
- ✅ Provide absolute paths to contracts
- ✅ Ask Claude to explain findings
- ✅ Request patches for specific issues
- ✅ Compare tool outputs for consensus
- ✅ Generate compliance reports

**Don't:**
- ❌ Rely solely on automated tools (always get expert review)
- ❌ Skip testing patches in a testnet
- ❌ Ignore medium/low severity findings
- ❌ Deploy without professional audit

---

## 📝 Configuration Templates

### Minimal Setup (Slither only)
```json
{
  "mcpServers": {
    "miesc": {
      "command": "python",
      "args": ["/path/to/MIESC/src/mcp/server.py"],
      "env": {
        "MIESC_TOOLS": "slither",
        "MIESC_MODE": "fast"
      }
    }
  }
}
```

### Full Setup (All 15 tools)
```json
{
  "mcpServers": {
    "miesc": {
      "command": "python",
      "args": ["/path/to/MIESC/src/mcp/server.py"],
      "env": {
        "PYTHONPATH": "/path/to/MIESC",
        "MIESC_MODE": "full",
        "MIESC_AI_TRIAGE": "true",
        "OPENAI_API_KEY": "sk-...",
        "MIESC_OUTPUT_DIR": "/path/to/reports"
      }
    }
  }
}
```

### Docker Setup
```json
{
  "mcpServers": {
    "miesc": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "${HOME}/contracts:/contracts",
        "fboiero/miesc:latest",
        "python", "src/mcp/server.py"
      ]
    }
  }
}
```

---

## 🆘 Support

**Issues?**
- 📧 Email: fboiero@frvm.utn.edu.ar
- 🐛 GitHub Issues: https://github.com/fboiero/MIESC/issues
- 💬 Discord: [Coming Soon]
- 📖 Docs: https://fboiero.github.io/MIESC/

---

**Last Updated:** December 2024
**Author:** Fernando Boiero
**License:** GPL-3.0
