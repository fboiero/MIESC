# Privacy Policy - MIESC Framework

**Effective Date**: October 12, 2025
**Last Updated**: October 12, 2025
**Version**: 1.0

---

## Overview

MIESC (Marco Integrado de Evaluación de Seguridad en Smart Contracts) is a security analysis framework for smart contracts. This privacy policy explains our data practices and your privacy rights.

**TL;DR**: MIESC collects **NO personal information**. All data processing occurs locally on your machine.

---

## 1. Information We Collect

### 1.1 Personal Information

**❌ NONE**

MIESC does **NOT** collect, store, transmit, or process any Personally Identifiable Information (PII).

- ❌ No names or contact information
- ❌ No IP addresses or device identifiers
- ❌ No location data
- ❌ No user behavior tracking
- ❌ No cookies or analytics
- ❌ No telemetry (unless explicitly enabled by you)

### 1.2 Technical Data Processed Locally

MIESC processes the following data **locally on your machine**:

✅ **Smart Contract Source Code**:
- Solidity (.sol) files you provide for analysis
- Stored temporarily during analysis
- Never transmitted to external servers (unless you use optional cloud AI features)

✅ **Vulnerability Findings**:
- Technical security findings from analysis
- Stored in local JSON files
- You control all storage locations

✅ **Analysis Logs**:
- Tool execution logs
- MCP message history
- Stored locally for debugging

✅ **Configuration Data**:
- Your local settings (e.g., tool preferences)
- API keys stored in `.env` file (your responsibility to protect)

**Data Retention**: All data is stored locally under your control. You can delete any files at any time.

---

## 2. Optional Cloud Services

### 2.1 OpenAI API (Optional)

If you **choose** to enable AI-powered triage features:

- Your smart contract code is sent to OpenAI's API for analysis
- OpenAI's privacy policy applies: https://openai.com/policies/privacy-policy
- You provide your own API key
- **You control this feature** - it's optional and disabled by default

**How to disable**: Do not configure `OPENAI_API_KEY` in your `.env` file.

### 2.2 Local LLM Alternative

For privacy-sensitive contracts, use local models:
- LLaMA 3.1 (runs 100% offline on your machine)
- No data leaves your computer
- See: `docs/LLAMA_SETUP.md`

---

## 3. Data Storage and Security

### 3.1 Local Storage

- All MIESC outputs stored in `outputs/` directory on your machine
- You control access via file system permissions
- Optional: Encrypt sensitive contracts using your OS encryption tools

### 3.2 Data in Transit

**Default Configuration**:
- ✅ MCP protocol over stdio (local process communication)
- ✅ No network communication required
- ✅ All analysis happens locally

**Optional Network Communication**:
- If using OpenAI API: HTTPS encrypted
- If using remote MCP server: Configure TLS/SSL

### 3.3 Security Measures

- API keys stored in `.env` file (not hardcoded)
- `.env` excluded from git via `.gitignore`
- No default telemetry or "phone home" features
- Audit trail logs for compliance (ISO 27001 A.8.15)

---

## 4. Third-Party Services

### 4.1 Dependencies

MIESC uses open-source security tools:
- Slither, Mythril, Echidna, Foundry (all run locally)
- These tools do not collect personal information
- See `requirements.txt` for full dependency list

### 4.2 External APIs (Optional)

You may choose to integrate:
- **OpenAI API**: Subject to OpenAI's privacy policy
- **Anthropic API**: Subject to Anthropic's privacy policy
- **HuggingFace Hub**: For downloading LLM models (public models only)

**Control**: All external API usage is optional and under your control.

---

## 5. Compliance

### 5.1 GDPR (European Union)

**Not Applicable**: MIESC does not collect personal data.

If you are subject to GDPR:
- ✅ Article 25: Privacy by design (no PII by default)
- ✅ Article 32: Security of processing (local-first architecture)
- ✅ Article 17: Right to erasure (you control all data)

### 5.2 CCPA (California, USA)

**Not Applicable**: MIESC does not collect personal data.

### 5.3 ISO/IEC 27001:2022

MIESC implements:
- Control A.8.15: Logging (local audit trail)
- Control A.8.16: Monitoring (activity logs)
- Evidence: `standards/iso27001_controls.md`

---

## 6. Children's Privacy

MIESC is not directed at children under 13 (or applicable local age of digital consent). We do not knowingly collect data from children.

**Academic/Professional Tool**: Intended for security researchers, developers, and auditors.

---

## 7. Data Sharing

### 7.1 With Third Parties

**❌ NONE**

MIESC does not share, sell, or rent any data to third parties.

### 7.2 Legal Requirements

In the unlikely event of legal compulsion:
- We have no data to provide (no PII collected)
- You control all local data
- We would notify you if legally permitted

### 7.3 Research Purposes

If you choose to contribute anonymized findings to research:
- Explicit opt-in required
- No personal information included
- Only technical vulnerability statistics

---

## 8. Your Rights

Since MIESC processes data locally, **you have complete control**:

✅ **Access**: View all local files in `outputs/`
✅ **Deletion**: Delete any files at any time
✅ **Portability**: Export data in JSON format
✅ **Control**: Disable any optional features
✅ **Transparency**: View source code (open source GPL-3.0)

---

## 9. Changes to This Policy

We may update this privacy policy to reflect:
- Changes in legal requirements
- New features (with privacy impact)
- Community feedback

**Notification**:
- Updates published in this file (GitHub)
- Version number and date updated
- Major changes announced in README.md

**Previous Versions**: Available in git history

---

## 10. Contact Information

**Questions or Concerns**:
- Email: fboiero@frvm.utn.edu.ar
- GitHub Issues: https://github.com/fboiero/MIESC/issues
- Security Reports: See `SECURITY.md`

**Data Controller**:
- Fernando Boiero
- Universidad Tecnológica Nacional - FRVM
- Argentina

---

## 11. Additional Resources

- **DPG Compliance**: See `DPG_COMPLIANCE.md`
- **Security Policy**: See `SECURITY.md`
- **Code of Conduct**: See `CODE_OF_CONDUCT.md`
- **License**: See `LICENSE` (GPL-3.0)

---

## Summary

| Aspect | MIESC Practice |
|--------|----------------|
| **Personal Data Collected** | ❌ None |
| **Telemetry** | ❌ None (by default) |
| **Third-Party Sharing** | ❌ None |
| **Data Processing** | ✅ Local only (default) |
| **User Control** | ✅ Complete |
| **Open Source** | ✅ GPL-3.0 |
| **Privacy by Design** | ✅ Yes |

**Philosophy**: Your data is yours. MIESC is a tool you run on your machine, analyzing contracts you provide, with all results under your control.

---

**Last Updated**: October 12, 2025
**Next Review**: October 12, 2026
**Version**: 1.0
**Language**: English (ES version available)
