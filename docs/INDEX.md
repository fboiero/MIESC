# MIESC Documentation Index

**Version:** 3.3.0
**Last Updated:** 2025-01-18

Welcome to the MIESC documentation! This index provides a complete navigation guide to all documentation resources.

---

## 🚀 Quick Start

**New to MIESC?** Start here:

1. [00_OVERVIEW.md](00_OVERVIEW.md) - Purpose, key metrics, use cases
2. [02_SETUP_AND_USAGE.md](02_SETUP_AND_USAGE.md) - Installation and first run
3. [03_DEMO_GUIDE.md](03_DEMO_GUIDE.md) - Interactive 5-minute demo
4. [../demo/README.md](../demo/README.md) - Hands-on demo walkthrough

**Estimated time to productive use:** ~15 minutes

---

## 📚 Documentation Structure

### Core Documentation (Sequential Learning Path)

The primary documentation is organized as **10 numbered modules** for sequential reading:

| # | Document | Topic | Length | Audience |
|---|----------|-------|--------|----------|
| **00** | [00_OVERVIEW.md](00_OVERVIEW.md) | Purpose, metrics, use cases | 600 lines | Everyone |
| **01** | [01_ARCHITECTURE.md](01_ARCHITECTURE.md) | System design, components | 850 lines | Developers |
| **02** | [02_SETUP_AND_USAGE.md](02_SETUP_AND_USAGE.md) | Installation, CLI usage | 650 lines | Users |
| **03** | [03_DEMO_GUIDE.md](03_DEMO_GUIDE.md) | Interactive demo walkthrough | 550 lines | New users |
| **04** | [04_AI_CORRELATION.md](04_AI_CORRELATION.md) | AI false positive reduction | 700 lines | AI researchers |
| **05** | [05_POLICY_AGENT.md](05_POLICY_AGENT.md) | Internal security validation | 750 lines | DevSecOps |
| **06** | [SHIFT_LEFT_SECURITY.md](SHIFT_LEFT_SECURITY.md) | DevSecOps integration | 330 lines | CI/CD users |
| **07** | [07_MCP_INTEROPERABILITY.md](07_MCP_INTEROPERABILITY.md) | Model Context Protocol | 800 lines | Integration |
| **08** | [08_METRICS_AND_RESULTS.md](08_METRICS_AND_RESULTS.md) | Scientific validation | 900 lines | Researchers |
| **09** | [09_THEORETICAL_FOUNDATION.md](09_THEORETICAL_FOUNDATION.md) | Academic background | 750 lines | Academics |
| **10** | [FRAMEWORK_ALIGNMENT.md](FRAMEWORK_ALIGNMENT.md) | ISO/NIST/OWASP compliance | 467 lines | Compliance |

**Total:** ~6,900 lines of comprehensive documentation

---

## 🎯 Documentation by Use Case

### For Smart Contract Developers

**Goal:** Integrate MIESC into your development workflow

1. [02_SETUP_AND_USAGE.md](02_SETUP_AND_USAGE.md) - Installation
2. [03_DEMO_GUIDE.md](03_DEMO_GUIDE.md) - See it in action
3. [SHIFT_LEFT_SECURITY.md](SHIFT_LEFT_SECURITY.md) - CI/CD integration
4. [guides/QUICKSTART_API.md](guides/QUICKSTART_API.md) - Programmatic usage

**Next steps:** Run demo, analyze your contracts, integrate into CI/CD

---

### For Security Auditors

**Goal:** Use MIESC for professional smart contract audits

1. [00_OVERVIEW.md](00_OVERVIEW.md) - Understand capabilities
2. [08_METRICS_AND_RESULTS.md](08_METRICS_AND_RESULTS.md) - Validation metrics
3. [04_AI_CORRELATION.md](04_AI_CORRELATION.md) - AI triage methodology
4. [ENHANCED_REPORTS.md](ENHANCED_REPORTS.md) - Report generation

**Next steps:** Benchmark on your test suite, integrate into audit workflow

---

### For Researchers

**Goal:** Extend MIESC or use in academic studies

1. [09_THEORETICAL_FOUNDATION.md](09_THEORETICAL_FOUNDATION.md) - Research context
2. [08_METRICS_AND_RESULTS.md](08_METRICS_AND_RESULTS.md) - Empirical results
3. [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) - Extend MIESC
4. [REPRODUCIBILITY.md](REPRODUCIBILITY.md) - Reproduce experiments

**Next steps:** Clone repo, run reproducibility package, propose extensions

---

### For DevSecOps Engineers

**Goal:** Deploy MIESC in production security pipelines

1. [SHIFT_LEFT_SECURITY.md](SHIFT_LEFT_SECURITY.md) - Shift-Left approach
2. [05_POLICY_AGENT.md](05_POLICY_AGENT.md) - Internal validation
3. [07_MCP_INTEROPERABILITY.md](07_MCP_INTEROPERABILITY.md) - MCP protocol
4. [docker/README.md](../docker/README.md) - Containerization
5. [k8s/README.md](../k8s/README.md) - Kubernetes deployment

**Next steps:** Deploy MCP adapter, configure CI/CD, monitor compliance

---

### For Compliance Officers

**Goal:** Demonstrate security compliance for smart contract projects

1. [FRAMEWORK_ALIGNMENT.md](FRAMEWORK_ALIGNMENT.md) - ISO/NIST/OWASP mapping
2. [05_POLICY_AGENT.md](05_POLICY_AGENT.md) - Automated compliance checks
3. [governance/ISO_42001_compliance.md](governance/ISO_42001_compliance.md) - AI governance
4. [compliance/DPG_COMPLIANCE.md](compliance/DPG_COMPLIANCE.md) - Digital public goods

**Next steps:** Generate compliance reports, map to your framework

---

## 📖 Supplementary Documentation

### Setup & Installation

- [02_SETUP_AND_USAGE.md](02_SETUP_AND_USAGE.md) - Primary installation guide
- [setup/INSTALL_MACOS.md](setup/INSTALL_MACOS.md) - macOS-specific instructions
- [docker/README.md](../docker/README.md) - Docker installation
- [API_SETUP.md](API_SETUP.md) - AI API configuration

### Tools & Integration

- [tool_integration_standard.md](tool_integration_standard.md) - Adding new tools
- [MANTICORE_MIGRATION.md](MANTICORE_MIGRATION.md) - Manticore integration
- [MYTHRIL_APPLE_SILICON.md](MYTHRIL_APPLE_SILICON.md) - Mythril on M1/M2 Macs
- [LLAMA_SETUP.md](LLAMA_SETUP.md) - Local LLM setup

### AI & Agents

- [04_AI_CORRELATION.md](04_AI_CORRELATION.md) - AI correlation engine
- [AI_ARCHITECTURE.md](AI_ARCHITECTURE.md) - AI system design
- [AGENTS_EXPLAINED.md](AGENTS_EXPLAINED.md) - Multi-agent architecture
- [AGENT_DEVELOPMENT_GUIDE.md](AGENT_DEVELOPMENT_GUIDE.md) - Building agents
- [INTELLIGENT_AGENTS_UPGRADE.md](INTELLIGENT_AGENTS_UPGRADE.md) - Intelligent agents

### MCP Protocol

- [07_MCP_INTEROPERABILITY.md](07_MCP_INTEROPERABILITY.md) - MCP integration guide
- [MCP_SETUP_GUIDE.md](MCP_SETUP_GUIDE.md) - MCP configuration
- [MCP_clients_setup.md](MCP_clients_setup.md) - MCP client integration
- [MCP_evolution.md](MCP_evolution.md) - MCP protocol evolution

### Compliance & Governance

- [FRAMEWORK_ALIGNMENT.md](FRAMEWORK_ALIGNMENT.md) - ISO/NIST/OWASP
- [governance/ISO_42001_compliance.md](governance/ISO_42001_compliance.md) - AI governance
- [05_POLICY_AGENT.md](05_POLICY_AGENT.md) - PolicyAgent
- [POLICY_VALIDATION.md](POLICY_VALIDATION.md) - Policy validation methodology

### Testing & Quality

- [REGRESSION_TESTING.md](REGRESSION_TESTING.md) - Regression test suite
- [../tests/TEST_ANALYSIS_REPORT.md](../tests/TEST_ANALYSIS_REPORT.md) - Test analysis
- [REPRODUCIBILITY.md](REPRODUCIBILITY.md) - Reproducibility package

### Project Management

- [PROJECT_STATUS.md](PROJECT_STATUS.md) - Current status
- [PROJECT_ANALYSIS.md](PROJECT_ANALYSIS.md) - Project analysis
- [ROADMAP_6_MONTHS.md](ROADMAP_6_MONTHS.md) - 6-month roadmap
- [INTEGRATION_ROADMAP.md](INTEGRATION_ROADMAP.md) - Integration roadmap

### Academic & Research

- [09_THEORETICAL_FOUNDATION.md](09_THEORETICAL_FOUNDATION.md) - Research foundation
- [08_METRICS_AND_RESULTS.md](08_METRICS_AND_RESULTS.md) - Scientific metrics
- [THESIS_PRESENTATION.md](THESIS_PRESENTATION.md) - Thesis materials
- [STATE_OF_THE_ART_COMPARISON.md](STATE_OF_THE_ART_COMPARISON.md) - SOTA comparison
- [TOOLS_COMPARISON_2025.md](TOOLS_COMPARISON_2025.md) - Tool benchmarks

---

## 🎬 Multimedia Resources

### Video & Presentations

- [VIDEO_PRODUCTION_GUIDE.md](VIDEO_PRODUCTION_GUIDE.md) - Video creation guide
- [VIDEO_SCRIPT.md](VIDEO_SCRIPT.md) - Demo video script
- [../video_assets/PRODUCTION_CHECKLIST.md](../video_assets/PRODUCTION_CHECKLIST.md) - Production checklist
- [../video_assets/RECORDING_INSTRUCTIONS.md](../video_assets/RECORDING_INSTRUCTIONS.md) - Recording guide

### Interactive Demo

- [03_DEMO_GUIDE.md](03_DEMO_GUIDE.md) - Step-by-step demo
- [../demo/README.md](../demo/README.md) - Demo folder documentation
- Run: `bash demo/run_demo.sh`

---

## 🏗️ Architecture & Design

- [01_ARCHITECTURE.md](01_ARCHITECTURE.md) - System architecture
- [AI_ARCHITECTURE.md](AI_ARCHITECTURE.md) - AI subsystem design
- [architecture/](architecture/) - Architecture diagrams
- [AGENTS_EXPLAINED.md](AGENTS_EXPLAINED.md) - Agent design patterns

---

## 🔐 Security & Compliance

### Security Documentation

- [../SECURITY.md](../SECURITY.md) - Security policy
- [05_POLICY_AGENT.md](05_POLICY_AGENT.md) - Self-auditing
- [DEVSECOPS.md](DEVSECOPS.md) - DevSecOps practices

### Compliance Standards

- [FRAMEWORK_ALIGNMENT.md](FRAMEWORK_ALIGNMENT.md) - Multi-framework compliance
- [governance/ISO_42001_compliance.md](governance/ISO_42001_compliance.md) - AI governance
- [compliance/DPG_COMPLIANCE.md](compliance/DPG_COMPLIANCE.md) - Digital public goods

---

## 🔧 Developer Resources

### Development Guides

- [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) - Internal architecture guide
- [../CONTRIBUTING.md](../CONTRIBUTING.md) - Contribution guidelines
- [AGENT_DEVELOPMENT_GUIDE.md](AGENT_DEVELOPMENT_GUIDE.md) - Building agents
- [tool_integration_standard.md](tool_integration_standard.md) - Tool integration

### API & Usage

- [02_SETUP_AND_USAGE.md](02_SETUP_AND_USAGE.md) - CLI usage
- [guides/QUICKSTART_API.md](guides/QUICKSTART_API.md) - API quickstart
- [USAGE.md](USAGE.md) - General usage guide

---

## 📦 Deployment

### Containerization

- [docker/README.md](../docker/README.md) - Docker setup
- [DOCKER.md](DOCKER.md) - Docker documentation
- [../Dockerfile](../Dockerfile) - Container definition

### Kubernetes

- [k8s/README.md](../k8s/README.md) - Kubernetes deployment
- [deployment_guide.md](deployment_guide.md) - General deployment

---

## 📊 Reports & Analysis

- [08_METRICS_AND_RESULTS.md](08_METRICS_AND_RESULTS.md) - Scientific metrics
- [ENHANCED_REPORTS.md](ENHANCED_REPORTS.md) - Report generation
- [MULTI_CONTRACT_SUMMARY.md](MULTI_CONTRACT_SUMMARY.md) - Multi-contract analysis
- [SESSION_REPORT_IMPROVEMENTS.md](SESSION_REPORT_IMPROVEMENTS.md) - Report enhancements

---

## 🌐 Website & Public Docs

- [website/](website/) - Website source files
- [../website/README.md](../website/README.md) - Website documentation
- [../index.html](../index.html) - Landing page

---

## 📝 Release Notes

- [../CHANGELOG.md](../CHANGELOG.md) - Version history
- [releases/](releases/) - Release documentation
- [../MIESC_V3.3_DEMO_RELEASE.md](../MIESC_V3.3_DEMO_RELEASE.md) - v3.3.0 release notes
- [../MIESC_V3.2_IMPLEMENTATION_SUMMARY.md](../MIESC_V3.2_IMPLEMENTATION_SUMMARY.md) - v3.2.0 summary

---

## 🆘 Getting Help

### Common Questions

1. **How do I install MIESC?**
   → [02_SETUP_AND_USAGE.md](02_SETUP_AND_USAGE.md)

2. **How do I run the demo?**
   → [03_DEMO_GUIDE.md](03_DEMO_GUIDE.md) or `bash demo/run_demo.sh`

3. **How accurate is MIESC?**
   → [08_METRICS_AND_RESULTS.md](08_METRICS_AND_RESULTS.md) (Precision: 89.47%, Recall: 86.2%)

4. **Can I add my own security tool?**
   → [tool_integration_standard.md](tool_integration_standard.md)

5. **How do I integrate MIESC into CI/CD?**
   → [SHIFT_LEFT_SECURITY.md](SHIFT_LEFT_SECURITY.md)

6. **What compliance frameworks does MIESC support?**
   → [FRAMEWORK_ALIGNMENT.md](FRAMEWORK_ALIGNMENT.md) (ISO/NIST/OWASP/etc.)

### Support Channels

- **Documentation:** You're here! 📚
- **Issues:** [GitHub Issues](https://github.com/fboiero/MIESC/issues)
- **Email:** fboiero@frvm.utn.edu.ar
- **Contributing:** [../CONTRIBUTING.md](../CONTRIBUTING.md)

---

## 🗺️ Documentation Roadmap

### Completed (v3.3.0) ✅

- Core documentation (00-10)
- Demo guide
- Developer guide
- MCP integration
- Scientific validation

### Planned (v3.4.0)

- [ ] Video tutorials
- [ ] Interactive API reference
- [ ] More use case examples
- [ ] Multi-language translations (Spanish, Chinese)

---

## 📄 Document Conventions

### File Naming

- **Numbered (00-10):** Sequential core documentation
- **UPPERCASE.md:** Standalone guides (e.g., USAGE.md, DOCKER.md)
- **lowercase.md:** Internal/legacy documentation

### Document Structure

Most documents follow this structure:
1. Title and metadata (version, date)
2. Purpose/overview
3. Main content (with headers)
4. Examples
5. Next steps/related docs

### Cross-References

Documents link to each other using relative paths:
- Same directory: `[Document](DOCUMENT.md)`
- Parent directory: `[Document](../DOCUMENT.md)`
- Subdirectory: `[Document](subdir/DOCUMENT.md)`

---

## 🔄 Keeping Documentation Updated

Documentation is maintained alongside code:
- **Version:** Matches MIESC version (currently 3.3.0)
- **Updates:** See [../CHANGELOG.md](../CHANGELOG.md)
- **Last Updated:** Check date at top of each document

To contribute documentation improvements:
1. Read [../CONTRIBUTING.md](../CONTRIBUTING.md)
2. Follow documentation style guide
3. Submit PR with updated docs

---

## 📚 Citation

If you use MIESC in your research, please cite:

```bibtex
@software{MIESC_2025,
  author = {Boiero, Fernando},
  title = {MIESC: Multi-layer Intelligent Evaluation for Smart Contracts},
  year = {2025},
  url = {https://github.com/fboiero/MIESC},
  version = {3.3.0}
}
```

See [../CITATION.cff](../CITATION.cff) for full citation metadata.

---

**Version:** 3.3.0
**Maintainer:** Fernando Boiero - UNDEF
**Last Updated:** 2025-01-18

**Happy Reading! 📖**
