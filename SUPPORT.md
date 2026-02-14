# Support

Need help with MIESC? Here's how to get support.

---

## Getting Help

### Documentation

- [Quick Start Guide](docs/guides/QUICKSTART.md) - Get started in 5 minutes
- [Full Documentation](https://fboiero.github.io/MIESC) - Complete user guide
- [API Reference](docs/api/) - Developer documentation
- [Tool Reference](docs/TOOLS.md) - All 50 security tools

### Community

- [GitHub Discussions](https://github.com/fboiero/MIESC/discussions) - Questions, ideas, community
- [Issue Tracker](https://github.com/fboiero/MIESC/issues) - Bug reports and feature requests
- [Community Guide](docs/COMMUNITY.md) - Full community resources and guidelines

**Real-time chat (Discord/Matrix) coming soon!** See [Community Guide](docs/COMMUNITY.md) for updates.

---

## Response Times

| Channel | Response Time |
|---------|---------------|
| Security Issues | 48 hours |
| Bug Reports | 5 business days |
| Feature Requests | 2 weeks |
| General Questions | Best effort |

---

## Before Asking

1. Check the [documentation](https://fboiero.github.io/MIESC)
2. Search [existing issues](https://github.com/fboiero/MIESC/issues)
3. Review the [FAQ](#faq) below
4. Run `miesc doctor` to check your installation

---

## FAQ

### Installation

**Q: Which Python version do I need?**

A: Python 3.12 or higher is required.

**Q: Why is Mythril not working?**

A: Mythril has dependency conflicts with some packages. Install it in a separate virtual environment or use the Docker image (`miesc:full`).

### Docker

**Q: Why does Docker say "scan: not found"?**

A: You have an old cached image. Run:
```bash
docker rmi ghcr.io/fboiero/miesc:latest
docker pull ghcr.io/fboiero/miesc:latest
```

**Q: How do I use MIESC with Ollama in Docker?**

A: Set the `OLLAMA_HOST` environment variable:
```bash
# macOS/Windows
docker run -e OLLAMA_HOST=http://host.docker.internal:11434 ...

# Linux
docker run --network host -e OLLAMA_HOST=http://localhost:11434 ...
```

### Analysis

**Q: How do I skip unavailable tools?**

A: Use `--skip-unavailable`:
```bash
miesc audit full contract.sol --skip-unavailable
```

**Q: Why am I getting false positives?**

A: Enable LLM interpretation to reduce false positives:
```bash
miesc report results.json -t premium --llm-interpret
```

---

## Reporting Issues

### Bug Reports

When reporting bugs, please include:

1. MIESC version (`miesc --version`)
2. Python version (`python --version`)
3. Operating system
4. Steps to reproduce
5. Expected vs actual behavior
6. Error messages and logs

Use the [bug report template](https://github.com/fboiero/MIESC/issues/new?template=bug_report.md).

### Feature Requests

For feature requests:

1. Check existing [feature requests](https://github.com/fboiero/MIESC/labels/enhancement)
2. Describe the use case
3. Propose a solution if possible

Use the [feature request template](https://github.com/fboiero/MIESC/issues/new?template=feature_request.md).

### Security Vulnerabilities

**Do NOT report security vulnerabilities in public issues.**

See [SECURITY.md](docs/policies/SECURITY.md) for responsible disclosure instructions.

---

## Commercial Support

For enterprise support, training, or custom development:

**Contact:** Fernando Boiero
**Email:** fboiero@frvm.utn.edu.ar
**Institution:** Universidad de la Defensa Nacional (UNDEF), Argentina

---

## Contributing

Want to help improve MIESC? See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

*[Spanish version / Versión en español](SUPPORT_ES.md)*
