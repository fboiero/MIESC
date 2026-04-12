# Maintenance Policy

This document describes the maintenance policy and release schedule for MIESC.

---

## Release Schedule

| Release Type | Frequency | Description |
|--------------|-----------|-------------|
| Major (X.0.0) | 6-12 months | Breaking changes, new architectures |
| Minor (x.Y.0) | 1-2 months | New features, tool integrations |
| Patch (x.y.Z) | As needed | Bug fixes, security patches |

---

## Version Support

| Version | Status | Support Until |
|---------|--------|---------------|
| 5.1.x | **Current** | Active development |
| 5.0.x | Maintained | 6 months after 5.2.0 |
| 4.x | End of Life | No longer supported |

### Support Levels

- **Active Development**: Receives new features, bug fixes, and security patches
- **Maintained**: Receives critical bug fixes and security patches only
- **End of Life**: No longer supported; upgrade recommended

---

## Security Updates

Security vulnerabilities are treated with high priority:

| Severity | Response Time | Fix Timeline |
|----------|---------------|--------------|
| Critical | 24 hours | 48-72 hours |
| High | 48 hours | 1 week |
| Medium | 1 week | 2-4 weeks |
| Low | 2 weeks | Next minor release |

See [SECURITY.md](docs/policies/SECURITY.md) for reporting vulnerabilities.

---

## Dependency Updates

- **Python**: Support latest stable + previous version (currently 3.12, 3.13)
- **Security tools**: Updated within 2 weeks of upstream releases
- **Dependencies**: Reviewed monthly, updated quarterly

---

## Breaking Changes Policy

Before making breaking changes:

1. **Deprecation notice** in previous minor release
2. **Migration guide** provided in documentation
3. **Minimum 1 minor release** between deprecation and removal

Breaking changes are only made in major releases unless required for security.

---

## Backwards Compatibility

We maintain backwards compatibility for:

- CLI commands and flags (2 major versions)
- Python API (1 major version)
- Configuration files (migration provided)
- Docker image tags (current + previous major)

---

## Long-Term Support (LTS)

Currently, MIESC does not have designated LTS releases. This may change as the project matures.

For enterprise users requiring extended support, contact: fboiero@frvm.utn.edu.ar

---

## Contribution to Maintenance

Help maintain MIESC:

- **Report bugs** promptly with reproduction steps
- **Submit PRs** for issues you encounter
- **Review PRs** to help speed up merges
- **Update documentation** when you find gaps

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Release Process

1. **Feature freeze** 1 week before release
2. **Release candidate** for testing
3. **Final release** with changelog
4. **Docker images** published to GHCR
5. **PyPI package** published
6. **Documentation** updated

---

## Contact

- **Maintainer**: Fernando Boiero
- **Email**: fboiero@frvm.utn.edu.ar
- **GitHub**: [@fboiero](https://github.com/fboiero)

---

*Last updated: February 2026*
