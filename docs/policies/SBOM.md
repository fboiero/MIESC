# Software Bill of Materials (SBOM)

This document describes MIESC's SBOM generation, distribution, and verification process.

---

## Overview

MIESC provides a Software Bill of Materials (SBOM) for supply chain transparency. The SBOM lists all dependencies, their versions, and licenses.

**Format**: [CycloneDX](https://cyclonedx.org/) JSON (industry standard)

---

## SBOM Availability

### Release SBOMs

Each GitHub release includes:

| File | Description |
|------|-------------|
| `sbom.json` | Full SBOM in CycloneDX JSON format |
| `licenses.csv` | License summary for all dependencies |

Download from: [GitHub Releases](https://github.com/fboiero/MIESC/releases)

### Artifact SBOMs

Weekly SBOM snapshots are stored as GitHub Actions artifacts:

1. Go to [Actions > SBOM Generation](https://github.com/fboiero/MIESC/actions/workflows/sbom.yml)
2. Select a workflow run
3. Download the `sbom-*` artifact

Artifacts are retained for **90 days**.

---

## SBOM Contents

The SBOM includes:

- **Component name**: Package name
- **Version**: Installed version
- **License**: SPDX license identifier
- **Hashes**: SHA256 checksums (when available)
- **PURL**: Package URL for identification

### Example Entry

```json
{
  "type": "library",
  "name": "slither-analyzer",
  "version": "0.10.0",
  "purl": "pkg:pypi/slither-analyzer@0.10.0",
  "licenses": [
    {
      "license": {
        "id": "AGPL-3.0-only"
      }
    }
  ]
}
```

---

## Generating SBOM Locally

### Using CycloneDX

```bash
# Install CycloneDX
pip install cyclonedx-bom

# Generate from installed environment
cyclonedx-py environment -o sbom.json --of JSON

# Generate from requirements file
cyclonedx-py requirements requirements.txt -o sbom.json --of JSON
```

### Using pip-licenses

```bash
# Install pip-licenses
pip install pip-licenses

# Generate license report
pip-licenses --format=markdown

# Generate CSV for analysis
pip-licenses --format=csv > licenses.csv
```

### Using Syft

```bash
# Install syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh

# Generate SBOM from directory
syft dir:. -o cyclonedx-json > sbom.json

# Generate from Docker image
syft ghcr.io/fboiero/miesc:latest -o cyclonedx-json > docker-sbom.json
```

---

## SBOM Verification

### Validate Format

```bash
# Install cyclonedx-cli
npm install -g @cyclonedx/cyclonedx-cli

# Validate SBOM
cyclonedx validate --input-file sbom.json
```

### Check for Vulnerabilities

```bash
# Using grype (Anchore)
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh
grype sbom:sbom.json

# Using osv-scanner (Google)
pip install osv-scanner
osv-scanner --sbom sbom.json
```

---

## SBOM Update Schedule

| Trigger | When |
|---------|------|
| Release | Every GitHub release |
| Scheduled | Weekly (Sunday 2 AM UTC) |
| Manual | On-demand via workflow_dispatch |

---

## License Compliance

### Allowed Licenses

MIESC (AGPL-3.0) is compatible with:

| License | Compatible | Notes |
|---------|------------|-------|
| MIT | ✅ | Permissive |
| Apache-2.0 | ✅ | Permissive |
| BSD-2-Clause | ✅ | Permissive |
| BSD-3-Clause | ✅ | Permissive |
| ISC | ✅ | Permissive |
| LGPL-2.1+ | ✅ | Weak copyleft |
| LGPL-3.0 | ✅ | Weak copyleft |
| GPL-3.0 | ✅ | Same terms |
| AGPL-3.0 | ✅ | Same license |

### Potentially Problematic

| License | Status | Action |
|---------|--------|--------|
| GPL-2.0-only | ⚠️ Review | Check compatibility |
| Proprietary | ❌ Avoid | Cannot include |
| SSPL | ❌ Avoid | Not OSI-approved |

---

## Supply Chain Security

### SLSA Attestations

Future releases will include [SLSA](https://slsa.dev/) attestations:

- **Level 1**: Documentation (current)
- **Level 2**: Signed provenance (in progress)
- **Level 3**: Hardened builds (planned)

### Dependency Pinning

All dependencies are pinned in:

- `pyproject.toml`: Version constraints
- `requirements-lock.txt`: Exact versions

### Vulnerability Scanning

Dependencies are scanned:

- **On every PR**: pip-audit check
- **Weekly**: Scheduled vulnerability scan
- **On release**: Full security audit

See [dependency-security.yml](../../.github/workflows/dependency-security.yml).

---

## Integration with Other Tools

### Dependency-Track

Import SBOM into [Dependency-Track](https://dependencytrack.org/):

```bash
curl -X POST "https://your-dt-server/api/v1/bom" \
  -H "X-Api-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d @sbom.json
```

### GitHub Dependency Graph

SBOM is automatically uploaded to GitHub's dependency graph when available.

### Snyk

```bash
snyk sbom --file=sbom.json
```

---

## Retention Policy

| SBOM Type | Retention | Location |
|-----------|-----------|----------|
| Release SBOM | Permanent | GitHub Release assets |
| Artifact SBOM | 90 days | GitHub Actions artifacts |
| Docker SBOM | With image | Container registry |

---

## Contact

Questions about SBOM or supply chain security:

- **Email**: fboiero@frvm.utn.edu.ar
- **Security Issues**: [SECURITY.md](SECURITY.md)

---

## References

- [CycloneDX Specification](https://cyclonedx.org/specification/overview/)
- [SPDX License List](https://spdx.org/licenses/)
- [SLSA Framework](https://slsa.dev/)
- [OpenSSF Scorecard](https://securityscorecards.dev/)

---

*Last updated: February 2026*
