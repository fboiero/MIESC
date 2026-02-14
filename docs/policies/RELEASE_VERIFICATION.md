# Release Verification

This document describes how to verify the authenticity and integrity of MIESC releases.

---

## Overview

All MIESC releases are:

1. **Signed with Sigstore** - Cryptographically signed using keyless signing
2. **Checksummed** - SHA256 checksums provided for all artifacts
3. **Published via GitHub Actions** - Transparent, auditable build process

---

## Quick Verification

### 1. Verify Checksums

Download `SHA256SUMS.txt` from the release and verify:

```bash
# Download the release files and checksums
wget https://github.com/fboiero/MIESC/releases/download/v5.1.1/SHA256SUMS.txt
wget https://github.com/fboiero/MIESC/releases/download/v5.1.1/miesc-5.1.1.tar.gz

# Verify checksum
sha256sum -c SHA256SUMS.txt
```

### 2. Verify Sigstore Signatures

```bash
# Install cosign (https://docs.sigstore.dev/cosign/installation/)
# macOS
brew install cosign

# Linux
curl -LO https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
chmod +x cosign-linux-amd64
sudo mv cosign-linux-amd64 /usr/local/bin/cosign

# Verify signature
cosign verify-blob \
  --signature miesc-5.1.1.tar.gz.sig \
  --certificate miesc-5.1.1.tar.gz.pem \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  miesc-5.1.1.tar.gz
```

Expected output:
```
Verified OK
```

---

## Understanding Sigstore Signatures

### What is Sigstore?

[Sigstore](https://www.sigstore.dev/) is a Linux Foundation project that provides:

- **Keyless signing**: No long-lived keys to manage
- **Transparency log**: All signatures recorded in Rekor
- **OIDC-based identity**: Tied to GitHub Actions workflow

### What the Signature Proves

When you verify a MIESC signature, you confirm:

1. **Provenance**: The artifact was built by GitHub Actions in the fboiero/MIESC repository
2. **Integrity**: The artifact hasn't been modified since signing
3. **Authenticity**: The signature was created during an official release workflow

### Certificate Details

Each `.pem` certificate file contains:

```
Subject: workflow:release.yml, repo:fboiero/MIESC
Issuer: sigstore.dev (Fulcio)
```

---

## Verifying Docker Images

Docker images are also signed with cosign:

```bash
# Verify Docker image signature
cosign verify ghcr.io/fboiero/miesc:5.1.1

# Verify with specific issuer
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/fboiero/miesc:5.1.1
```

---

## Verifying PyPI Packages

PyPI packages are published using Trusted Publishers (OIDC):

```bash
# Download from PyPI
pip download miesc==5.1.1 --no-deps

# Compare checksum with GitHub release
sha256sum miesc-5.1.1.tar.gz
# Should match SHA256SUMS.txt from GitHub release
```

---

## Build Reproducibility

While full reproducibility is not yet implemented, you can verify the build process:

1. **Check workflow run**: Each release links to its GitHub Actions run
2. **Audit logs**: GitHub provides audit logs for all workflow executions
3. **Attestations**: SLSA attestations are planned for future releases

---

## Supply Chain Security

### SLSA Compliance

MIESC targets [SLSA Level 2](https://slsa.dev/spec/v1.0/levels):

| Requirement | Status |
|-------------|--------|
| Version controlled | ✅ Git |
| Build service | ✅ GitHub Actions |
| Build as code | ✅ Workflow files |
| Provenance | ✅ Sigstore attestations |
| Isolated builds | ✅ Ephemeral runners |

### SBOM

Software Bill of Materials (SBOM) is generated for each release:

```bash
# Download SBOM (CycloneDX format)
wget https://github.com/fboiero/MIESC/releases/download/v5.1.1/sbom.json
```

---

## Troubleshooting

### Signature Verification Fails

```
Error: signature verification failed
```

**Possible causes:**

1. **File modified**: Re-download the artifact
2. **Wrong certificate**: Ensure `.sig` and `.pem` match the artifact
3. **Clock skew**: Ensure system clock is accurate

### Certificate Expired

Sigstore certificates are short-lived (10 minutes), but signatures remain valid because they're recorded in the Rekor transparency log.

```bash
# Verify with transparency log
cosign verify-blob \
  --signature file.sig \
  --certificate file.pem \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --insecure-ignore-sct \
  file
```

---

## Security Contacts

If you discover a security issue with the release process:

- **Email**: fboiero@frvm.utn.edu.ar
- **Security Policy**: [SECURITY.md](SECURITY.md)

---

## References

- [Sigstore Documentation](https://docs.sigstore.dev/)
- [Cosign Usage](https://docs.sigstore.dev/cosign/signing_and_verification/)
- [SLSA Framework](https://slsa.dev/)
- [GitHub Artifact Attestations](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds)

---

*Last updated: February 2026*
