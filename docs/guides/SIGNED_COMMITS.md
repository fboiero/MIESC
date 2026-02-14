# Signed Commits Guide

This guide explains how to set up GPG signing for your commits to MIESC.

---

## Why Sign Commits?

Signed commits provide:

- **Authenticity**: Proves you authored the commit
- **Integrity**: Confirms the commit hasn't been modified
- **Non-repudiation**: Creates a verifiable chain of authorship
- **Trust**: Shows as "Verified" badge on GitHub

---

## Quick Setup

### 1. Generate a GPG Key

```bash
# Generate a new GPG key
gpg --full-generate-key

# Choose:
# - RSA and RSA (default)
# - 4096 bits
# - Key does not expire (or set expiry)
# - Your name and email (must match Git config)
```

### 2. Get Your Key ID

```bash
# List your GPG keys
gpg --list-secret-keys --keyid-format=long

# Output example:
# sec   rsa4096/3AA5C34371567BD2 2024-01-01 [SC]
#       1234567890ABCDEF1234567890ABCDEF12345678
# uid                 [ultimate] Your Name <your.email@example.com>

# The key ID is: 3AA5C34371567BD2
```

### 3. Configure Git

```bash
# Set your signing key
git config --global user.signingkey 3AA5C34371567BD2

# Enable automatic commit signing
git config --global commit.gpgsign true

# Enable automatic tag signing
git config --global tag.gpgsign true
```

### 4. Add Key to GitHub

```bash
# Export your public key
gpg --armor --export 3AA5C34371567BD2

# Copy the output (including -----BEGIN PGP PUBLIC KEY BLOCK-----)
```

Then:
1. Go to GitHub → Settings → SSH and GPG keys
2. Click "New GPG key"
3. Paste your public key
4. Click "Add GPG key"

---

## Detailed Setup by Platform

### macOS

```bash
# Install GPG
brew install gnupg pinentry-mac

# Configure pinentry
echo "pinentry-program $(which pinentry-mac)" >> ~/.gnupg/gpg-agent.conf

# Restart gpg-agent
gpgconf --kill gpg-agent

# Add to shell profile (~/.zshrc or ~/.bashrc)
export GPG_TTY=$(tty)
```

### Linux

```bash
# Install GPG (usually pre-installed)
sudo apt-get install gnupg  # Debian/Ubuntu
sudo dnf install gnupg2     # Fedora

# Add to shell profile
export GPG_TTY=$(tty)
```

### Windows

1. Download [Gpg4win](https://www.gpg4win.org/)
2. Install with default options
3. Use Kleopatra GUI to generate keys
4. Configure Git:
   ```bash
   git config --global gpg.program "C:\Program Files (x86)\GnuPG\bin\gpg.exe"
   ```

---

## Signing Commits

### Automatic Signing (Recommended)

With `commit.gpgsign = true`, all commits are automatically signed:

```bash
git commit -m "Your commit message"
# GPG passphrase will be requested
```

### Manual Signing

```bash
# Sign a specific commit
git commit -S -m "Your commit message"

# Sign when amending
git commit --amend -S
```

### Verify Signatures

```bash
# Verify last commit
git verify-commit HEAD

# Verify specific commit
git verify-commit abc1234

# Show signatures in log
git log --show-signature -1
```

---

## Signing Tags

```bash
# Create signed tag
git tag -s v1.0.0 -m "Release v1.0.0"

# Verify tag signature
git verify-tag v1.0.0
```

---

## Troubleshooting

### "gpg: signing failed: No secret key"

```bash
# Check if key is available
gpg --list-secret-keys

# Verify key ID in git config
git config user.signingkey
```

### "gpg: signing failed: Inappropriate ioctl for device"

```bash
# Add to ~/.bashrc or ~/.zshrc
export GPG_TTY=$(tty)

# Reload shell
source ~/.bashrc
```

### "error: gpg failed to sign the data"

```bash
# Test GPG signing
echo "test" | gpg --clearsign

# If it fails, restart gpg-agent
gpgconf --kill gpg-agent
```

### Passphrase Not Remembered

```bash
# Configure gpg-agent cache (10 hours)
echo "default-cache-ttl 36000" >> ~/.gnupg/gpg-agent.conf
echo "max-cache-ttl 36000" >> ~/.gnupg/gpg-agent.conf

# Restart agent
gpgconf --kill gpg-agent
```

---

## Branch Protection (Maintainers)

To require signed commits on protected branches:

### GitHub UI

1. Repository → Settings → Branches
2. Edit branch protection rule for `main`
3. Check "Require signed commits"
4. Save changes

### GitHub CLI

```bash
gh api repos/fboiero/MIESC/branches/main/protection \
  -X PUT \
  -H "Accept: application/vnd.github+json" \
  -f required_signatures=true
```

---

## Verification on GitHub

Signed commits show verification status:

| Status | Meaning |
|--------|---------|
| **Verified** | Valid signature from known GPG key |
| **Partially verified** | Valid signature, key not in GitHub |
| **Unverified** | No signature or invalid |

---

## Best Practices

1. **Use a strong passphrase** for your GPG key
2. **Back up your private key** securely
3. **Set key expiration** and rotate periodically
4. **Use separate keys** for different purposes (signing, encryption)
5. **Revoke compromised keys** immediately

### Key Backup

```bash
# Export private key (keep secure!)
gpg --export-secret-keys --armor YOUR_KEY_ID > private-key.asc

# Export public key
gpg --export --armor YOUR_KEY_ID > public-key.asc

# Store in secure location (password manager, encrypted drive)
```

### Key Revocation

```bash
# Generate revocation certificate (do this now, store securely)
gpg --gen-revoke YOUR_KEY_ID > revoke.asc

# If key is compromised, import revocation
gpg --import revoke.asc
```

---

## IDE Integration

### VS Code

Install "GnuPG" extension and add to settings:

```json
{
  "git.enableCommitSigning": true
}
```

### JetBrains IDEs

1. Settings → Version Control → Git
2. Check "Sign commits using GPG"
3. Enter GPG key path if needed

---

## References

- [GitHub: Signing commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits)
- [Git: Signing Your Work](https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work)
- [GPG Documentation](https://gnupg.org/documentation/)

---

*Last updated: February 2026*
