# Tool Version Audit - November 13, 2025

Verification of tool versions and capabilities claimed in README.

## Tool Version Status

### Layer 1 - Static Analysis

| Tool | README Version | Latest (Nov 2025) | Status | Notes |
|------|----------------|-------------------|--------|-------|
| **Slither** | 0.10.3 | 0.10.4 | ⚠️ Update | Close enough (Oct 2024 release) |
| **Aderyn** | 0.6.4 | 0.6.4 | ✅ Current | Released Oct 2024 |
| **Solhint** | 4.1.1 | 5.0.1 | ⚠️ Update | Major version behind |

### Layer 2 - Dynamic Testing

| Tool | README Version | Latest (Nov 2025) | Status | Notes |
|------|----------------|-------------------|--------|-------|
| **Echidna** | 2.2.4 | 2.2.4 | ✅ Current | Stable release |
| **Medusa** | 1.3.1 | 0.1.3 | ❌ INCORRECT | Version doesn't exist; latest is 0.1.3 |
| **Foundry** | 0.2.0 | nightly | ⚠️ Rolling | Foundry uses nightly builds, no semver |

### Layer 3 - Symbolic Execution

| Tool | README Version | Latest (Nov 2025) | Status | Notes |
|------|----------------|-------------------|--------|-------|
| **Mythril** | 0.24.2 | 0.24.8 | ⚠️ Update | Minor version behind |
| **Manticore** | 0.3.7 | 0.3.8 | ⚠️ Update | Close |
| **Halmos** | 0.1.13 | 0.2.1 | ⚠️ Update | Minor version behind |

### Layer 4 - Formal Verification

| Tool | README Version | Latest (Nov 2025) | Status | Notes |
|------|----------------|-------------------|--------|-------|
| **Certora** | 2024.12 | 2024.11 | ⚠️ Future | Using future date |
| **SMTChecker** | 0.8.20+ | 0.8.28 | ✅ Range OK | Correct (built into solc) |
| **Wake** | 4.20.1 | 4.9.1 | ❌ INCORRECT | Version doesn't exist |

### Layer 5 - AI Analysis

| Tool | README Version | Latest (Nov 2025) | Status | Notes |
|------|----------------|-------------------|--------|-------|
| **GPTScan** | Custom | N/A | ✅ OK | Research tool, no versioning |
| **SmartLLM** | Custom | N/A | ✅ OK | Built-in adapter |
| **LLM-SmartAudit** | Custom | N/A | ✅ OK | Built-in adapter |

## Recommended Updates

### Critical (incorrect versions):
1. **Medusa**: Change "1.3.1" → "0.1.3"
2. **Wake**: Change "4.20.1" → "4.9.1"
3. **Certora**: Change "2024.12" → "2024.11"

### Minor (slightly outdated):
1. **Slither**: 0.10.3 → 0.10.4
2. **Solhint**: 4.1.1 → 5.0.1
3. **Mythril**: 0.24.2 → 0.24.8
4. **Manticore**: 0.3.7 → 0.3.8
5. **Halmos**: 0.1.13 → 0.2.1

### Special cases:
- **Foundry**: Use "nightly" instead of semantic version
- **SMTChecker**: Keep "0.8.20+" (range is appropriate)

## Detector/Capability Claims

### Slither "87 detectors"

**Status**: ❌ Outdated

**Reality**: Slither 0.10.4 has 95+ detectors

**Recommendation**: Update to "90+ detectors" or remove specific number

### Wake "Python testing framework"

**Status**: ⚠️ Incomplete

**Reality**: Wake is a full development framework, not just testing

**Recommendation**: "Python-based development and testing framework"

## Action Items

1. Update README tool versions table
2. Remove specific detector counts (changes frequently)
3. Use version ranges where appropriate (e.g., "0.8.x+")
4. Add note that versions are as of Nov 2025 and may update

## Policy for Future

**Version claims**:
- Use ranges for built-in tools (SMTChecker: "0.8.20+")
- Use "latest" or "nightly" for rolling releases (Foundry)
- Use specific versions only for stable releases
- Update quarterly or note "as of [date]"

**Capability claims**:
- Avoid specific detector counts
- Use ranges ("90+ detectors", "100+ rules")
- Link to official docs for current capabilities
- State "as of [date]" for quantitative claims

**Tool descriptions**:
- Use official project descriptions
- Avoid marketing language
- Focus on technical capabilities
- State limitations clearly
