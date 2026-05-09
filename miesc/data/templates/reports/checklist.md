# Smart Contract Security Audit Checklist

**Contract:** {{ contract_name }}
**Auditor:** {{ auditor_name }}
**Date:** {{ audit_date }}

---

## Pre-Audit Preparation

- [ ] Received complete source code
- [ ] Verified commit hash: `{{ commit_hash }}`
- [ ] Reviewed project documentation
- [ ] Identified scope boundaries
- [ ] Set up local testing environment
- [ ] Collected compiler settings

---

## 1. Code Quality & Best Practices

### 1.1 Compiler Configuration
- [ ] Solidity version is pinned (not floating)
- [ ] Latest stable compiler version used
- [ ] Optimizer settings documented
- [ ] No deprecated features used

### 1.2 Code Organization
- [ ] Contracts follow naming conventions
- [ ] Functions have clear documentation
- [ ] State variables properly organized
- [ ] Events defined for state changes
- [ ] Error messages are descriptive

### 1.3 Testing Coverage
- [ ] Unit tests present: {{ unit_test_status }}
- [ ] Integration tests present: {{ integration_test_status }}
- [ ] Fuzz tests present: {{ fuzz_test_status }}
- [ ] Test coverage: {{ test_coverage }}%

---

## 2. Access Control

### 2.1 Authorization
- [ ] Owner/admin roles properly defined
- [ ] Role-based access control implemented
- [ ] No unprotected external functions
- [ ] tx.origin not used for authorization

### 2.2 Privilege Management
- [ ] Multi-sig for critical operations
- [ ] Timelocks for admin changes
- [ ] Emergency pause functionality
- [ ] Ownership transfer is two-step

### Findings:
{% for finding in access_control_findings %}
- **[{{ finding.severity }}]** {{ finding.title }} - `{{ finding.location }}`
{% endfor %}

---

## 3. Reentrancy Protection

### 3.1 External Calls
- [ ] Checks-Effects-Interactions pattern followed
- [ ] ReentrancyGuard used where appropriate
- [ ] No recursive calls without protection
- [ ] Callback functions protected

### 3.2 Cross-Function Reentrancy
- [ ] State consistent across function calls
- [ ] Shared state properly protected
- [ ] No view functions with side effects

### Findings:
{% for finding in reentrancy_findings %}
- **[{{ finding.severity }}]** {{ finding.title }} - `{{ finding.location }}`
{% endfor %}

---

## 4. Arithmetic Safety

### 4.1 Overflow/Underflow
- [ ] Solidity 0.8+ used OR SafeMath library
- [ ] Unchecked blocks reviewed for safety
- [ ] Division by zero protected
- [ ] Multiplication overflow considered

### 4.2 Precision
- [ ] Fixed-point arithmetic handled correctly
- [ ] Rounding errors considered
- [ ] Order of operations optimized for precision

### Findings:
{% for finding in arithmetic_findings %}
- **[{{ finding.severity }}]** {{ finding.title }} - `{{ finding.location }}`
{% endfor %}

---

## 5. External Interactions

### 5.1 External Calls
- [ ] Return values checked
- [ ] Gas stipend considered
- [ ] Call failures handled gracefully
- [ ] Untrusted contracts identified

### 5.2 Token Handling
- [ ] ERC-20 return value handling
- [ ] Fee-on-transfer tokens considered
- [ ] Rebasing tokens considered
- [ ] Token decimals handled

### Findings:
{% for finding in external_call_findings %}
- **[{{ finding.severity }}]** {{ finding.title }} - `{{ finding.location }}`
{% endfor %}

---

## 6. DeFi-Specific Checks

### 6.1 Price Oracles
- [ ] TWAP or multi-oracle used
- [ ] Oracle freshness checked
- [ ] Fallback oracle available
- [ ] Price manipulation resistant

### 6.2 Flash Loan Protection
- [ ] Same-block manipulation considered
- [ ] Liquidity checks before operations
- [ ] Atomic transaction risks assessed

### 6.3 MEV Protection
- [ ] Sandwich attack vectors identified
- [ ] Slippage protection implemented
- [ ] Commit-reveal for sensitive operations
- [ ] Private mempool consideration

### 6.4 Rug Pull Prevention
- [ ] Owner cannot freeze funds
- [ ] No unlimited minting
- [ ] Fee limits enforced
- [ ] Blacklist function reviewed

### Findings:
{% for finding in defi_findings %}
- **[{{ finding.severity }}]** {{ finding.title }} - `{{ finding.location }}`
{% endfor %}

---

## 7. Gas Optimization & DoS

### 7.1 Gas Efficiency
- [ ] No unbounded loops
- [ ] Efficient storage patterns
- [ ] Memory vs storage optimized
- [ ] Batch operations available

### 7.2 Denial of Service
- [ ] No block gas limit issues
- [ ] No unexpected reverts in loops
- [ ] Pull over push payment pattern
- [ ] No attacker-controlled arrays

### Findings:
{% for finding in gas_findings %}
- **[{{ finding.severity }}]** {{ finding.title }} - `{{ finding.location }}`
{% endfor %}

---

## 8. Cryptography & Randomness

### 8.1 Randomness
- [ ] No block.timestamp for randomness
- [ ] No block.difficulty/prevrandao abuse
- [ ] Chainlink VRF or commit-reveal used
- [ ] No predictable entropy sources

### 8.2 Signatures
- [ ] Signature replay protection
- [ ] EIP-712 typed data signing
- [ ] Nonce management
- [ ] Deadline/expiry checks

### Findings:
{% for finding in crypto_findings %}
- **[{{ finding.severity }}]** {{ finding.title }} - `{{ finding.location }}`
{% endfor %}

---

## 9. Upgrades & Proxies

### 9.1 Proxy Patterns
- [ ] Storage layout documented
- [ ] Implementation cannot be initialized
- [ ] Upgrade authorization protected
- [ ] No storage collisions

### 9.2 Upgrade Safety
- [ ] Initializers protected
- [ ] Reinitializer version tracked
- [ ] Admin functions protected
- [ ] Rollback capability

### Findings:
{% for finding in upgrade_findings %}
- **[{{ finding.severity }}]** {{ finding.title }} - `{{ finding.location }}`
{% endfor %}

---

## 10. Dependencies & Supply Chain

### 10.1 External Dependencies
- [ ] OpenZeppelin version: {{ openzeppelin_version }}
- [ ] Dependencies pinned to versions
- [ ] No known vulnerable versions
- [ ] Imports reviewed for modifications

### 10.2 Interface Conformance
- [ ] ERC standards properly implemented
- [ ] No missing interface functions
- [ ] Event signatures match standards

### Findings:
{% for finding in dependency_findings %}
- **[{{ finding.severity }}]** {{ finding.title }} - `{{ finding.location }}`
{% endfor %}

---

## Summary

### Findings by Severity

| Severity | Count | Status |
|----------|-------|--------|
| Critical | {{ critical_count }} | {{ critical_status }} |
| High | {{ high_count }} | {{ high_status }} |
| Medium | {{ medium_count }} | {{ medium_status }} |
| Low | {{ low_count }} | {{ low_status }} |
| Informational | {{ info_count }} | {{ info_status }} |

### Overall Assessment

**Risk Level:** {{ overall_risk }}

**Recommendation:** {{ overall_recommendation }}

---

## Sign-off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Lead Auditor | {{ auditor_name }} | {{ audit_date }} | ____________ |
| Reviewer | {{ reviewer_name }} | {{ review_date }} | ____________ |
| Client | {{ client_name }} | {{ sign_date }} | ____________ |

---

*Generated by [MIESC](https://github.com/fboiero/MIESC) v{{ miesc_version }}*
*Report ID: {{ report_id }}*
