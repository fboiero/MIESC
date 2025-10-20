#!/usr/bin/env python3
"""
MIESC Web Demo - Interactive Smart Contract Auditor

A Streamlit-based web interface for the MIESC framework that allows users to:
- Upload or paste Solidity smart contracts
- Run multi-tool security analysis
- View AI-correlated findings with risk scores
- Export analysis reports

Author: Fernando Boiero - UNDEF
License: GPL-3.0
Version: 3.3.0
"""

import streamlit as st
import sys
import json
import os
import tempfile
from pathlib import Path
from datetime import datetime
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from src.miesc_core import MIESCCore
    from src.miesc_ai_layer import AICorrelator, MetricsCalculator
    from src.miesc_risk_engine import RiskEngine
    from src.miesc_policy_mapper import PolicyMapper
except ImportError as e:
    st.error(f"❌ Import Error: {e}")
    st.info("Please ensure MIESC dependencies are installed: `pip install -r requirements.txt`")
    st.stop()

# ============================================================================
# PAGE CONFIGURATION
# ============================================================================

st.set_page_config(
    page_title="MIESC - Smart Contract Auditor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================
# CUSTOM CSS
# ============================================================================

st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
        padding: 1rem 0;
    }
    .sub-header {
        text-align: center;
        color: #666;
        font-size: 1.2rem;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 10px;
        color: white;
        text-align: center;
    }
    .finding-critical {
        border-left: 5px solid #d32f2f;
        padding-left: 1rem;
        margin: 0.5rem 0;
    }
    .finding-high {
        border-left: 5px solid #f57c00;
        padding-left: 1rem;
        margin: 0.5rem 0;
    }
    .finding-medium {
        border-left: 5px solid #fbc02d;
        padding-left: 1rem;
        margin: 0.5rem 0;
    }
    .finding-low {
        border-left: 5px solid #388e3c;
        padding-left: 1rem;
        margin: 0.5rem 0;
    }
    .stButton>button {
        width: 100%;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        color: white;
        font-weight: bold;
        border: none;
        padding: 0.75rem;
        border-radius: 5px;
    }
</style>
""", unsafe_allow_html=True)

# ============================================================================
# SESSION STATE INITIALIZATION
# ============================================================================

if 'analysis_results' not in st.session_state:
    st.session_state.analysis_results = None
if 'analysis_running' not in st.session_state:
    st.session_state.analysis_running = False

# ============================================================================
# SIDEBAR CONFIGURATION
# ============================================================================

with st.sidebar:
    st.image("https://img.shields.io/badge/MIESC-v3.3.0-blue?style=for-the-badge", use_container_width=True)

    st.markdown("### ⚙️ Analysis Configuration")

    # Tool selection
    st.markdown("#### 🛠️ Security Tools")
    use_slither = st.checkbox("Slither", value=True, help="Static analysis with 90+ detectors")
    use_mythril = st.checkbox("Mythril", value=True, help="Symbolic execution & taint analysis")
    use_aderyn = st.checkbox("Aderyn", value=True, help="Rust-based static analyzer")

    # AI correlation
    st.markdown("#### 🤖 AI Features")
    enable_ai = st.checkbox("Enable AI Correlation", value=True,
                           help="Use GPT-4o to reduce false positives (43% reduction)")

    # Risk assessment
    enable_risk = st.checkbox("Risk Scoring", value=True,
                             help="Calculate comprehensive risk scores")

    # Policy mapping
    enable_policy = st.checkbox("Policy Mapping", value=True,
                               help="Map findings to NIST/ISO/OWASP standards")

    # Timeout
    timeout = st.slider("Timeout (seconds)", 60, 600, 300, 30)

    st.markdown("---")
    st.markdown("### 📚 Resources")
    st.markdown("""
    - [Documentation](https://fboiero.github.io/MIESC)
    - [GitHub](https://github.com/fboiero/MIESC)
    - [Thesis](https://github.com/fboiero/MIESC/tree/main/thesis)
    """)

    st.markdown("---")
    st.markdown("**Author:** Fernando Boiero")
    st.markdown("**Institution:** UNDEF - IUA Córdoba")
    st.markdown("**License:** GPL-3.0")

# ============================================================================
# MAIN CONTENT
# ============================================================================

st.markdown('<div class="main-header">🛡️ MIESC Web Demo</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Multi-layer Intelligent Evaluation for Smart Contracts</div>',
           unsafe_allow_html=True)

# Info banner
st.info("""
**🎯 How it works:**
1. **Upload or paste** your Solidity smart contract below
2. **Configure** security tools and AI features in the sidebar
3. **Run analysis** to detect vulnerabilities with multiple tools
4. **Review** AI-correlated findings with risk scores and policy mappings
5. **Export** the complete report in JSON or Markdown format
""")

# ============================================================================
# INPUT SECTION
# ============================================================================

st.markdown("### 📝 Smart Contract Input")

input_method = st.radio("Choose input method:", ["Paste Code", "Upload File", "Load Example"])

contract_code = None
contract_name = "contract.sol"

if input_method == "Paste Code":
    contract_code = st.text_area(
        "Paste your Solidity contract here:",
        height=300,
        placeholder="// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n\ncontract MyContract {\n    // Your code here\n}"
    )
    contract_name = st.text_input("Contract filename:", value="contract.sol")

elif input_method == "Upload File":
    uploaded_file = st.file_uploader("Upload Solidity file (.sol)", type=["sol"])
    if uploaded_file:
        contract_code = uploaded_file.read().decode('utf-8')
        contract_name = uploaded_file.name
        st.code(contract_code, language='solidity')

elif input_method == "Load Example":
    example_choice = st.selectbox(
        "Select example contract:",
        ["Reentrancy Vulnerability", "Integer Overflow", "Unchecked Call"]
    )

    # Load example contracts
    example_contracts = {
        "Reentrancy Vulnerability": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: Reentrancy attack possible
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount; // State update AFTER external call
    }

    function getBalance() public view returns (uint256) {
        return balances[msg.sender];
    }
}""",
        "Integer Overflow": """// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0; // Vulnerable version without overflow protection

contract VulnerableToken {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    constructor(uint256 _initialSupply) {
        balances[msg.sender] = _initialSupply;
        totalSupply = _initialSupply;
    }

    // VULNERABLE: Integer overflow possible
    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount; // Overflow possible here
    }

    // VULNERABLE: Can mint unlimited tokens
    function mint(uint256 amount) public {
        balances[msg.sender] += amount; // Overflow possible
        totalSupply += amount; // Overflow possible
    }
}""",
        "Unchecked Call": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UncheckedCalls {
    address payable owner;

    constructor() {
        owner = payable(msg.sender);
    }

    // VULNERABLE: Unchecked low-level call
    function sendPayment(address payable recipient, uint256 amount) public {
        require(msg.sender == owner, "Only owner");
        recipient.call{value: amount}(""); // Return value not checked!
    }

    // VULNERABLE: Delegatecall without validation
    function executeCode(address target, bytes memory data) public {
        require(msg.sender == owner, "Only owner");
        target.delegatecall(data); // Dangerous delegatecall
    }

    receive() external payable {}
}"""
    }

    contract_code = example_contracts[example_choice]
    contract_name = f"{example_choice.replace(' ', '_').lower()}.sol"
    st.code(contract_code, language='solidity')

# ============================================================================
# ANALYSIS EXECUTION
# ============================================================================

st.markdown("### 🔬 Run Analysis")

col1, col2, col3 = st.columns([2, 1, 1])

with col1:
    run_button = st.button("🚀 Run Security Audit", disabled=not contract_code or st.session_state.analysis_running)

with col2:
    if st.session_state.analysis_results:
        st.button("🔄 Clear Results", on_click=lambda: st.session_state.update({'analysis_results': None}))

with col3:
    if st.session_state.analysis_results:
        export_format = st.selectbox("Export:", ["JSON", "Markdown"], label_visibility="collapsed")

if run_button and contract_code:
    st.session_state.analysis_running = True

    # Create temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as tmp:
        tmp.write(contract_code)
        tmp_path = tmp.name

    try:
        # Prepare tools list
        tools = []
        if use_slither:
            tools.append('slither')
        if use_mythril:
            tools.append('mythril')
        if use_aderyn:
            tools.append('aderyn')

        if not tools:
            st.error("❌ Please select at least one security tool")
            st.session_state.analysis_running = False
            st.stop()

        # Progress tracking
        progress_bar = st.progress(0)
        status_text = st.empty()

        # Phase 1: Multi-tool scanning
        status_text.text("🔬 Phase 1: Running multi-tool security scan...")
        progress_bar.progress(20)

        config = {'timeout': timeout}
        core = MIESCCore(config)
        scan_results = core.scan_contract(tmp_path, tools=tools)

        progress_bar.progress(40)

        # Phase 2: AI correlation
        correlated_findings = scan_results.get('findings', [])
        ai_metadata = {}

        if enable_ai and correlated_findings:
            status_text.text("🤖 Phase 2: Applying AI correlation...")
            progress_bar.progress(60)

            correlator = AICorrelator()
            correlated_findings = correlator.correlate_findings(correlated_findings)
            ai_metadata = correlator.get_metadata()

        # Phase 3: Risk scoring
        risk_scores = {}
        if enable_risk:
            status_text.text("⚖️ Phase 3: Calculating risk scores...")
            progress_bar.progress(75)

            risk_engine = RiskEngine()
            risk_scores = risk_engine.calculate_risk(correlated_findings)

        # Phase 4: Policy mapping
        policy_mappings = {}
        if enable_policy:
            status_text.text("📋 Phase 4: Mapping to compliance frameworks...")
            progress_bar.progress(90)

            policy_mapper = PolicyMapper()
            policy_mappings = policy_mapper.map_findings(correlated_findings)

        # Compile results
        progress_bar.progress(100)
        status_text.text("✅ Analysis complete!")

        st.session_state.analysis_results = {
            'contract_name': contract_name,
            'timestamp': datetime.now().isoformat(),
            'tools_used': tools,
            'ai_enabled': enable_ai,
            'total_findings': len(correlated_findings),
            'findings': correlated_findings,
            'risk_scores': risk_scores,
            'policy_mappings': policy_mappings,
            'ai_metadata': ai_metadata,
            'raw_results': scan_results
        }

        st.success(f"✅ Analysis complete! Found {len(correlated_findings)} findings.")

    except Exception as e:
        st.error(f"❌ Analysis failed: {str(e)}")
        st.exception(e)

    finally:
        # Cleanup
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        st.session_state.analysis_running = False
        progress_bar.empty()
        status_text.empty()

# ============================================================================
# RESULTS DISPLAY
# ============================================================================

if st.session_state.analysis_results:
    results = st.session_state.analysis_results

    st.markdown("---")
    st.markdown("## 📊 Analysis Results")

    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)

    findings = results['findings']
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}

    for finding in findings:
        severity = finding.get('severity', 'info').lower()
        if severity in severity_counts:
            severity_counts[severity] += 1

    with col1:
        st.metric("Total Findings", results['total_findings'])
    with col2:
        st.metric("Critical", severity_counts['critical'], delta=None,
                 delta_color="inverse" if severity_counts['critical'] > 0 else "off")
    with col3:
        st.metric("High", severity_counts['high'], delta=None,
                 delta_color="inverse" if severity_counts['high'] > 0 else "off")
    with col4:
        if 'overall_risk_score' in results.get('risk_scores', {}):
            risk_score = results['risk_scores']['overall_risk_score']
            st.metric("Risk Score", f"{risk_score:.1f}/100")
        else:
            st.metric("Medium + Low", severity_counts['medium'] + severity_counts['low'])

    # Severity distribution chart
    st.markdown("### 📈 Severity Distribution")

    fig = go.Figure(data=[go.Bar(
        x=list(severity_counts.keys()),
        y=list(severity_counts.values()),
        marker_color=['#d32f2f', '#f57c00', '#fbc02d', '#388e3c', '#1976d2']
    )])

    fig.update_layout(
        title="Findings by Severity",
        xaxis_title="Severity Level",
        yaxis_title="Count",
        height=300
    )

    st.plotly_chart(fig, use_container_width=True)

    # Detailed findings
    st.markdown("### 🔍 Detailed Findings")

    if findings:
        # Filter options
        filter_severity = st.multiselect(
            "Filter by severity:",
            options=['critical', 'high', 'medium', 'low', 'info'],
            default=['critical', 'high', 'medium']
        )

        filtered_findings = [f for f in findings
                           if f.get('severity', 'info').lower() in filter_severity]

        for idx, finding in enumerate(filtered_findings, 1):
            severity = finding.get('severity', 'info').lower()
            severity_class = f"finding-{severity}"

            with st.expander(f"**{idx}. [{severity.upper()}]** {finding.get('title', 'Unknown Issue')}"):
                st.markdown(f"**Description:** {finding.get('description', 'N/A')}")
                st.markdown(f"**Detector:** {finding.get('detector', 'N/A')}")
                st.markdown(f"**Tool:** {finding.get('tool', 'N/A')}")

                if 'location' in finding:
                    st.markdown(f"**Location:** Line {finding['location'].get('line', 'N/A')}")

                if enable_ai and 'ai_analysis' in finding:
                    st.markdown("**🤖 AI Analysis:**")
                    st.info(finding['ai_analysis'])

                if enable_risk and 'risk_score' in finding:
                    st.markdown(f"**⚖️ Risk Score:** {finding['risk_score']}/100")

                if enable_policy and 'policy_mappings' in finding:
                    st.markdown("**📋 Policy Mappings:**")
                    for framework, controls in finding['policy_mappings'].items():
                        st.markdown(f"- **{framework}:** {', '.join(controls)}")
    else:
        st.success("✅ No vulnerabilities detected! However, consider additional manual review.")

    # Export functionality
    st.markdown("### 💾 Export Report")

    col1, col2 = st.columns(2)

    with col1:
        json_report = json.dumps(results, indent=2)
        st.download_button(
            label="📥 Download JSON Report",
            data=json_report,
            file_name=f"miesc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )

    with col2:
        # Generate Markdown report
        md_report = f"""# MIESC Security Audit Report

**Contract:** {results['contract_name']}
**Date:** {results['timestamp']}
**Tools:** {', '.join(results['tools_used'])}
**AI Correlation:** {'Enabled' if results['ai_enabled'] else 'Disabled'}

## Summary

- **Total Findings:** {results['total_findings']}
- **Critical:** {severity_counts['critical']}
- **High:** {severity_counts['high']}
- **Medium:** {severity_counts['medium']}
- **Low:** {severity_counts['low']}

## Detailed Findings

"""
        for idx, finding in enumerate(findings, 1):
            md_report += f"""
### {idx}. [{finding.get('severity', 'INFO').upper()}] {finding.get('title', 'Unknown')}

**Description:** {finding.get('description', 'N/A')}

**Tool:** {finding.get('tool', 'N/A')}

**Location:** Line {finding.get('location', {}).get('line', 'N/A')}

---
"""

        st.download_button(
            label="📥 Download Markdown Report",
            data=md_report,
            file_name=f"miesc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
            mime="text/markdown"
        )

# ============================================================================
# FOOTER
# ============================================================================

st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #666;'>
    <p><strong>MIESC v3.3.0</strong> - Multi-layer Intelligent Evaluation for Smart Contracts</p>
    <p>Master's Thesis in Cyberdefense | Universidad de la Defensa Nacional (UNDEF)</p>
    <p>Author: Fernando Boiero | License: GPL-3.0</p>
    <p>
        <a href="https://github.com/fboiero/MIESC">GitHub</a> |
        <a href="https://fboiero.github.io/MIESC">Documentation</a> |
        <a href="https://github.com/fboiero/MIESC/blob/main/SECURITY.md">Security Policy</a>
    </p>
</div>
""", unsafe_allow_html=True)
