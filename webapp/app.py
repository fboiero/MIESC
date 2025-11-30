#!/usr/bin/env python3
"""
MIESC v4.0.0 - Interactive Web Dashboard
Streamlit-based interface for smart contract security analysis

Author: Fernando Boiero
Institution: UNDEF - IUA Córdoba
"""

import streamlit as st
import sys
import json
import tempfile
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.miesc_core import MIESCCore
from src.miesc_policy_mapper import PolicyMapper
from src.miesc_risk_engine import RiskEngine

# Page configuration
st.set_page_config(
    page_title="MIESC v4.0.0",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #667eea;
        text-align: center;
        margin-bottom: 0.5rem;
    }
    .sub-header {
        font-size: 1.1rem;
        color: #666;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
    }
    .severity-critical { color: #dc3545; font-weight: bold; }
    .severity-high { color: #fd7e14; font-weight: bold; }
    .severity-medium { color: #ffc107; }
    .severity-low { color: #17a2b8; }
    .stTabs [data-baseweb="tab-list"] {
        gap: 24px;
    }
</style>
""", unsafe_allow_html=True)

# Header
st.markdown('<p class="main-header">🔍 MIESC v4.0.0</p>', unsafe_allow_html=True)
st.markdown('<p class="sub-header">Multi-layer Intelligent Evaluation for Smart Contracts</p>', unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.image("https://img.shields.io/badge/version-4.0.0-blue", width=100)
    st.markdown("---")
    st.markdown("### Configuration")

    # Tool selection
    available_tools = ["slither", "mythril", "aderyn", "solhint", "securify2"]
    selected_tools = st.multiselect(
        "Security Tools",
        available_tools,
        default=["slither"]
    )

    # AI options
    enable_ai = st.checkbox("Enable AI Correlation", value=False)

    # Timeout
    timeout = st.slider("Timeout per tool (seconds)", 30, 300, 120)

    st.markdown("---")
    st.markdown("### About")
    st.markdown("""
    **Author:** Fernando Boiero
    **Institution:** UNDEF - IUA Córdoba
    **License:** GPL-3.0

    📊 25 Security Adapters
    🛡️ 7 Defense Layers
    🎯 94.5% Precision
    """)

# Main content
tab1, tab2, tab3, tab4 = st.tabs(["📤 Upload & Analyze", "📊 Results", "📋 Report", "ℹ️ System Status"])

# Initialize session state
if 'results' not in st.session_state:
    st.session_state.results = None
if 'contract_code' not in st.session_state:
    st.session_state.contract_code = None

with tab1:
    st.markdown("### Upload Smart Contract")

    col1, col2 = st.columns([1, 1])

    with col1:
        uploaded_file = st.file_uploader(
            "Choose a Solidity file",
            type=['sol'],
            help="Upload a .sol file for security analysis"
        )

        if uploaded_file:
            st.session_state.contract_code = uploaded_file.read().decode('utf-8')
            st.success(f"✅ Loaded: {uploaded_file.name}")

    with col2:
        st.markdown("**Or paste code directly:**")
        code_input = st.text_area(
            "Solidity Code",
            height=200,
            placeholder="// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n\ncontract MyContract {\n    // ...\n}"
        )
        if code_input:
            st.session_state.contract_code = code_input

    # Sample contracts
    st.markdown("---")
    st.markdown("### Quick Demo Contracts")

    demo_contracts = {
        "Reentrancy Vulnerable": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance");

        // Vulnerable: external call before state update
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0;  // State updated after external call!
    }
}''',
        "Integer Overflow": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;  // Old version without SafeMath

contract TokenSale {
    mapping(address => uint256) public balances;
    uint256 public price = 1 ether;

    function buy(uint256 amount) public payable {
        // Potential overflow in older Solidity versions
        uint256 cost = amount * price;
        require(msg.value >= cost, "Not enough ETH");
        balances[msg.sender] += amount;
    }
}''',
        "Access Control Missing": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // Missing access control!
    function setOwner(address newOwner) public {
        owner = newOwner;
    }

    function withdraw() public {
        require(msg.sender == owner, "Not owner");
        payable(owner).transfer(address(this).balance);
    }
}'''
    }

    demo_cols = st.columns(len(demo_contracts))
    for i, (name, code) in enumerate(demo_contracts.items()):
        with demo_cols[i]:
            if st.button(f"Load: {name}", key=f"demo_{i}"):
                st.session_state.contract_code = code
                st.rerun()

    # Analysis button
    st.markdown("---")
    if st.session_state.contract_code:
        st.markdown("### Contract Preview")
        st.code(st.session_state.contract_code[:1000] + ("..." if len(st.session_state.contract_code) > 1000 else ""), language="solidity")

        if st.button("🚀 Run Security Analysis", type="primary", use_container_width=True):
            with st.spinner("Analyzing contract..."):
                try:
                    # Save to temp file
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
                        f.write(st.session_state.contract_code)
                        temp_path = f.name

                    # Run analysis
                    core = MIESCCore()
                    results = core.scan(temp_path, tools=selected_tools)

                    # Add metadata
                    results['metadata'] = {
                        'timestamp': datetime.now().isoformat(),
                        'tools_used': selected_tools,
                        'ai_enabled': enable_ai
                    }

                    # Policy mapping
                    mapper = PolicyMapper()
                    results['compliance'] = mapper.map_to_policies(results.get('findings', []))

                    # Risk assessment
                    risk_engine = RiskEngine()
                    results['risk'] = risk_engine.assess(results.get('findings', []))

                    st.session_state.results = results
                    st.success("✅ Analysis complete! Go to Results tab.")

                    # Cleanup
                    Path(temp_path).unlink(missing_ok=True)

                except Exception as e:
                    st.error(f"❌ Error during analysis: {str(e)}")

with tab2:
    if st.session_state.results:
        results = st.session_state.results
        findings = results.get('findings', [])

        # Summary metrics
        st.markdown("### Summary")
        col1, col2, col3, col4, col5 = st.columns(5)

        severity_counts = results.get('summary', {})

        with col1:
            st.metric("Total Findings", len(findings))
        with col2:
            st.metric("Critical", severity_counts.get('Critical', 0), delta_color="inverse")
        with col3:
            st.metric("High", severity_counts.get('High', 0), delta_color="inverse")
        with col4:
            st.metric("Medium", severity_counts.get('Medium', 0))
        with col5:
            st.metric("Low/Info", severity_counts.get('Low', 0) + severity_counts.get('Info', 0))

        # Findings table
        st.markdown("---")
        st.markdown("### Detailed Findings")

        if findings:
            for i, finding in enumerate(findings):
                severity = finding.get('severity', 'Info')
                severity_color = {
                    'Critical': '🔴',
                    'High': '🟠',
                    'Medium': '🟡',
                    'Low': '🔵',
                    'Info': '⚪'
                }.get(severity, '⚪')

                with st.expander(f"{severity_color} {finding.get('title', 'Finding')} [{severity}]", expanded=(severity in ['Critical', 'High'])):
                    st.markdown(f"**Tool:** {finding.get('tool', 'Unknown')}")
                    st.markdown(f"**Severity:** {severity}")
                    st.markdown(f"**Description:** {finding.get('description', 'N/A')}")
                    if finding.get('location'):
                        st.markdown(f"**Location:** {finding.get('location')}")
                    if finding.get('recommendation'):
                        st.info(f"💡 **Recommendation:** {finding.get('recommendation')}")
        else:
            st.success("🎉 No vulnerabilities found!")

        # Compliance
        st.markdown("---")
        st.markdown("### Compliance Status")
        compliance = results.get('compliance', {})

        if compliance:
            comp_col1, comp_col2 = st.columns(2)
            with comp_col1:
                score = compliance.get('score', 100)
                st.metric("Compliance Score", f"{score}/100")
            with comp_col2:
                policies = compliance.get('mapped_policies', [])
                st.metric("Policies Checked", len(policies))

        # Risk assessment
        st.markdown("---")
        st.markdown("### Risk Assessment")
        risk = results.get('risk', {})

        if risk:
            risk_score = risk.get('total_score', 0)
            risk_level = "Low" if risk_score < 30 else "Medium" if risk_score < 70 else "High"
            risk_color = "green" if risk_level == "Low" else "orange" if risk_level == "Medium" else "red"

            st.markdown(f"**Risk Level:** :{risk_color}[{risk_level}] (Score: {risk_score}/100)")

    else:
        st.info("📤 Upload and analyze a contract first to see results here.")

with tab3:
    if st.session_state.results:
        st.markdown("### Export Report")

        col1, col2 = st.columns(2)

        with col1:
            # JSON export
            json_report = json.dumps(st.session_state.results, indent=2, default=str)
            st.download_button(
                label="📥 Download JSON Report",
                data=json_report,
                file_name=f"miesc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )

        with col2:
            # Markdown export
            findings = st.session_state.results.get('findings', [])
            md_report = f"""# MIESC Security Audit Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Tools Used:** {', '.join(st.session_state.results.get('metadata', {}).get('tools_used', []))}

## Summary

- **Total Findings:** {len(findings)}
- **Critical:** {st.session_state.results.get('summary', {}).get('Critical', 0)}
- **High:** {st.session_state.results.get('summary', {}).get('High', 0)}
- **Medium:** {st.session_state.results.get('summary', {}).get('Medium', 0)}
- **Low:** {st.session_state.results.get('summary', {}).get('Low', 0)}

## Findings

"""
            for f in findings:
                md_report += f"""### {f.get('title', 'Finding')}
- **Severity:** {f.get('severity', 'Info')}
- **Tool:** {f.get('tool', 'Unknown')}
- **Description:** {f.get('description', 'N/A')}

"""

            st.download_button(
                label="📥 Download Markdown Report",
                data=md_report,
                file_name=f"miesc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                mime="text/markdown"
            )

        # Preview
        st.markdown("---")
        st.markdown("### Report Preview")
        st.json(st.session_state.results)

    else:
        st.info("📤 Upload and analyze a contract first to generate a report.")

with tab4:
    st.markdown("### System Status")

    # Check tools
    import subprocess

    tools_status = {}

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### Security Tools")

        # Slither
        try:
            result = subprocess.run(['slither', '--version'], capture_output=True, text=True, timeout=5)
            tools_status['Slither'] = ('✅', result.stdout.strip() or result.stderr.strip())
        except:
            tools_status['Slither'] = ('❌', 'Not installed')

        # Mythril
        try:
            result = subprocess.run(['myth', 'version'], capture_output=True, text=True, timeout=5)
            tools_status['Mythril'] = ('✅', result.stdout.strip())
        except:
            tools_status['Mythril'] = ('❌', 'Not installed')

        # Solc
        try:
            result = subprocess.run(['solc', '--version'], capture_output=True, text=True, timeout=5)
            version = result.stdout.split('\n')[1] if result.stdout else 'Unknown'
            tools_status['Solc'] = ('✅', version)
        except:
            tools_status['Solc'] = ('❌', 'Not installed')

        for tool, (status, version) in tools_status.items():
            st.markdown(f"{status} **{tool}:** {version}")

    with col2:
        st.markdown("#### AI/LLM Services")

        # Ollama
        try:
            result = subprocess.run(['ollama', 'list'], capture_output=True, text=True, timeout=5)
            model_count = len(result.stdout.strip().split('\n')) - 1
            st.markdown(f"✅ **Ollama:** {model_count} models available")
        except:
            st.markdown("❌ **Ollama:** Not running")

        st.markdown("---")
        st.markdown("#### MIESC Info")
        st.markdown("""
        - **Version:** 4.0.0
        - **Adapters:** 25
        - **Layers:** 7
        - **Precision:** 94.5%
        - **Recall:** 92.8%
        """)

# Footer
st.markdown("---")
st.markdown(
    '<p style="text-align: center; color: #666;">MIESC v4.0.0 | Fernando Boiero | UNDEF - IUA Córdoba</p>',
    unsafe_allow_html=True
)
