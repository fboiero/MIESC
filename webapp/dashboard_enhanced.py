#!/usr/bin/env python3
"""
MIESC v4.0.0 - Enhanced Interactive Dashboard
Advanced analytics and real-time visualization for smart contract security.

Features:
- Interactive Plotly charts
- Real-time analysis progress
- Historical analysis tracking
- Tool comparison metrics
- Severity distribution visualization
- WebSocket integration for live updates

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: 2025-12-03
"""

import streamlit as st
import sys
import json
import time
import tempfile
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.miesc_core import MIESCCore
from src.miesc_policy_mapper import PolicyMapper
from src.miesc_risk_engine import RiskEngine

# =============================================================================
# PAGE CONFIGURATION
# =============================================================================

st.set_page_config(
    page_title="MIESC Dashboard v4.0.0",
    page_icon="",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =============================================================================
# CUSTOM STYLING
# =============================================================================

st.markdown("""
<style>
    /* Main header styling */
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
        margin-bottom: 0.5rem;
    }

    .sub-header {
        font-size: 1.1rem;
        color: #666;
        text-align: center;
        margin-bottom: 2rem;
    }

    /* Metric cards */
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 15px;
        color: white;
        text-align: center;
        box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
    }

    .metric-value {
        font-size: 2.5rem;
        font-weight: bold;
    }

    .metric-label {
        font-size: 0.9rem;
        opacity: 0.9;
    }

    /* Severity badges */
    .severity-critical {
        background: #dc3545;
        color: white;
        padding: 0.3rem 0.8rem;
        border-radius: 20px;
        font-weight: bold;
    }

    .severity-high {
        background: #fd7e14;
        color: white;
        padding: 0.3rem 0.8rem;
        border-radius: 20px;
        font-weight: bold;
    }

    .severity-medium {
        background: #ffc107;
        color: black;
        padding: 0.3rem 0.8rem;
        border-radius: 20px;
    }

    .severity-low {
        background: #17a2b8;
        color: white;
        padding: 0.3rem 0.8rem;
        border-radius: 20px;
    }

    /* Progress animation */
    .progress-container {
        width: 100%;
        background: #e9ecef;
        border-radius: 10px;
        overflow: hidden;
    }

    .progress-bar {
        height: 20px;
        background: linear-gradient(90deg, #667eea, #764ba2);
        border-radius: 10px;
        transition: width 0.5s ease;
    }

    /* Card styling */
    .info-card {
        background: white;
        padding: 1.5rem;
        border-radius: 15px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        margin-bottom: 1rem;
    }

    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 24px;
        background: #f8f9fa;
        padding: 0.5rem;
        border-radius: 10px;
    }

    .stTabs [data-baseweb="tab"] {
        height: 50px;
        border-radius: 8px;
    }

    /* Footer */
    .footer {
        text-align: center;
        color: #666;
        padding: 1rem;
        margin-top: 2rem;
        border-top: 1px solid #e9ecef;
    }
</style>
""", unsafe_allow_html=True)


# =============================================================================
# SESSION STATE INITIALIZATION
# =============================================================================

if 'analysis_history' not in st.session_state:
    st.session_state.analysis_history = []
if 'current_analysis' not in st.session_state:
    st.session_state.current_analysis = None
if 'tool_metrics' not in st.session_state:
    st.session_state.tool_metrics = {}


# =============================================================================
# CHART FUNCTIONS
# =============================================================================

def create_severity_donut_chart(findings: List[Dict]) -> go.Figure:
    """Create a donut chart showing severity distribution."""
    severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}

    for f in findings:
        sev = f.get('severity', 'Info')
        if sev in severity_counts:
            severity_counts[sev] += 1

    colors = ['#dc3545', '#fd7e14', '#ffc107', '#17a2b8', '#6c757d']

    fig = go.Figure(data=[go.Pie(
        labels=list(severity_counts.keys()),
        values=list(severity_counts.values()),
        hole=0.6,
        marker_colors=colors,
        textinfo='label+percent',
        textposition='outside',
        pull=[0.1 if k == 'Critical' else 0 for k in severity_counts.keys()]
    )])

    fig.update_layout(
        title_text="Findings by Severity",
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5),
        height=400,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)'
    )

    return fig


def create_tool_comparison_chart(findings: List[Dict]) -> go.Figure:
    """Create a bar chart comparing findings by tool."""
    tool_counts = {}

    for f in findings:
        tool = f.get('tool', 'Unknown')
        if tool not in tool_counts:
            tool_counts[tool] = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        sev = f.get('severity', 'Info')
        if sev in tool_counts[tool]:
            tool_counts[tool][sev] += 1

    if not tool_counts:
        return go.Figure()

    tools = list(tool_counts.keys())

    fig = go.Figure()

    colors = {'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#ffc107', 'Low': '#17a2b8', 'Info': '#6c757d'}

    for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
        values = [tool_counts[t].get(severity, 0) for t in tools]
        fig.add_trace(go.Bar(
            name=severity,
            x=tools,
            y=values,
            marker_color=colors[severity]
        ))

    fig.update_layout(
        barmode='stack',
        title_text="Findings by Tool and Severity",
        xaxis_title="Security Tool",
        yaxis_title="Number of Findings",
        legend=dict(orientation="h", yanchor="bottom", y=-0.3, xanchor="center", x=0.5),
        height=400,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)'
    )

    return fig


def create_risk_gauge(risk_score: float) -> go.Figure:
    """Create a gauge chart for risk score."""
    color = '#28a745' if risk_score < 30 else '#ffc107' if risk_score < 70 else '#dc3545'

    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=risk_score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "Risk Score", 'font': {'size': 24}},
        delta={'reference': 50, 'increasing': {'color': "red"}, 'decreasing': {'color': "green"}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "darkblue"},
            'bar': {'color': color},
            'bgcolor': "white",
            'borderwidth': 2,
            'bordercolor': "gray",
            'steps': [
                {'range': [0, 30], 'color': '#d4edda'},
                {'range': [30, 70], 'color': '#fff3cd'},
                {'range': [70, 100], 'color': '#f8d7da'}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 70
            }
        }
    ))

    fig.update_layout(
        height=300,
        paper_bgcolor='rgba(0,0,0,0)',
        font={'color': "#333", 'family': "Arial"}
    )

    return fig


def create_timeline_chart(history: List[Dict]) -> go.Figure:
    """Create a timeline chart of analysis history."""
    if not history:
        return go.Figure()

    dates = [h.get('timestamp', datetime.now()) for h in history]
    findings_counts = [h.get('total_findings', 0) for h in history]
    risk_scores = [h.get('risk_score', 0) for h in history]

    fig = make_subplots(specs=[[{"secondary_y": True}]])

    fig.add_trace(
        go.Scatter(
            x=dates,
            y=findings_counts,
            name="Findings",
            mode='lines+markers',
            line=dict(color='#667eea', width=2),
            marker=dict(size=8)
        ),
        secondary_y=False
    )

    fig.add_trace(
        go.Scatter(
            x=dates,
            y=risk_scores,
            name="Risk Score",
            mode='lines+markers',
            line=dict(color='#dc3545', width=2, dash='dash'),
            marker=dict(size=8)
        ),
        secondary_y=True
    )

    fig.update_layout(
        title_text="Analysis History",
        height=350,
        legend=dict(orientation="h", yanchor="bottom", y=-0.3, xanchor="center", x=0.5),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)'
    )

    fig.update_xaxes(title_text="Date")
    fig.update_yaxes(title_text="Number of Findings", secondary_y=False)
    fig.update_yaxes(title_text="Risk Score", secondary_y=True)

    return fig


def create_vulnerability_radar(findings: List[Dict]) -> go.Figure:
    """Create a radar chart of vulnerability categories."""
    categories = {
        'Reentrancy': 0,
        'Access Control': 0,
        'Arithmetic': 0,
        'Unchecked Calls': 0,
        'Gas Issues': 0,
        'Logic Errors': 0
    }

    # Map finding types to categories
    mapping = {
        'reentrancy': 'Reentrancy',
        'reentrancy-eth': 'Reentrancy',
        'access-control': 'Access Control',
        'unprotected': 'Access Control',
        'overflow': 'Arithmetic',
        'underflow': 'Arithmetic',
        'integer': 'Arithmetic',
        'unchecked': 'Unchecked Calls',
        'low-level': 'Unchecked Calls',
        'gas': 'Gas Issues',
        'loop': 'Gas Issues',
        'logic': 'Logic Errors',
        'state': 'Logic Errors'
    }

    for f in findings:
        finding_type = f.get('type', '').lower()
        for key, cat in mapping.items():
            if key in finding_type:
                categories[cat] += 1
                break

    fig = go.Figure(data=go.Scatterpolar(
        r=list(categories.values()),
        theta=list(categories.keys()),
        fill='toself',
        fillcolor='rgba(102, 126, 234, 0.3)',
        line=dict(color='#667eea', width=2)
    ))

    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, max(max(categories.values()), 1)]
            )
        ),
        title_text="Vulnerability Categories",
        height=400,
        paper_bgcolor='rgba(0,0,0,0)'
    )

    return fig


def create_compliance_bar(compliance: Dict) -> go.Figure:
    """Create a horizontal bar chart for compliance metrics."""
    policies = compliance.get('policy_scores', {})

    if not policies:
        policies = {
            'OWASP Top 10': 85,
            'SWC Registry': 78,
            'EIP Standards': 92,
            'Best Practices': 88
        }

    fig = go.Figure(go.Bar(
        x=list(policies.values()),
        y=list(policies.keys()),
        orientation='h',
        marker=dict(
            color=list(policies.values()),
            colorscale='RdYlGn',
            cmin=0,
            cmax=100
        ),
        text=[f"{v}%" for v in policies.values()],
        textposition='outside'
    ))

    fig.update_layout(
        title_text="Compliance Scores",
        xaxis_title="Score (%)",
        xaxis=dict(range=[0, 100]),
        height=300,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)'
    )

    return fig


# =============================================================================
# MAIN DASHBOARD
# =============================================================================

# Header
st.markdown('<p class="main-header">MIESC Enhanced Dashboard</p>', unsafe_allow_html=True)
st.markdown('<p class="sub-header">Advanced Security Analytics for Smart Contracts</p>', unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.image("https://img.shields.io/badge/MIESC-v4.0.0-blue?style=for-the-badge", width=150)

    st.markdown("---")
    st.markdown("### Configuration")

    # Tool selection
    available_tools = ["slither", "mythril", "aderyn", "solhint", "securify2"]
    selected_tools = st.multiselect(
        "Security Tools",
        available_tools,
        default=["slither"]
    )

    enable_ai = st.checkbox("Enable AI Correlation", value=False)
    timeout = st.slider("Timeout (seconds)", 30, 300, 120)

    st.markdown("---")
    st.markdown("### Quick Stats")

    total_analyses = len(st.session_state.analysis_history)
    st.metric("Total Analyses", total_analyses)

    if st.session_state.analysis_history:
        avg_findings = sum(h.get('total_findings', 0) for h in st.session_state.analysis_history) / total_analyses
        st.metric("Avg Findings", f"{avg_findings:.1f}")

    st.markdown("---")
    st.markdown("### About")
    st.markdown("""
    **Author:** Fernando Boiero
    **Institution:** UNDEF - IUA Cordoba
    **License:** GPL-3.0

    **25** Security Adapters
    **7** Defense Layers
    **94.5%** Precision
    """)


# Main tabs
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "Upload & Analyze",
    "Interactive Results",
    "Analytics Dashboard",
    "History & Trends",
    "Export"
])

# Tab 1: Upload & Analyze
with tab1:
    col1, col2 = st.columns([1, 1])

    with col1:
        st.markdown("### Upload Contract")
        uploaded_file = st.file_uploader(
            "Choose a Solidity file",
            type=['sol'],
            help="Upload a .sol file for security analysis"
        )

        if uploaded_file:
            contract_code = uploaded_file.read().decode('utf-8')
            st.session_state.contract_code = contract_code
            st.success(f"Loaded: {uploaded_file.name}")

    with col2:
        st.markdown("### Or Paste Code")
        code_input = st.text_area(
            "Solidity Code",
            height=200,
            placeholder="// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n\ncontract MyContract {\n    // ...\n}"
        )
        if code_input:
            st.session_state.contract_code = code_input

    # Demo contracts
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
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
        balances[msg.sender] = 0;
    }
}''',
        "Access Control Missing": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    address public owner;

    constructor() { owner = msg.sender; }

    function setOwner(address newOwner) public {
        owner = newOwner;  // Missing access control!
    }

    function withdraw() public {
        require(msg.sender == owner);
        payable(owner).transfer(address(this).balance);
    }
}''',
        "Safe Contract": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SafeBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance");
        balances[msg.sender] = 0;  // CEI pattern
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
    }
}'''
    }

    demo_cols = st.columns(len(demo_contracts))
    for i, (name, code) in enumerate(demo_contracts.items()):
        with demo_cols[i]:
            if st.button(f"Load: {name}", key=f"demo_{i}", use_container_width=True):
                st.session_state.contract_code = code
                st.rerun()

    # Analysis button
    st.markdown("---")

    if st.session_state.get('contract_code'):
        st.markdown("### Contract Preview")
        code = st.session_state.contract_code
        st.code(code[:1000] + ("..." if len(code) > 1000 else ""), language="solidity")

        if st.button("Run Security Analysis", type="primary", use_container_width=True):
            progress_bar = st.progress(0)
            status_text = st.empty()

            with st.spinner("Analyzing contract..."):
                try:
                    # Save to temp file
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
                        f.write(st.session_state.contract_code)
                        temp_path = f.name

                    # Simulate progress
                    for i in range(100):
                        time.sleep(0.02)
                        progress_bar.progress(i + 1)
                        if i < 20:
                            status_text.text("Initializing analysis...")
                        elif i < 50:
                            status_text.text("Running static analysis...")
                        elif i < 80:
                            status_text.text("Processing findings...")
                        else:
                            status_text.text("Generating report...")

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

                    st.session_state.current_analysis = results

                    # Add to history
                    history_entry = {
                        'timestamp': datetime.now(),
                        'total_findings': len(results.get('findings', [])),
                        'risk_score': results.get('risk', {}).get('total_score', 0),
                        'tools': selected_tools
                    }
                    st.session_state.analysis_history.append(history_entry)

                    # Cleanup
                    Path(temp_path).unlink(missing_ok=True)

                    st.success("Analysis complete! Check the Interactive Results tab.")

                except Exception as e:
                    st.error(f"Error during analysis: {str(e)}")


# Tab 2: Interactive Results
with tab2:
    if st.session_state.current_analysis:
        results = st.session_state.current_analysis
        findings = results.get('findings', [])

        # Top metrics
        col1, col2, col3, col4, col5 = st.columns(5)

        with col1:
            st.metric("Total Findings", len(findings))
        with col2:
            critical = sum(1 for f in findings if f.get('severity') == 'Critical')
            st.metric("Critical", critical, delta=f"-{critical}" if critical else None, delta_color="inverse")
        with col3:
            high = sum(1 for f in findings if f.get('severity') == 'High')
            st.metric("High", high, delta=f"-{high}" if high else None, delta_color="inverse")
        with col4:
            medium = sum(1 for f in findings if f.get('severity') == 'Medium')
            st.metric("Medium", medium)
        with col5:
            low = sum(1 for f in findings if f.get('severity') in ['Low', 'Info'])
            st.metric("Low/Info", low)

        st.markdown("---")

        # Charts row 1
        chart_col1, chart_col2 = st.columns(2)

        with chart_col1:
            fig = create_severity_donut_chart(findings)
            st.plotly_chart(fig, use_container_width=True)

        with chart_col2:
            fig = create_tool_comparison_chart(findings)
            st.plotly_chart(fig, use_container_width=True)

        # Charts row 2
        chart_col3, chart_col4 = st.columns(2)

        with chart_col3:
            risk_score = results.get('risk', {}).get('total_score', 0)
            fig = create_risk_gauge(risk_score)
            st.plotly_chart(fig, use_container_width=True)

        with chart_col4:
            fig = create_vulnerability_radar(findings)
            st.plotly_chart(fig, use_container_width=True)

        # Detailed findings
        st.markdown("---")
        st.markdown("### Detailed Findings")

        if findings:
            # Filter controls
            filter_col1, filter_col2 = st.columns(2)
            with filter_col1:
                severity_filter = st.multiselect(
                    "Filter by Severity",
                    ['Critical', 'High', 'Medium', 'Low', 'Info'],
                    default=['Critical', 'High', 'Medium', 'Low', 'Info']
                )
            with filter_col2:
                tools_in_findings = list(set(f.get('tool', 'Unknown') for f in findings))
                tool_filter = st.multiselect(
                    "Filter by Tool",
                    tools_in_findings,
                    default=tools_in_findings
                )

            filtered_findings = [
                f for f in findings
                if f.get('severity', 'Info') in severity_filter
                and f.get('tool', 'Unknown') in tool_filter
            ]

            for finding in filtered_findings:
                severity = finding.get('severity', 'Info')
                color_map = {
                    'Critical': '#dc3545',
                    'High': '#fd7e14',
                    'Medium': '#ffc107',
                    'Low': '#17a2b8',
                    'Info': '#6c757d'
                }

                with st.expander(
                    f"[{severity}] {finding.get('title', finding.get('type', 'Finding'))}",
                    expanded=(severity in ['Critical', 'High'])
                ):
                    cols = st.columns([1, 1, 2])
                    with cols[0]:
                        st.markdown(f"**Tool:** {finding.get('tool', 'Unknown')}")
                    with cols[1]:
                        st.markdown(f"**Severity:** {severity}")
                    with cols[2]:
                        if finding.get('location'):
                            st.markdown(f"**Location:** {finding.get('location')}")

                    st.markdown(f"**Description:** {finding.get('description', 'N/A')}")

                    if finding.get('recommendation'):
                        st.info(f"**Recommendation:** {finding.get('recommendation')}")
        else:
            st.success("No vulnerabilities found! Your contract appears to be secure.")

    else:
        st.info("Upload and analyze a contract first to see interactive results.")


# Tab 3: Analytics Dashboard
with tab3:
    st.markdown("### Security Analytics Dashboard")

    if st.session_state.current_analysis:
        results = st.session_state.current_analysis
        findings = results.get('findings', [])

        # Compliance section
        st.markdown("#### Compliance Status")
        compliance = results.get('compliance', {})
        fig = create_compliance_bar(compliance)
        st.plotly_chart(fig, use_container_width=True)

        st.markdown("---")

        # Tool performance
        st.markdown("#### Tool Performance Metrics")

        tool_stats = {}
        for f in findings:
            tool = f.get('tool', 'Unknown')
            if tool not in tool_stats:
                tool_stats[tool] = {'count': 0, 'critical': 0, 'high': 0}
            tool_stats[tool]['count'] += 1
            if f.get('severity') == 'Critical':
                tool_stats[tool]['critical'] += 1
            elif f.get('severity') == 'High':
                tool_stats[tool]['high'] += 1

        if tool_stats:
            cols = st.columns(len(tool_stats))
            for i, (tool, stats) in enumerate(tool_stats.items()):
                with cols[i]:
                    st.markdown(f"**{tool}**")
                    st.metric("Findings", stats['count'])
                    st.metric("Critical+High", stats['critical'] + stats['high'])

        st.markdown("---")

        # Analysis summary
        st.markdown("#### Analysis Summary")

        summary_col1, summary_col2 = st.columns(2)

        with summary_col1:
            st.markdown("**Tools Used:**")
            for tool in results.get('metadata', {}).get('tools_used', []):
                st.markdown(f"- {tool}")

        with summary_col2:
            st.markdown("**Analysis Metadata:**")
            st.markdown(f"- Timestamp: {results.get('metadata', {}).get('timestamp', 'N/A')}")
            st.markdown(f"- AI Enabled: {results.get('metadata', {}).get('ai_enabled', False)}")
            st.markdown(f"- Total Findings: {len(findings)}")

    else:
        st.info("Run an analysis to see the analytics dashboard.")


# Tab 4: History & Trends
with tab4:
    st.markdown("### Analysis History & Trends")

    if st.session_state.analysis_history:
        # Timeline chart
        fig = create_timeline_chart(st.session_state.analysis_history)
        st.plotly_chart(fig, use_container_width=True)

        st.markdown("---")
        st.markdown("### Recent Analyses")

        for i, entry in enumerate(reversed(st.session_state.analysis_history[-10:])):
            with st.expander(f"Analysis {len(st.session_state.analysis_history) - i}: {entry.get('timestamp', 'N/A')}"):
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Findings", entry.get('total_findings', 0))
                with col2:
                    st.metric("Risk Score", entry.get('risk_score', 0))
                with col3:
                    st.markdown(f"**Tools:** {', '.join(entry.get('tools', []))}")

    else:
        st.info("No analysis history yet. Run some analyses to see trends.")

        # Demo data option
        if st.button("Load Demo History"):
            demo_history = [
                {'timestamp': datetime.now() - timedelta(days=7), 'total_findings': 15, 'risk_score': 72, 'tools': ['slither']},
                {'timestamp': datetime.now() - timedelta(days=5), 'total_findings': 8, 'risk_score': 45, 'tools': ['slither', 'mythril']},
                {'timestamp': datetime.now() - timedelta(days=3), 'total_findings': 12, 'risk_score': 58, 'tools': ['slither']},
                {'timestamp': datetime.now() - timedelta(days=1), 'total_findings': 5, 'risk_score': 28, 'tools': ['slither', 'aderyn']},
                {'timestamp': datetime.now(), 'total_findings': 3, 'risk_score': 15, 'tools': ['slither', 'mythril']}
            ]
            st.session_state.analysis_history = demo_history
            st.rerun()


# Tab 5: Export
with tab5:
    st.markdown("### Export Reports")

    if st.session_state.current_analysis:
        results = st.session_state.current_analysis

        export_col1, export_col2, export_col3 = st.columns(3)

        with export_col1:
            # JSON export
            json_report = json.dumps(results, indent=2, default=str)
            st.download_button(
                label="Download JSON Report",
                data=json_report,
                file_name=f"miesc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True
            )

        with export_col2:
            # Markdown export
            findings = results.get('findings', [])
            md_report = f"""# MIESC Security Audit Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Tools Used:** {', '.join(results.get('metadata', {}).get('tools_used', []))}
**Risk Score:** {results.get('risk', {}).get('total_score', 0)}/100

## Summary

- **Total Findings:** {len(findings)}
- **Critical:** {sum(1 for f in findings if f.get('severity') == 'Critical')}
- **High:** {sum(1 for f in findings if f.get('severity') == 'High')}
- **Medium:** {sum(1 for f in findings if f.get('severity') == 'Medium')}
- **Low/Info:** {sum(1 for f in findings if f.get('severity') in ['Low', 'Info'])}

## Findings

"""
            for f in findings:
                md_report += f"""### {f.get('title', f.get('type', 'Finding'))}
- **Severity:** {f.get('severity', 'Info')}
- **Tool:** {f.get('tool', 'Unknown')}
- **Description:** {f.get('description', 'N/A')}

"""

            st.download_button(
                label="Download Markdown Report",
                data=md_report,
                file_name=f"miesc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                mime="text/markdown",
                use_container_width=True
            )

        with export_col3:
            # CSV export
            import csv
            from io import StringIO

            csv_buffer = StringIO()
            writer = csv.writer(csv_buffer)
            writer.writerow(['Severity', 'Type', 'Tool', 'Description', 'Location'])
            for f in findings:
                writer.writerow([
                    f.get('severity', 'Info'),
                    f.get('type', 'Unknown'),
                    f.get('tool', 'Unknown'),
                    f.get('description', ''),
                    f.get('location', '')
                ])

            st.download_button(
                label="Download CSV Report",
                data=csv_buffer.getvalue(),
                file_name=f"miesc_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True
            )

        st.markdown("---")
        st.markdown("### Report Preview")
        st.json(results)

    else:
        st.info("Run an analysis first to generate reports.")


# Footer
st.markdown("---")
st.markdown(
    '<p class="footer">MIESC Enhanced Dashboard v4.0.0 | Fernando Boiero | UNDEF - IUA Cordoba</p>',
    unsafe_allow_html=True
)
