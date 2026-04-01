"""
Tests for DeepAuditAgent - Agentic Deep Audit

Tests the 4-phase agentic loop: reconnaissance, targeted scan,
deep investigation, and synthesis.
"""

import time
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from src.agents.deep_audit_agent import (
    AuditPhase,
    DeepAuditAgent,
    DeepAuditConfig,
    ReconResult,
    ScanResult,
    RISK_PATTERNS,
    run_deep_audit,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VULNERABLE_CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableVault {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() { owner = msg.sender; }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;
    }

    function destroy() external {
        selfdestruct(payable(msg.sender));
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function lottery() external view returns (bool) {
        return uint256(keccak256(abi.encodePacked(block.timestamp))) % 2 == 0;
    }

    receive() external payable {}
}
"""

DEFI_CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract DeFiPool {
    mapping(address => uint256) public liquidity;
    address public oracle;
    uint256 public totalSupply;

    function swap(address tokenIn, uint256 amount) external {
        uint256 price = getPrice(tokenIn);
        uint256 amountOut = amount * price / 1e18;
        IERC20(tokenIn).transferFrom(msg.sender, address(this), amount);
    }

    function flashLoan(uint256 amount) external {
        uint256 balanceBefore = address(this).balance;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(address(this).balance >= balanceBefore, "Repay");
    }

    function getPrice(address token) public view returns (uint256) {
        return 1e18;
    }
}
"""

TOKEN_CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SimpleToken {
    string public name = "Test";
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function transfer(address to, uint256 value) external returns (bool) {
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }
}
"""

PROXY_CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/proxy/utils/Initializable.sol";

contract ProxyImpl is Initializable {
    address public implementation;

    function upgradeTo(address newImpl) external {
        implementation = newImpl;
    }

    fallback() external payable {
        (bool success, ) = implementation.delegatecall(msg.data);
        require(success);
    }
}
"""


@pytest.fixture
def tmp_contract(tmp_path):
    """Create a temporary contract file."""
    path = tmp_path / "VulnerableVault.sol"
    path.write_text(VULNERABLE_CONTRACT)
    return str(path)


@pytest.fixture
def tmp_defi(tmp_path):
    path = tmp_path / "DeFiPool.sol"
    path.write_text(DEFI_CONTRACT)
    return str(path)


@pytest.fixture
def tmp_token(tmp_path):
    path = tmp_path / "SimpleToken.sol"
    path.write_text(TOKEN_CONTRACT)
    return str(path)


@pytest.fixture
def tmp_proxy(tmp_path):
    path = tmp_path / "ProxyImpl.sol"
    path.write_text(PROXY_CONTRACT)
    return str(path)


@pytest.fixture
def config():
    return DeepAuditConfig(
        timeout_seconds=60,
        max_iterations=3,
        enable_llm=False,
        enable_rag=False,
        enable_taint=False,
        enable_call_graph=False,
        enable_exploit_chains=False,
    )


@pytest.fixture
def agent(config):
    return DeepAuditAgent(config=config)


# ---------------------------------------------------------------------------
# Configuration Tests
# ---------------------------------------------------------------------------

class TestDeepAuditConfig:
    def test_defaults(self):
        cfg = DeepAuditConfig()
        assert cfg.timeout_seconds == 600
        assert cfg.max_iterations == 5
        assert cfg.enable_llm is True
        assert cfg.llm_provider == "auto"
        assert cfg.llm_model == "mistral:latest"
        assert cfg.enable_rag is True
        assert cfg.enable_taint is True
        assert cfg.enable_call_graph is True
        assert cfg.enable_exploit_chains is True
        assert cfg.fp_threshold == 0.5
        assert cfg.max_workers == 4

    def test_custom_config(self):
        cfg = DeepAuditConfig(
            timeout_seconds=120,
            max_iterations=2,
            enable_llm=False,
            llm_provider="anthropic",
        )
        assert cfg.timeout_seconds == 120
        assert cfg.max_iterations == 2
        assert cfg.enable_llm is False
        assert cfg.llm_provider == "anthropic"


class TestAuditPhase:
    def test_phases(self):
        assert AuditPhase.RECONNAISSANCE.value == "reconnaissance"
        assert AuditPhase.TARGETED_SCAN.value == "targeted_scan"
        assert AuditPhase.DEEP_INVESTIGATION.value == "deep_investigation"
        assert AuditPhase.SYNTHESIS.value == "synthesis"


# ---------------------------------------------------------------------------
# Agent Initialization
# ---------------------------------------------------------------------------

class TestDeepAuditAgentInit:
    def test_initialization(self, agent):
        assert agent.agent_name == "DeepAuditAgent"
        assert agent.agent_type == "coordinator"
        assert "agentic_audit" in agent.capabilities
        assert "adaptive_tool_selection" in agent.capabilities

    def test_context_types(self, agent):
        types = agent.get_context_types()
        assert "deep_audit_reconnaissance" in types
        assert "deep_audit_initial_findings" in types
        assert "deep_audit_enriched_findings" in types
        assert "deep_audit_report" in types

    def test_custom_config(self):
        cfg = DeepAuditConfig(timeout_seconds=30, enable_llm=False)
        agent = DeepAuditAgent(config=cfg)
        assert agent.config.timeout_seconds == 30
        assert agent.config.enable_llm is False


# ---------------------------------------------------------------------------
# Phase 1: Reconnaissance
# ---------------------------------------------------------------------------

class TestReconnaissance:
    def test_risk_profile_general(self, agent, tmp_contract):
        profile = agent._classify_risk_profile(VULNERABLE_CONTRACT)
        assert profile["has_external_calls"] is True
        assert profile["has_selfdestruct"] is True
        assert profile["solidity_version"] == "^0.8.20"

    def test_risk_profile_defi(self, agent):
        profile = agent._classify_risk_profile(DEFI_CONTRACT)
        assert profile["is_defi"] is True
        assert profile["scores"].get("defi", 0) >= 2

    def test_risk_profile_token(self, agent):
        profile = agent._classify_risk_profile(TOKEN_CONTRACT)
        assert profile["scores"].get("token", 0) >= 1  # Transfer, balanceOf, totalSupply, mint

    def test_risk_profile_proxy(self, agent):
        profile = agent._classify_risk_profile(PROXY_CONTRACT)
        assert profile["is_proxy"] is True

    def test_solidity_version_extraction(self, agent):
        assert agent._extract_solidity_version("pragma solidity ^0.8.20;") == "^0.8.20"
        assert agent._extract_solidity_version("pragma solidity 0.8.0;") == "0.8.0"
        assert agent._extract_solidity_version("no pragma") == "unknown"

    def test_framework_detection_openzeppelin(self, agent, tmp_path):
        path = tmp_path / "OZContract.sol"
        path.write_text('import "@openzeppelin/contracts/token/ERC20.sol";\ncontract T {}')
        assert agent._detect_framework(str(path)) == "openzeppelin"

    def test_framework_detection_custom(self, agent, tmp_contract):
        assert agent._detect_framework(tmp_contract) == "custom"

    def test_attack_surface_score(self, agent):
        score = agent._compute_attack_surface(
            entries=["withdraw", "deposit", "destroy"],
            ext_calls=["msg.sender.call", "selfdestruct"],
            taint=[1, 2],
        )
        assert 0 <= score <= 100
        assert score > 0

    def test_attack_surface_empty(self, agent):
        score = agent._compute_attack_surface([], [], [])
        assert score == 0.0

    def test_phase_recon(self, agent, tmp_contract):
        recon = agent._phase_reconnaissance(tmp_contract, VULNERABLE_CONTRACT)
        assert isinstance(recon, ReconResult)
        assert recon.risk_profile["has_selfdestruct"] is True
        assert recon.duration_ms > 0


# ---------------------------------------------------------------------------
# Phase 2: Targeted Scan
# ---------------------------------------------------------------------------

class TestTargetedScan:
    def test_tool_selection_general(self, agent):
        recon = ReconResult(
            risk_profile={
                "primary": "general",
                "is_defi": False, "is_token": False,
                "is_proxy": False, "is_bridge": False,
                "has_external_calls": True, "has_selfdestruct": True,
            }
        )
        tools = agent._select_tools(recon)
        assert "slither" in tools
        assert "aderyn" in tools
        assert "mythril" in tools  # has_external_calls + has_selfdestruct

    def test_tool_selection_defi(self, agent):
        recon = ReconResult(
            risk_profile={
                "primary": "defi",
                "is_defi": True, "is_token": False,
                "is_proxy": False, "is_bridge": False,
                "has_external_calls": True, "has_selfdestruct": False,
            }
        )
        tools = agent._select_tools(recon)
        assert "defi" in tools
        assert "mev_detector" in tools

    def test_tool_selection_proxy(self, agent):
        recon = ReconResult(
            risk_profile={
                "primary": "proxy",
                "is_defi": False, "is_token": False,
                "is_proxy": True, "is_bridge": False,
                "has_external_calls": True, "has_selfdestruct": False,
            }
        )
        tools = agent._select_tools(recon)
        assert "upgradability_checker" in tools

    def test_tool_selection_bridge(self, agent):
        recon = ReconResult(
            risk_profile={
                "primary": "bridge",
                "is_defi": False, "is_token": False,
                "is_proxy": False, "is_bridge": True,
                "has_external_calls": False, "has_selfdestruct": False,
            }
        )
        tools = agent._select_tools(recon)
        assert "crosschain" in tools
        assert "bridge_monitor" in tools

    def test_tool_deduplication(self, agent):
        recon = ReconResult(
            risk_profile={
                "primary": "general",
                "is_defi": False, "is_token": False,
                "is_proxy": False, "is_bridge": False,
                "has_external_calls": True, "has_selfdestruct": True,
                "has_assembly": True,
            }
        )
        tools = agent._select_tools(recon)
        assert len(tools) == len(set(tools))  # No duplicates


# ---------------------------------------------------------------------------
# Phase 3: Deep Investigation
# ---------------------------------------------------------------------------

class TestDeepInvestigation:
    def test_extract_function_name_dict(self, agent):
        finding = {"location": {"file": "test.sol", "line": 10, "function": "withdraw"}}
        assert agent._extract_function_name(finding) == "withdraw"

    def test_extract_function_name_unknown(self, agent):
        finding = {"location": {"file": "test.sol", "line": 10, "function": "unknown"}}
        assert agent._extract_function_name(finding) is None

    def test_extract_function_name_none(self, agent):
        finding = {"location": "test.sol:10"}
        assert agent._extract_function_name(finding) is None

    def test_should_trigger_reentrancy(self, agent):
        finding = {"type": "reentrancy", "severity": "high"}
        tool = agent._should_trigger_tool(finding, ["slither", "aderyn"], set())
        assert tool == "mythril"

    def test_should_trigger_delegatecall(self, agent):
        finding = {"type": "delegatecall-injection", "severity": "critical"}
        tool = agent._should_trigger_tool(finding, ["slither"], set())
        assert tool == "halmos"

    def test_should_trigger_access_control(self, agent):
        finding = {"type": "access-control-missing", "severity": "high"}
        tool = agent._should_trigger_tool(finding, ["slither"], set())
        assert tool == "echidna"

    def test_should_not_trigger_low(self, agent):
        finding = {"type": "reentrancy", "severity": "low"}
        tool = agent._should_trigger_tool(finding, ["slither"], set())
        assert tool is None

    def test_should_not_trigger_already_run(self, agent):
        finding = {"type": "reentrancy", "severity": "high"}
        tool = agent._should_trigger_tool(finding, ["slither", "mythril"], set())
        assert tool is None

    def test_should_not_trigger_already_triggered(self, agent):
        finding = {"type": "reentrancy", "severity": "high"}
        tool = agent._should_trigger_tool(finding, ["slither"], {"mythril"})
        assert tool is None

    def test_check_mitigation_found(self, agent):
        source = "contract Safe { modifier nonReentrant() { _; } function withdraw() nonReentrant external {} }"
        rag_data = {"fix_pattern": "Use nonReentrant modifier from ReentrancyGuard"}
        assert agent._check_mitigation(source, rag_data) is True

    def test_check_mitigation_not_found(self, agent):
        source = "contract Unsafe { function withdraw() external {} }"
        rag_data = {"fix_pattern": "Use nonReentrant modifier from ReentrancyGuard"}
        assert agent._check_mitigation(source, rag_data) is False

    def test_check_mitigation_no_fix(self, agent):
        assert agent._check_mitigation("contract T {}", {}) is False

    def test_investigation_empty_queue(self, agent, tmp_contract):
        recon = ReconResult()
        scan = ScanResult(tools_run=["slither"], filtered_findings=[])
        result = agent._phase_deep_investigation(
            tmp_contract, VULNERABLE_CONTRACT, recon, scan
        )
        assert result["iterations"] == 0
        assert result["enriched_count"] == 0

    def test_investigation_with_findings(self, agent, tmp_contract):
        agent._start_time = time.monotonic()  # Required for timeout check
        agent.contract_path = tmp_contract
        recon = ReconResult()
        scan = ScanResult(
            tools_run=["slither", "aderyn"],
            filtered_findings=[
                {"id": "f1", "title": "reentrancy", "type": "reentrancy", "severity": "High"},
                {"id": "f2", "title": "selfdestruct", "type": "selfdestruct", "severity": "High"},
                {"id": "f3", "title": "info", "type": "solc-version", "severity": "low"},
            ],
        )
        result = agent._phase_deep_investigation(
            tmp_contract, VULNERABLE_CONTRACT, recon, scan
        )
        assert result["iterations"] >= 1
        assert result["enriched_count"] == 2  # Only HIGH findings enriched


# ---------------------------------------------------------------------------
# Phase 4: Synthesis
# ---------------------------------------------------------------------------

class TestSynthesis:
    def test_template_narrative_critical(self, agent):
        summary = {"CRITICAL": 2, "HIGH": 3, "total": 10, "tools_used": ["slither"], "iterations": 2}
        narrative = agent._template_narrative(summary, [])
        assert "CRITICAL" in narrative
        assert "Immediate remediation" in narrative

    def test_template_narrative_high(self, agent):
        summary = {"CRITICAL": 0, "HIGH": 2, "total": 5, "tools_used": ["slither", "aderyn"], "iterations": 1}
        narrative = agent._template_narrative(summary, [])
        assert "HIGH" in narrative
        assert "mainnet deployment" in narrative

    def test_template_narrative_clean(self, agent):
        summary = {"CRITICAL": 0, "HIGH": 0, "total": 0, "tools_used": ["slither"], "iterations": 0}
        narrative = agent._template_narrative(summary, [])
        assert "LOW" in narrative
        assert "No significant" in narrative

    def test_template_narrative_with_chains(self, agent):
        summary = {"CRITICAL": 1, "HIGH": 0, "total": 3, "tools_used": ["slither"], "iterations": 1}
        chains = [{"name": "Reentrancy + Unchecked Call"}]
        narrative = agent._template_narrative(summary, chains)
        assert "exploit chain" in narrative

    def test_synthesis_no_llm(self, agent, tmp_contract):
        recon = ReconResult(risk_profile={"primary": "general"})
        scan = ScanResult(tools_run=["slither"], filtered_findings=[
            {"id": "f1", "severity": "high", "title": "test"},
        ])
        investigation = {
            "findings": scan.filtered_findings,
            "exploit_chains": [],
            "iterations": 1,
        }
        result = agent._phase_synthesis(
            tmp_contract, VULNERABLE_CONTRACT, recon, scan, investigation
        )
        assert "findings" in result
        assert "summary" in result
        assert "narrative" in result
        assert result["has_llm_narrative"] is False
        assert result["summary"]["HIGH"] == 1


# ---------------------------------------------------------------------------
# Timeout Management
# ---------------------------------------------------------------------------

class TestTimeout:
    def test_timeout_not_exceeded(self, agent):
        agent._start_time = time.monotonic()
        assert agent._timeout_exceeded() is False

    def test_timeout_exceeded(self, agent):
        agent._start_time = time.monotonic() - 9999
        assert agent._timeout_exceeded() is True

    def test_remaining_seconds(self, agent):
        agent._start_time = time.monotonic()
        remaining = agent._remaining_seconds()
        assert remaining > 0
        assert remaining <= agent.config.timeout_seconds

    def test_remaining_after_timeout(self, agent):
        agent._start_time = time.monotonic() - 9999
        assert agent._remaining_seconds() == 0


# ---------------------------------------------------------------------------
# Full Flow (Mocked)
# ---------------------------------------------------------------------------

class TestFullFlow:
    @patch("src.mcp_core.context_bus.get_context_bus")
    @patch("src.agents.deep_audit_agent.DeepAuditAgent._get_ml_orchestrator")
    def test_analyze_minimal(self, mock_orch, mock_bus, agent, tmp_contract):
        """Test full analyze with all external deps mocked."""
        mock_bus.return_value = MagicMock()
        agent.bus = MagicMock()

        mock_ml = MagicMock()
        mock_ml.analyze.return_value = MagicMock(
            raw_findings=[],
            ml_filtered_findings=[],
            tools_success=["slither"],
        )
        mock_orch.return_value = mock_ml

        result = agent.analyze(tmp_contract)

        assert "contract" in result
        assert "phases" in result
        assert "findings" in result
        assert "summary" in result
        assert "metadata" in result
        assert result["phases"]["reconnaissance"]["risk_profile"]["has_selfdestruct"] is True

    @patch("src.mcp_core.context_bus.get_context_bus")
    @patch("src.agents.deep_audit_agent.DeepAuditAgent._get_ml_orchestrator")
    def test_analyze_with_findings(self, mock_orch, mock_bus, tmp_contract):
        mock_bus.return_value = MagicMock()

        config = DeepAuditConfig(
            timeout_seconds=30,
            max_iterations=2,
            enable_llm=False,
            enable_rag=False,
            enable_taint=False,
            enable_call_graph=False,
            enable_exploit_chains=False,
        )
        agent = DeepAuditAgent(config=config)
        agent.bus = MagicMock()

        mock_ml = MagicMock()
        mock_ml.analyze.return_value = MagicMock(
            raw_findings=[
                {"id": "1", "title": "reentrancy", "type": "reentrancy", "severity": "High",
                 "description": "Reentrancy in withdraw", "tool": "slither"},
                {"id": "2", "title": "selfdestruct", "type": "selfdestruct", "severity": "High",
                 "description": "Unprotected selfdestruct", "tool": "aderyn"},
                {"id": "3", "title": "pragma", "type": "solc-version", "severity": "Info",
                 "description": "Old solc", "tool": "slither"},
            ],
            ml_filtered_findings=[
                {"id": "1", "title": "reentrancy", "type": "reentrancy", "severity": "High",
                 "description": "Reentrancy in withdraw", "tool": "slither"},
                {"id": "2", "title": "selfdestruct", "type": "selfdestruct", "severity": "High",
                 "description": "Unprotected selfdestruct", "tool": "aderyn"},
                {"id": "3", "title": "pragma", "type": "solc-version", "severity": "Info",
                 "description": "Old solc", "tool": "slither"},
            ],
            tools_success=["slither", "aderyn"],
        )
        mock_orch.return_value = mock_ml

        result = agent.analyze(tmp_contract)

        assert result["summary"]["total"] >= 2
        assert result["phases"]["deep_investigation"]["iterations"] >= 1
        assert result["phases"]["deep_investigation"]["findings_enriched"] == 2


# ---------------------------------------------------------------------------
# Convenience Function
# ---------------------------------------------------------------------------

class TestRunDeepAudit:
    @patch("src.agents.deep_audit_agent.DeepAuditAgent.analyze")
    def test_run_deep_audit(self, mock_analyze, tmp_contract):
        mock_analyze.return_value = {"findings": [], "summary": {"total": 0}}
        result = run_deep_audit(tmp_contract, timeout_seconds=30, enable_llm=False)
        assert result == {"findings": [], "summary": {"total": 0}}
        mock_analyze.assert_called_once_with(tmp_contract)


# ---------------------------------------------------------------------------
# Risk Patterns
# ---------------------------------------------------------------------------

class TestRiskPatterns:
    def test_defi_patterns_exist(self):
        assert "defi" in RISK_PATTERNS
        assert len(RISK_PATTERNS["defi"]) >= 8

    def test_token_patterns_exist(self):
        assert "token" in RISK_PATTERNS
        assert len(RISK_PATTERNS["token"]) >= 6

    def test_proxy_patterns_exist(self):
        assert "proxy" in RISK_PATTERNS
        assert len(RISK_PATTERNS["proxy"]) >= 4

    def test_bridge_patterns_exist(self):
        assert "bridge" in RISK_PATTERNS
        assert len(RISK_PATTERNS["bridge"]) >= 3
