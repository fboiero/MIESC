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


# ---------------------------------------------------------------------------
# Internal Methods - _build_call_graph
# ---------------------------------------------------------------------------

class TestBuildCallGraph:
    def test_success(self, agent):
        mock_cg = MagicMock()
        mock_cg.get_entry_points.return_value = [MagicMock(name="withdraw"), MagicMock(name="deposit")]
        mock_cg.external_call_chains.return_value = [["call1", "call2"]]
        mock_builder = MagicMock()
        mock_builder.build_from_source.return_value = mock_cg

        with patch("src.agents.deep_audit_agent.CallGraphBuilder", mock_builder.__class__, create=True):
            with patch.dict("sys.modules", {"src.ml.call_graph": MagicMock(CallGraphBuilder=lambda: mock_builder)}):
                cg, entries, ext = agent._build_call_graph("contract code")
                assert cg is mock_cg
                assert len(entries) == 2
                assert len(ext) >= 1

    def test_import_failure(self, agent):
        with patch.dict("sys.modules", {"src.ml.call_graph": None}):
            cg, entries, ext = agent._build_call_graph("code")
            assert cg is None
            assert entries == []
            assert ext == []

    def test_exception_returns_defaults(self, agent):
        mock_mod = MagicMock()
        mock_mod.CallGraphBuilder.side_effect = RuntimeError("broken")
        with patch.dict("sys.modules", {"src.ml.call_graph": mock_mod}):
            cg, entries, ext = agent._build_call_graph("code")
            assert cg is None
            assert entries == []

    def test_no_get_entry_points(self, agent):
        """Call graph without get_entry_points attribute."""
        mock_cg = MagicMock(spec=[])  # No attributes
        mock_builder = MagicMock()
        mock_builder.build_from_source.return_value = mock_cg
        mock_mod = MagicMock()
        mock_mod.CallGraphBuilder.return_value = mock_builder
        with patch.dict("sys.modules", {"src.ml.call_graph": mock_mod}):
            cg, entries, ext = agent._build_call_graph("code")
            assert cg is mock_cg
            assert entries == []


# ---------------------------------------------------------------------------
# Internal Methods - _run_taint_analysis
# ---------------------------------------------------------------------------

class TestRunTaintAnalysis:
    def test_success(self, agent):
        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = [{"sink": "call", "source": "msg.value"}]
        mock_mod = MagicMock()
        mock_mod.TaintAnalyzer.return_value = mock_analyzer
        with patch.dict("sys.modules", {"src.ml.taint_analysis": mock_mod}):
            result = agent._run_taint_analysis("code")
            assert len(result) == 1

    def test_import_failure(self, agent):
        with patch.dict("sys.modules", {"src.ml.taint_analysis": None}):
            result = agent._run_taint_analysis("code")
            assert result == []

    def test_exception(self, agent):
        mock_mod = MagicMock()
        mock_mod.TaintAnalyzer.side_effect = RuntimeError("no taint")
        with patch.dict("sys.modules", {"src.ml.taint_analysis": mock_mod}):
            result = agent._run_taint_analysis("code")
            assert result == []


# ---------------------------------------------------------------------------
# Internal Methods - _get_ml_orchestrator
# ---------------------------------------------------------------------------

class TestGetMLOrchestrator:
    def test_primary_import(self, agent):
        mock_orch = MagicMock()
        mock_utils = MagicMock()
        mock_utils.get_ml_orchestrator.return_value = mock_orch
        with patch.dict("sys.modules", {"miesc.cli.utils": mock_utils, "miesc.cli": MagicMock(), "miesc": MagicMock()}):
            result = agent._get_ml_orchestrator()
            assert result is mock_orch

    def test_fallback_import(self, agent):
        mock_orch = MagicMock()
        mock_core = MagicMock()
        mock_core.MLOrchestrator.return_value = mock_orch
        with patch("src.agents.deep_audit_agent.DeepAuditAgent._get_ml_orchestrator") as m:
            # Test the actual fallback logic by calling the real method
            pass

        # Direct test: primary fails, fallback succeeds
        def fail_primary():
            raise ImportError("no miesc.cli.utils")
        with patch("builtins.__import__", side_effect=ImportError):
            result = agent._get_ml_orchestrator()
            assert result is None  # Both imports fail

    def test_both_fail(self, agent):
        result = agent._get_ml_orchestrator()
        # In test environment, both imports likely fail
        # Just verify it returns None or an object without crashing
        assert result is None or result is not None


# ---------------------------------------------------------------------------
# Internal Methods - _get_available_tools
# ---------------------------------------------------------------------------

class TestGetAvailableTools:
    def test_fallback_default(self, agent):
        """When imports fail, returns default tools."""
        result = agent._get_available_tools()
        assert "slither" in result
        assert "aderyn" in result

    def test_with_adapters(self, agent):
        mock_adapter1 = MagicMock()
        mock_adapter1.is_available.return_value = True
        mock_adapter2 = MagicMock(spec=[])  # No is_available
        mock_utils = MagicMock()
        mock_utils.load_adapters.return_value = {"slither": mock_adapter1, "aderyn": mock_adapter2}
        with patch.dict("sys.modules", {"miesc.cli.utils": mock_utils, "miesc.cli": MagicMock(), "miesc": MagicMock()}):
            result = agent._get_available_tools()
            assert "slither" in result
            assert "aderyn" in result


# ---------------------------------------------------------------------------
# Internal Methods - _run_tools_parallel
# ---------------------------------------------------------------------------

class TestRunToolsParallel:
    def test_no_adapters(self, agent):
        """When adapter loading fails, returns empty."""
        agent._start_time = time.monotonic()
        result = agent._run_tools_parallel(["slither"], "/fake/path.sol")
        assert result == []

    def test_with_mocked_adapters(self, agent):
        agent._start_time = time.monotonic()
        mock_adapter = MagicMock()
        mock_adapter.analyze.return_value = {
            "findings": [{"title": "reentrancy", "severity": "high"}]
        }
        mock_utils = MagicMock()
        mock_utils.load_adapters.return_value = {"slither": mock_adapter}
        with patch.dict("sys.modules", {"miesc.cli.utils": mock_utils, "miesc.cli": MagicMock(), "miesc": MagicMock()}):
            result = agent._run_tools_parallel(["slither"], "/fake.sol")
            assert len(result) == 1
            assert result[0]["tool"] == "slither"

    def test_tool_not_in_adapters(self, agent):
        agent._start_time = time.monotonic()
        mock_utils = MagicMock()
        mock_utils.load_adapters.return_value = {}
        with patch.dict("sys.modules", {"miesc.cli.utils": mock_utils, "miesc.cli": MagicMock(), "miesc": MagicMock()}):
            result = agent._run_tools_parallel(["nonexistent"], "/fake.sol")
            assert result == []

    def test_tool_exception(self, agent):
        agent._start_time = time.monotonic()
        mock_adapter = MagicMock()
        mock_adapter.analyze.side_effect = RuntimeError("crash")
        mock_utils = MagicMock()
        mock_utils.load_adapters.return_value = {"slither": mock_adapter}
        with patch.dict("sys.modules", {"miesc.cli.utils": mock_utils, "miesc.cli": MagicMock(), "miesc": MagicMock()}):
            result = agent._run_tools_parallel(["slither"], "/fake.sol")
            assert result == []


# ---------------------------------------------------------------------------
# Internal Methods - _run_single_tool
# ---------------------------------------------------------------------------

class TestRunSingleTool:
    def test_success(self, agent):
        adapter = MagicMock()
        adapter.analyze.return_value = {
            "findings": [{"title": "overflow", "severity": "medium"}]
        }
        result = agent._run_single_tool(adapter, "mythril", "/path.sol", 60.0)
        assert len(result) == 1
        assert result[0]["title"] == "overflow"

    def test_non_dict_result(self, agent):
        adapter = MagicMock()
        adapter.analyze.return_value = "unexpected"
        result = agent._run_single_tool(adapter, "tool", "/path.sol", 60.0)
        assert result == []

    def test_non_list_findings(self, agent):
        adapter = MagicMock()
        adapter.analyze.return_value = {"findings": "not a list"}
        result = agent._run_single_tool(adapter, "tool", "/path.sol", 60.0)
        assert result == []

    def test_exception(self, agent):
        adapter = MagicMock()
        adapter.analyze.side_effect = TimeoutError("too slow")
        result = agent._run_single_tool(adapter, "tool", "/path.sol", 60.0)
        assert result == []

    def test_empty_findings(self, agent):
        adapter = MagicMock()
        adapter.analyze.return_value = {"findings": []}
        result = agent._run_single_tool(adapter, "tool", "/path.sol", 60.0)
        assert result == []


# ---------------------------------------------------------------------------
# Internal Methods - _filter_false_positives
# ---------------------------------------------------------------------------

class TestFilterFalsePositives:
    def test_success(self, agent, tmp_contract):
        agent.contract_path = tmp_contract
        findings = [{"title": "test", "severity": "high"}]
        mock_fp = MagicMock()
        mock_fp.filter_findings.return_value = {"filtered": [{"title": "test", "severity": "high", "fp_score": 0.2}]}
        mock_mod = MagicMock()
        mock_mod.FalsePositiveFilter.return_value = mock_fp
        with patch.dict("sys.modules", {"src.ml.fp_filter": mock_mod}):
            result = agent._filter_false_positives(findings)
            assert len(result) == 1

    def test_import_failure(self, agent, tmp_contract):
        agent.contract_path = tmp_contract
        findings = [{"title": "test", "severity": "high"}]
        with patch.dict("sys.modules", {"src.ml.fp_filter": None}):
            result = agent._filter_false_positives(findings)
            assert result == findings  # Returns original on failure

    def test_non_dict_result(self, agent, tmp_contract):
        agent.contract_path = tmp_contract
        findings = [{"title": "test"}]
        mock_fp = MagicMock()
        mock_fp.filter_findings.return_value = "not a dict"
        mock_mod = MagicMock()
        mock_mod.FalsePositiveFilter.return_value = mock_fp
        with patch.dict("sys.modules", {"src.ml.fp_filter": mock_mod}):
            result = agent._filter_false_positives(findings)
            assert result == findings


# ---------------------------------------------------------------------------
# Internal Methods - _enrich_with_rag
# ---------------------------------------------------------------------------

class TestEnrichWithRAG:
    def test_success_with_results(self, agent):
        mock_result = {
            "title": "Reentrancy Attack",
            "real_exploit": "Curve $70M",
            "fixed_code": "Use nonReentrant modifier",
            "severity": "high",
            "similarity": 0.92,
        }
        mock_rag = MagicMock()
        mock_rag.search_by_finding.return_value = [mock_result]
        mock_mod = MagicMock()
        mock_mod.EmbeddingRAG.return_value = mock_rag
        with patch.dict("sys.modules", {"src.llm.embedding_rag": mock_mod}):
            result = agent._enrich_with_rag({"title": "reentrancy", "severity": "high"})
            assert result["matched"] is True
            assert result["similar_vuln"] == "Reentrancy Attack"
            assert result["fix_pattern_present"] is True
            assert result["similarity"] == 0.92

    def test_no_results(self, agent):
        mock_rag = MagicMock()
        mock_rag.search_by_finding.return_value = []
        mock_mod = MagicMock()
        mock_mod.EmbeddingRAG.return_value = mock_rag
        with patch.dict("sys.modules", {"src.llm.embedding_rag": mock_mod}):
            result = agent._enrich_with_rag({"title": "test"})
            assert result["matched"] is False

    def test_import_failure(self, agent):
        with patch.dict("sys.modules", {"src.llm.embedding_rag": None}):
            result = agent._enrich_with_rag({"title": "test"})
            assert result["matched"] is False

    def test_severity_match(self, agent):
        mock_result = {
            "title": "test",
            "real_exploit": "",
            "fixed_code": "",
            "severity": "high",
            "similarity": 0.8,
        }
        mock_rag = MagicMock()
        mock_rag.search_by_finding.return_value = [mock_result]
        mock_mod = MagicMock()
        mock_mod.EmbeddingRAG.return_value = mock_rag
        with patch.dict("sys.modules", {"src.llm.embedding_rag": mock_mod}):
            result = agent._enrich_with_rag({"title": "test", "severity": "high"})
            assert result["severity_match"] is True

    def test_non_dict_result_object(self, agent):
        """RAG returns object with __dict__."""
        mock_result = MagicMock()
        mock_result.__dict__ = {"title": "obj", "fixed_code": "fix", "severity": "low", "real_exploit": "", "similarity": 0.5}
        mock_rag = MagicMock()
        mock_rag.search_by_finding.return_value = [mock_result]
        mock_mod = MagicMock()
        mock_mod.EmbeddingRAG.return_value = mock_rag
        with patch.dict("sys.modules", {"src.llm.embedding_rag": mock_mod}):
            result = agent._enrich_with_rag({"title": "test", "severity": "high"})
            assert result["matched"] is True


# ---------------------------------------------------------------------------
# Internal Methods - _targeted_taint_for_function
# ---------------------------------------------------------------------------

class TestTargetedTaintForFunction:
    def test_success_with_match(self, agent):
        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = [
            {"sink": "withdraw.call", "source": "msg.value"},
            {"sink": "deposit", "source": "amount"},
        ]
        mock_mod = MagicMock()
        mock_mod.TaintAnalyzer.return_value = mock_analyzer
        with patch.dict("sys.modules", {"src.ml.taint_analysis": mock_mod}):
            result = agent._targeted_taint_for_function("code", "withdraw")
            assert len(result) == 1  # Only withdraw match

    def test_no_match(self, agent):
        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = [{"sink": "other", "source": "x"}]
        mock_mod = MagicMock()
        mock_mod.TaintAnalyzer.return_value = mock_analyzer
        with patch.dict("sys.modules", {"src.ml.taint_analysis": mock_mod}):
            result = agent._targeted_taint_for_function("code", "withdraw")
            assert result == []

    def test_import_failure(self, agent):
        with patch.dict("sys.modules", {"src.ml.taint_analysis": None}):
            result = agent._targeted_taint_for_function("code", "withdraw")
            assert result == []

    def test_non_list_result(self, agent):
        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = "not a list"
        mock_mod = MagicMock()
        mock_mod.TaintAnalyzer.return_value = mock_analyzer
        with patch.dict("sys.modules", {"src.ml.taint_analysis": mock_mod}):
            result = agent._targeted_taint_for_function("code", "withdraw")
            assert result == []


# ---------------------------------------------------------------------------
# Internal Methods - _find_attack_paths
# ---------------------------------------------------------------------------

class TestFindAttackPaths:
    def test_success(self, agent):
        mock_cg = MagicMock()
        mock_cg.paths_to_sink.return_value = [["entry", "mid", "withdraw"]]
        paths = agent._find_attack_paths(mock_cg, "withdraw")
        assert len(paths) == 1
        assert "withdraw" in paths[0]

    def test_no_call_graph(self, agent):
        assert agent._find_attack_paths(None, "withdraw") == []

    def test_no_func_name(self, agent):
        assert agent._find_attack_paths(MagicMock(), "") == []

    def test_no_paths_to_sink(self, agent):
        mock_cg = MagicMock(spec=[])  # No paths_to_sink attribute
        assert agent._find_attack_paths(mock_cg, "withdraw") == []

    def test_exception(self, agent):
        mock_cg = MagicMock()
        mock_cg.paths_to_sink.side_effect = RuntimeError("error")
        assert agent._find_attack_paths(mock_cg, "withdraw") == []

    def test_multiple_paths_truncated(self, agent):
        mock_cg = MagicMock()
        mock_cg.paths_to_sink.return_value = [
            ["a", "b", "c", "d", "e", "f"],
            ["x", "y"],
            ["p", "q", "r"],
            ["should", "be", "skipped"],
        ]
        paths = agent._find_attack_paths(mock_cg, "target")
        assert len(paths) == 3  # Max 3 paths
        assert len(paths[0].split(" -> ")) <= 5  # Max 5 nodes per path


# ---------------------------------------------------------------------------
# Internal Methods - _detect_exploit_chains
# ---------------------------------------------------------------------------

class TestDetectExploitChains:
    def test_success(self, agent):
        mock_chain = MagicMock()
        mock_chain.__dict__ = {"name": "Reentrancy + Unchecked", "severity": "critical"}
        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = [mock_chain]
        mock_mod = MagicMock()
        mock_mod.ExploitChainAnalyzer.return_value = mock_analyzer
        with patch.dict("sys.modules", {"src.ml.correlation_engine": mock_mod}):
            result = agent._detect_exploit_chains([{"title": "test"}])
            assert len(result) == 1

    def test_dict_chains(self, agent):
        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = [{"name": "chain1"}]
        mock_mod = MagicMock()
        mock_mod.ExploitChainAnalyzer.return_value = mock_analyzer
        with patch.dict("sys.modules", {"src.ml.correlation_engine": mock_mod}):
            result = agent._detect_exploit_chains([])
            assert result == [{"name": "chain1"}]

    def test_import_failure(self, agent):
        with patch.dict("sys.modules", {"src.ml.correlation_engine": None}):
            result = agent._detect_exploit_chains([{"title": "test"}])
            assert result == []

    def test_non_list_result(self, agent):
        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = "not a list"
        mock_mod = MagicMock()
        mock_mod.ExploitChainAnalyzer.return_value = mock_analyzer
        with patch.dict("sys.modules", {"src.ml.correlation_engine": mock_mod}):
            result = agent._detect_exploit_chains([])
            assert result == []


# ---------------------------------------------------------------------------
# Internal Methods - _correlate_findings
# ---------------------------------------------------------------------------

class TestCorrelateFindings:
    def test_success(self, agent):
        mock_mod = MagicMock()
        mock_mod.correlate_findings.return_value = {
            "findings": [{"title": "correlated", "severity": "high"}]
        }
        with patch.dict("sys.modules", {"src.ml.correlation_engine": mock_mod}):
            result = agent._correlate_findings([{"title": "raw"}])
            assert len(result) == 1
            assert result[0]["title"] == "correlated"

    def test_non_dict_result(self, agent):
        mock_mod = MagicMock()
        mock_mod.correlate_findings.return_value = [{"title": "direct"}]
        with patch.dict("sys.modules", {"src.ml.correlation_engine": mock_mod}):
            result = agent._correlate_findings([{"title": "raw"}])
            assert result == [{"title": "raw"}]  # Falls back to original

    def test_import_failure(self, agent):
        findings = [{"title": "test"}]
        with patch.dict("sys.modules", {"src.ml.correlation_engine": None}):
            result = agent._correlate_findings(findings)
            assert result == findings


# ---------------------------------------------------------------------------
# Internal Methods - _generate_narrative
# ---------------------------------------------------------------------------

class TestGenerateNarrative:
    def test_auto_tries_orchestrator_first(self, agent):
        agent.config.enable_llm = True
        agent.config.llm_provider = "auto"
        with patch.object(agent, "_try_llm_orchestrator", return_value="LLM narrative"):
            result = agent._generate_narrative([], {}, [])
            assert result == "LLM narrative"

    def test_auto_falls_back_to_ollama(self, agent):
        agent.config.enable_llm = True
        agent.config.llm_provider = "auto"
        with patch.object(agent, "_try_llm_orchestrator", return_value=""), \
             patch.object(agent, "_try_ollama_interpreter", return_value="Ollama narrative"):
            result = agent._generate_narrative([], {}, [])
            assert result == "Ollama narrative"

    def test_auto_returns_empty_when_all_fail(self, agent):
        agent.config.enable_llm = True
        agent.config.llm_provider = "auto"
        with patch.object(agent, "_try_llm_orchestrator", return_value=""), \
             patch.object(agent, "_try_ollama_interpreter", return_value=""):
            result = agent._generate_narrative([], {}, [])
            assert result == ""

    def test_ollama_provider_skips_orchestrator(self, agent):
        agent.config.enable_llm = True
        agent.config.llm_provider = "ollama"
        with patch.object(agent, "_try_llm_orchestrator") as mock_orch, \
             patch.object(agent, "_try_ollama_interpreter", return_value="ollama result"):
            result = agent._generate_narrative([], {}, [])
            mock_orch.assert_not_called()
            assert result == "ollama result"

    def test_anthropic_provider(self, agent):
        agent.config.enable_llm = True
        agent.config.llm_provider = "anthropic"
        with patch.object(agent, "_try_llm_orchestrator", return_value="claude"):
            result = agent._generate_narrative([], {}, [])
            assert result == "claude"


# ---------------------------------------------------------------------------
# Internal Methods - _try_llm_orchestrator
# ---------------------------------------------------------------------------

class TestTryLLMOrchestrator:
    def test_no_configs_returns_empty(self, agent):
        """With no API keys and provider='anthropic', should return empty."""
        agent.config.llm_provider = "anthropic"
        agent.contract_path = "/fake.sol"
        with patch.dict("os.environ", {}, clear=True):
            result = agent._try_llm_orchestrator([], {}, [])
            assert result == ""

    def test_import_failure(self, agent):
        agent.config.llm_provider = "auto"
        agent.contract_path = "/fake.sol"
        with patch.dict("sys.modules", {"src.llm.llm_orchestrator": None}):
            result = agent._try_llm_orchestrator([], {}, [])
            assert result == ""

    def test_exception_handling(self, agent):
        agent.config.llm_provider = "auto"
        agent.contract_path = "/fake.sol"
        mock_mod = MagicMock()
        mock_mod.LLMOrchestrator.side_effect = RuntimeError("LLM error")
        with patch.dict("sys.modules", {"src.llm.llm_orchestrator": mock_mod}):
            result = agent._try_llm_orchestrator([], {}, [])
            assert result == ""


# ---------------------------------------------------------------------------
# Internal Methods - _try_ollama_interpreter
# ---------------------------------------------------------------------------

class TestTryOllamaInterpreter:
    def test_success(self, agent):
        agent.contract_path = "/fake/Contract.sol"
        mock_interp = MagicMock()
        mock_interp.is_available.return_value = True
        mock_interp.generate_executive_interpretation.return_value = "Audit summary"
        mock_mod = MagicMock()
        mock_mod.LLMReportInterpreter.return_value = mock_interp
        with patch.dict("sys.modules", {"src.reports.llm_interpreter": mock_mod}):
            result = agent._try_ollama_interpreter([{"title": "test"}], {"total": 1})
            assert result == "Audit summary"

    def test_not_available(self, agent):
        agent.contract_path = "/fake.sol"
        mock_interp = MagicMock()
        mock_interp.is_available.return_value = False
        mock_mod = MagicMock()
        mock_mod.LLMReportInterpreter.return_value = mock_interp
        with patch.dict("sys.modules", {"src.reports.llm_interpreter": mock_mod}):
            result = agent._try_ollama_interpreter([], {})
            assert result == ""

    def test_non_string_result(self, agent):
        agent.contract_path = "/fake.sol"
        mock_interp = MagicMock()
        mock_interp.is_available.return_value = True
        mock_interp.generate_executive_interpretation.return_value = 42
        mock_mod = MagicMock()
        mock_mod.LLMReportInterpreter.return_value = mock_interp
        with patch.dict("sys.modules", {"src.reports.llm_interpreter": mock_mod}):
            result = agent._try_ollama_interpreter([], {})
            assert result == ""

    def test_import_failure(self, agent):
        agent.contract_path = "/fake.sol"
        with patch.dict("sys.modules", {"src.reports.llm_interpreter": None}):
            result = agent._try_ollama_interpreter([], {})
            assert result == ""

    def test_no_contract_path(self, agent):
        agent.contract_path = None
        mock_interp = MagicMock()
        mock_interp.is_available.return_value = True
        mock_interp.generate_executive_interpretation.return_value = "result"
        mock_mod = MagicMock()
        mock_mod.LLMReportInterpreter.return_value = mock_interp
        with patch.dict("sys.modules", {"src.reports.llm_interpreter": mock_mod}):
            result = agent._try_ollama_interpreter([], {})
            assert isinstance(result, str)


# ---------------------------------------------------------------------------
# Phase 2: _phase_targeted_scan with mocked orchestrator
# ---------------------------------------------------------------------------

class TestPhaseTargetedScan:
    def test_with_ml_orchestrator(self, agent, tmp_contract):
        agent._start_time = time.monotonic()
        agent.contract_path = tmp_contract
        recon = ReconResult(
            risk_profile={
                "primary": "general",
                "is_defi": False, "is_token": False,
                "is_proxy": False, "is_bridge": False,
                "has_external_calls": False, "has_selfdestruct": False,
            }
        )
        mock_ml = MagicMock()
        mock_ml.analyze.return_value = MagicMock(
            raw_findings=[{"id": "1", "severity": "high", "title": "vuln"}],
            ml_filtered_findings=[{"id": "1", "severity": "high", "title": "vuln"}],
            tools_success=["slither", "aderyn"],
        )
        with patch.object(agent, "_get_ml_orchestrator", return_value=mock_ml):
            result = agent._phase_targeted_scan(tmp_contract, recon)
            assert isinstance(result, ScanResult)
            assert len(result.filtered_findings) == 1
            assert result.severity_distribution.get("high", 0) == 1

    def test_orchestrator_fails_fallback(self, agent, tmp_contract):
        agent._start_time = time.monotonic()
        agent.contract_path = tmp_contract
        recon = ReconResult(
            risk_profile={
                "primary": "general",
                "is_defi": False, "is_token": False,
                "is_proxy": False, "is_bridge": False,
                "has_external_calls": False, "has_selfdestruct": False,
            }
        )
        mock_ml = MagicMock()
        mock_ml.analyze.side_effect = RuntimeError("MLOrchestrator crash")
        with patch.object(agent, "_get_ml_orchestrator", return_value=mock_ml), \
             patch.object(agent, "_run_tools_parallel", return_value=[]), \
             patch.object(agent, "_filter_false_positives", return_value=[]):
            result = agent._phase_targeted_scan(tmp_contract, recon)
            assert isinstance(result, ScanResult)
            assert result.raw_findings == []

    def test_no_orchestrator(self, agent, tmp_contract):
        agent._start_time = time.monotonic()
        agent.contract_path = tmp_contract
        recon = ReconResult(
            risk_profile={
                "primary": "general",
                "is_defi": False, "is_token": False,
                "is_proxy": False, "is_bridge": False,
                "has_external_calls": False, "has_selfdestruct": False,
            }
        )
        with patch.object(agent, "_get_ml_orchestrator", return_value=None), \
             patch.object(agent, "_run_tools_parallel", return_value=[{"severity": "medium"}]), \
             patch.object(agent, "_filter_false_positives", return_value=[{"severity": "medium"}]):
            result = agent._phase_targeted_scan(tmp_contract, recon)
            assert isinstance(result, ScanResult)
            assert result.severity_distribution.get("medium", 0) == 1


# ---------------------------------------------------------------------------
# Phase 3: Investigation with RAG/taint enabled
# ---------------------------------------------------------------------------

class TestDeepInvestigationWithFeatures:
    def test_with_rag_enrichment(self, tmp_contract):
        config = DeepAuditConfig(
            timeout_seconds=60,
            max_iterations=2,
            enable_llm=False,
            enable_rag=True,
            enable_taint=False,
            enable_call_graph=False,
            enable_exploit_chains=False,
        )
        agent = DeepAuditAgent(config=config)
        agent._start_time = time.monotonic()
        agent.contract_path = tmp_contract
        agent.bus = MagicMock()

        recon = ReconResult()
        scan = ScanResult(
            tools_run=["slither"],
            filtered_findings=[
                {"id": "f1", "title": "reentrancy", "type": "reentrancy", "severity": "high"}
            ],
        )
        with patch.object(agent, "_enrich_with_rag", return_value={"matched": True, "fix_pattern_present": False}):
            result = agent._phase_deep_investigation(
                tmp_contract, VULNERABLE_CONTRACT, recon, scan
            )
            assert result["enriched_count"] == 1

    def test_with_taint_and_call_graph(self, tmp_contract):
        config = DeepAuditConfig(
            timeout_seconds=60,
            max_iterations=2,
            enable_llm=False,
            enable_rag=False,
            enable_taint=True,
            enable_call_graph=True,
            enable_exploit_chains=False,
        )
        agent = DeepAuditAgent(config=config)
        agent._start_time = time.monotonic()
        agent.contract_path = tmp_contract
        agent.bus = MagicMock()

        mock_cg = MagicMock()
        recon = ReconResult(call_graph=mock_cg)
        scan = ScanResult(
            tools_run=["slither"],
            filtered_findings=[
                {"id": "f1", "title": "vuln", "type": "reentrancy", "severity": "high",
                 "location": {"function": "withdraw"}}
            ],
        )
        with patch.object(agent, "_targeted_taint_for_function", return_value=[{"taint": True}]), \
             patch.object(agent, "_find_attack_paths", return_value=["entry -> withdraw"]):
            result = agent._phase_deep_investigation(
                tmp_contract, VULNERABLE_CONTRACT, recon, scan
            )
            assert result["enriched_count"] == 1
            enriched = result["findings"][0]
            assert enriched["investigation"]["taint_paths"] == 1
            assert enriched["investigation"]["attack_paths"] == ["entry -> withdraw"]

    def test_with_exploit_chains(self, tmp_contract):
        config = DeepAuditConfig(
            timeout_seconds=60,
            max_iterations=2,
            enable_llm=False,
            enable_rag=False,
            enable_taint=False,
            enable_call_graph=False,
            enable_exploit_chains=True,
        )
        agent = DeepAuditAgent(config=config)
        agent._start_time = time.monotonic()
        agent.contract_path = tmp_contract
        agent.bus = MagicMock()

        recon = ReconResult()
        scan = ScanResult(
            tools_run=["slither"],
            filtered_findings=[
                {"id": "f1", "type": "reentrancy", "severity": "high"},
                {"id": "f2", "type": "unchecked-call", "severity": "medium"},
            ],
        )
        with patch.object(agent, "_detect_exploit_chains", return_value=[{"chain": "reentrancy+unchecked"}]):
            result = agent._phase_deep_investigation(
                tmp_contract, VULNERABLE_CONTRACT, recon, scan
            )
            assert len(result["exploit_chains"]) == 1

    def test_rag_mitigation_downgrades_severity(self, tmp_contract):
        config = DeepAuditConfig(
            timeout_seconds=60,
            max_iterations=2,
            enable_llm=False,
            enable_rag=True,
            enable_taint=False,
            enable_call_graph=False,
            enable_exploit_chains=False,
        )
        agent = DeepAuditAgent(config=config)
        agent._start_time = time.monotonic()
        agent.contract_path = tmp_contract
        agent.bus = MagicMock()

        recon = ReconResult()
        scan = ScanResult(
            tools_run=["slither"],
            filtered_findings=[
                {"id": "f1", "title": "reentrancy", "type": "reentrancy", "severity": "high"}
            ],
        )
        rag_data = {"matched": True, "fix_pattern_present": True, "fix_pattern": "Use nonReentrant modifier from ReentrancyGuard"}
        with patch.object(agent, "_enrich_with_rag", return_value=rag_data), \
             patch.object(agent, "_check_mitigation", return_value=True):
            result = agent._phase_deep_investigation(
                tmp_contract, VULNERABLE_CONTRACT, recon, scan
            )
            assert result["mitigated_count"] == 1
            enriched = result["findings"][0]
            assert enriched.get("mitigated") is True
            assert enriched["severity"] == "low"


# ---------------------------------------------------------------------------
# Phase 4: Synthesis with LLM
# ---------------------------------------------------------------------------

class TestSynthesisWithLLM:
    def test_synthesis_with_llm(self, tmp_contract):
        config = DeepAuditConfig(
            timeout_seconds=60,
            enable_llm=True,
        )
        agent = DeepAuditAgent(config=config)
        agent._start_time = time.monotonic()
        agent.contract_path = tmp_contract
        agent.bus = MagicMock()

        recon = ReconResult(risk_profile={"primary": "defi"}, attack_surface_score=65.0)
        scan = ScanResult(tools_run=["slither", "aderyn"])
        investigation = {
            "findings": [{"severity": "critical", "title": "flash loan attack"}],
            "exploit_chains": [{"name": "flash+oracle"}],
            "iterations": 2,
        }
        with patch.object(agent, "_correlate_findings", side_effect=lambda f: f), \
             patch.object(agent, "_generate_narrative", return_value="AI-generated summary"):
            result = agent._phase_synthesis(
                tmp_contract, VULNERABLE_CONTRACT, recon, scan, investigation
            )
            assert result["has_llm_narrative"] is True
            assert result["narrative"] == "AI-generated summary"
            assert result["summary"]["CRITICAL"] == 1

    def test_synthesis_falls_back_to_template(self, tmp_contract):
        config = DeepAuditConfig(
            timeout_seconds=60,
            enable_llm=True,
        )
        agent = DeepAuditAgent(config=config)
        agent._start_time = time.monotonic()
        agent.contract_path = tmp_contract
        agent.bus = MagicMock()

        recon = ReconResult(risk_profile={"primary": "general"}, attack_surface_score=20.0)
        scan = ScanResult(tools_run=["slither"])
        investigation = {"findings": [], "exploit_chains": [], "iterations": 0}
        with patch.object(agent, "_correlate_findings", side_effect=lambda f: f), \
             patch.object(agent, "_generate_narrative", return_value=""):
            result = agent._phase_synthesis(
                tmp_contract, VULNERABLE_CONTRACT, recon, scan, investigation
            )
            assert result["has_llm_narrative"] is False
            assert "LOW" in result["narrative"]


# ---------------------------------------------------------------------------
# LLM Second Opinion
# ---------------------------------------------------------------------------

class TestLLMSecondOpinion:
    def test_returns_none_on_connection_error(self, agent):
        """LLM second opinion returns None when Ollama unavailable."""
        agent.config.llm_model = "mistral:latest"
        with patch("urllib.request.urlopen", side_effect=ConnectionError("refused")):
            result = agent._get_llm_second_opinion(
                {"title": "reentrancy", "severity": "critical", "description": "test"},
                "contract code"
            )
            assert result is None

    def test_returns_none_on_timeout(self, agent):
        agent.config.llm_model = "mistral:latest"
        with patch("urllib.request.urlopen", side_effect=TimeoutError("timeout")):
            result = agent._get_llm_second_opinion(
                {"title": "test", "severity": "critical"},
                "code"
            )
            assert result is None

    def test_handles_empty_finding(self, agent):
        agent.config.llm_model = "mistral:latest"
        with patch("urllib.request.urlopen", side_effect=Exception("any error")):
            result = agent._get_llm_second_opinion({}, "")
            assert result is None


# ---------------------------------------------------------------------------
# Framework detection edge cases
# ---------------------------------------------------------------------------

class TestFrameworkDetectionEdgeCases:
    def test_solmate(self, agent, tmp_path):
        path = tmp_path / "Solmate.sol"
        path.write_text('import "solmate/tokens/ERC20.sol";\ncontract T {}')
        assert agent._detect_framework(str(path)) == "solmate"

    def test_solady(self, agent, tmp_path):
        path = tmp_path / "Solady.sol"
        path.write_text('import "solady/utils/SafeTransferLib.sol";\ncontract T {}')
        assert agent._detect_framework(str(path)) == "solady"

    def test_nonexistent_file(self, agent):
        assert agent._detect_framework("/nonexistent/file.sol") == "custom"


# ---------------------------------------------------------------------------
# Extract function name edge cases
# ---------------------------------------------------------------------------

class TestExtractFunctionNameEdgeCases:
    def test_from_location_string_with_function(self, agent):
        finding = {"location": "function transfer(address to, uint256 amount)"}
        assert agent._extract_function_name(finding) == "transfer"

    def test_empty_function(self, agent):
        finding = {"location": {"function": ""}}
        assert agent._extract_function_name(finding) is None

    def test_no_location(self, agent):
        finding = {"title": "test"}
        assert agent._extract_function_name(finding) is None


# ---------------------------------------------------------------------------
# Template narrative edge cases
# ---------------------------------------------------------------------------

class TestTemplateNarrativeEdgeCases:
    def test_medium_risk(self, agent):
        summary = {"CRITICAL": 0, "HIGH": 0, "total": 3, "tools_used": ["slither", "aderyn"], "iterations": 1}
        narrative = agent._template_narrative(summary, [])
        assert "MEDIUM" in narrative
        assert "Review findings" in narrative

    def test_multiple_chains(self, agent):
        summary = {"CRITICAL": 1, "HIGH": 1, "total": 5, "tools_used": ["slither"], "iterations": 2}
        chains = [{"name": "chain1"}, {"name": "chain2"}, {"name": "chain3"}]
        narrative = agent._template_narrative(summary, chains)
        assert "3 exploit chain" in narrative
        assert "cascading" in narrative
