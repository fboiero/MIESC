"""Tests for AutonomousAuditorAgent - dataclasses, enums, and init."""

from unittest.mock import MagicMock, patch

import pytest

from src.agents.auditor_agent import (
    AuditContext,
    AuditFinding,
    AuditReport,
    AuditStep,
    COT_PROMPTS,
    ContractType,
    FunctionInfo,
    ValueFlow,
)


class TestEnums:
    def test_audit_steps(self):
        assert AuditStep.UNDERSTAND_CONTRACT.value == "understand_contract"
        assert AuditStep.DETECT_VULNERABILITIES.value == "detect_vulnerabilities"
        assert AuditStep.VALIDATE_FINDINGS.value == "validate_findings"
        assert AuditStep.GENERATE_RECOMMENDATIONS.value == "generate_recommendations"
        assert len(AuditStep) == 8

    def test_contract_types(self):
        assert ContractType.UNKNOWN.value == "unknown"
        assert ContractType.ERC20.value == "erc20"
        assert ContractType.DEX.value == "dex"
        assert ContractType.LENDING.value == "lending"
        assert ContractType.BRIDGE.value == "bridge"
        assert ContractType.VAULT.value == "vault"
        assert len(ContractType) == 12


class TestFunctionInfo:
    def test_creation(self):
        fi = FunctionInfo(
            name="withdraw",
            visibility="external",
            modifiers=["nonReentrant"],
            parameters=[{"name": "amount", "type": "uint256"}],
            returns=["bool"],
            state_mutability="nonpayable",
            is_entry_point=True,
            handles_value=True,
            changes_state=True,
            code="function withdraw(uint256 amount) external { }",
            line_number=42,
        )
        assert fi.name == "withdraw"
        assert fi.is_entry_point is True
        assert fi.handles_value is True
        assert fi.modifiers == ["nonReentrant"]

    def test_view_function(self):
        fi = FunctionInfo(
            name="balanceOf",
            visibility="public",
            modifiers=[],
            parameters=[{"name": "account", "type": "address"}],
            returns=["uint256"],
            state_mutability="view",
            is_entry_point=True,
            handles_value=False,
            changes_state=False,
            code="function balanceOf(address account) public view returns (uint256) {}",
            line_number=10,
        )
        assert fi.changes_state is False
        assert fi.state_mutability == "view"


class TestValueFlow:
    def test_creation(self):
        vf = ValueFlow(
            source="deposit",
            destination="contract",
            asset_type="ETH",
            conditions=["msg.value > 0"],
            risk_level="medium",
        )
        assert vf.asset_type == "ETH"
        assert vf.risk_level == "medium"
        assert len(vf.conditions) == 1


class TestAuditFinding:
    def test_defaults(self):
        af = AuditFinding(
            id="F001",
            step=AuditStep.DETECT_VULNERABILITIES,
            type="reentrancy",
            severity="high",
            title="Reentrancy in withdraw",
            description="State updated after external call",
            location={"function": "withdraw", "line": 42},
        )
        assert af.confidence == 0.7
        assert af.validated is False
        assert af.attack_vector is None
        assert af.remediation is None

    def test_full(self):
        af = AuditFinding(
            id="F002",
            step=AuditStep.CHECK_ACCESS_CONTROL,
            type="access-control",
            severity="critical",
            title="Missing onlyOwner",
            description="Admin function callable by anyone",
            location={"function": "setOwner", "line": 15},
            attack_vector="Call setOwner directly",
            impact="Full contract takeover",
            remediation="Add onlyOwner modifier",
            confidence=0.95,
            validated=True,
            validation_notes="Confirmed by symbolic execution",
        )
        assert af.validated is True
        assert af.confidence == 0.95


class TestAuditContext:
    def test_defaults(self):
        ctx = AuditContext(
            contract_path="/tmp/test.sol",
            contract_code="contract Test {}",
        )
        assert ctx.contract_type == ContractType.UNKNOWN
        assert ctx.functions == []
        assert ctx.entry_points == []
        assert ctx.findings == []
        assert ctx.completed_steps == []

    def test_with_data(self):
        func = FunctionInfo(
            name="test", visibility="public", modifiers=[], parameters=[],
            returns=[], state_mutability="nonpayable", is_entry_point=True,
            handles_value=False, changes_state=True, code="", line_number=1,
        )
        ctx = AuditContext(
            contract_path="/tmp/test.sol",
            contract_code="contract Test {}",
            contract_name="Test",
            contract_type=ContractType.ERC20,
            solidity_version="0.8.20",
            functions=[func],
            entry_points=[func],
        )
        assert ctx.contract_name == "Test"
        assert ctx.contract_type == ContractType.ERC20
        assert len(ctx.functions) == 1


class TestAuditReport:
    def test_creation(self):
        report = AuditReport(
            contract_path="/tmp/test.sol",
            contract_name="Test",
            contract_type="erc20",
            audit_date="2026-04-01",
            total_functions=5,
            entry_points=3,
            findings_by_severity={"critical": 1, "high": 2, "medium": 1},
            findings=[],
            recommendations=[],
            risk_score=7.5,
            execution_time_ms=1234.5,
            steps_completed=["understand_contract", "detect_vulnerabilities"],
        )
        assert report.risk_score == 7.5
        assert report.findings_by_severity["critical"] == 1
        assert len(report.steps_completed) == 2


class TestCOTPrompts:
    def test_all_steps_have_prompts(self):
        expected_steps = [
            AuditStep.UNDERSTAND_CONTRACT,
            AuditStep.IDENTIFY_ENTRY_POINTS,
            AuditStep.TRACE_VALUE_FLOWS,
            AuditStep.CHECK_ACCESS_CONTROL,
            AuditStep.ANALYZE_STATE_CHANGES,
            AuditStep.DETECT_VULNERABILITIES,
            AuditStep.VALIDATE_FINDINGS,
            AuditStep.GENERATE_RECOMMENDATIONS,
        ]
        for step in expected_steps:
            assert step in COT_PROMPTS
            assert len(COT_PROMPTS[step]) > 50

    def test_prompts_contain_json_format(self):
        for step, prompt in COT_PROMPTS.items():
            assert "JSON" in prompt or "json" in prompt


class TestAutonomousAuditorAgentInit:
    @patch("src.mcp_core.context_bus.get_context_bus")
    def test_init_defaults(self, mock_bus):
        mock_bus.return_value = MagicMock()
        from src.agents.auditor_agent import AutonomousAuditorAgent
        agent = AutonomousAuditorAgent()
        assert agent.agent_name == "AutonomousAuditor"
        assert agent.model == "deepseek-coder:6.7b"
        assert agent.timeout == 120
        assert len(agent._step_handlers) == 8

    @patch("src.mcp_core.context_bus.get_context_bus")
    def test_init_custom(self, mock_bus):
        mock_bus.return_value = MagicMock()
        from src.agents.auditor_agent import AutonomousAuditorAgent
        agent = AutonomousAuditorAgent(
            model="mistral:latest",
            timeout=60,
            verbose=False,
        )
        assert agent.model == "mistral:latest"
        assert agent.timeout == 60
        assert agent.verbose is False

    @patch("src.mcp_core.context_bus.get_context_bus")
    def test_audit_steps_list(self, mock_bus):
        mock_bus.return_value = MagicMock()
        from src.agents.auditor_agent import AutonomousAuditorAgent
        assert len(AutonomousAuditorAgent.AUDIT_STEPS) == 8
        assert AutonomousAuditorAgent.AUDIT_STEPS[0] == AuditStep.UNDERSTAND_CONTRACT
        assert AutonomousAuditorAgent.AUDIT_STEPS[-1] == AuditStep.GENERATE_RECOMMENDATIONS

    @patch("src.mcp_core.context_bus.get_context_bus")
    def test_get_context_types(self, mock_bus):
        mock_bus.return_value = MagicMock()
        from src.agents.auditor_agent import AutonomousAuditorAgent
        agent = AutonomousAuditorAgent()
        types = agent.get_context_types()
        assert isinstance(types, list)
        assert len(types) > 0
