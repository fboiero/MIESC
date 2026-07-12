"""Tests for replaceable agentic reasoning provider adapters."""

import pytest

from miesc.llm import (
    LLMOrchestratorReasoningProvider as ExportedLLMOrchestratorReasoningProvider,
)
from miesc.llm import (
    LocalHeuristicReasoningProvider as ExportedLocalHeuristicReasoningProvider,
)
from miesc.llm import (
    ReasoningProviderRoute as ExportedReasoningProviderRoute,
)
from miesc.llm import (
    auto_reasoning_provider as exported_auto_reasoning_provider,
)
from miesc.llm.agentic_contracts import (
    AgentCapability,
    DPGAgentConfig,
    InvariantExtractionAgent,
    ReasoningTask,
)
from miesc.llm.llm_orchestrator import LLMResponse
from miesc.llm.reasoning_provider_adapter import (
    LLMOrchestratorReasoningProvider,
    LocalHeuristicReasoningProvider,
    ReasoningProviderRoute,
    auto_reasoning_provider,
)


class FakeOrchestrator:
    primary_provider = "local:test-agent"

    def __init__(self, content):
        self.content = content
        self.seen_prompt = None
        self.seen_context = None
        self.seen_provider = None

    async def query(self, prompt, context=None, provider=None):
        self.seen_prompt = prompt
        self.seen_context = context
        self.seen_provider = provider
        return LLMResponse(
            content=self.content,
            provider="local",
            model="test-agent",
            tokens_used=12,
            latency_ms=3.5,
        )


def test_llm_orchestrator_provider_returns_reasoning_result_from_json():
    orchestrator = FakeOrchestrator(
        """
        ```json
        {"invariants": [{"statement": "totalAssets covers totalSupply"}]}
        ```
        """
    )
    provider = LLMOrchestratorReasoningProvider(
        orchestrator,
        route=ReasoningProviderRoute(
            backend_key="local:test-agent",
            provider_kind="local",
            implementation_label="test-agent",
            local=True,
        ),
    )
    task = ReasoningTask(
        capability=AgentCapability.INVARIANT_EXTRACTION,
        objective="extract invariants",
        prompt="Return JSON only",
        policy=DPGAgentConfig(allow_remote=False),
    )

    result = provider.complete_json(task)

    assert result.data == {"invariants": [{"statement": "totalAssets covers totalSupply"}]}
    assert result.provider_kind == "local"
    assert result.implementation_label == "test-agent"
    assert result.local is True
    assert result.metadata["backend_key"] == "local:test-agent"
    assert orchestrator.seen_provider == "local:test-agent"
    assert orchestrator.seen_context["capability"] == "invariant_extraction"


def test_llm_orchestrator_provider_blocks_remote_when_policy_disallows_it():
    provider = LLMOrchestratorReasoningProvider(
        FakeOrchestrator("{}"),
        route=ReasoningProviderRoute(
            backend_key="remote:test-agent",
            provider_kind="remote",
            implementation_label="test-agent",
            local=False,
        ),
    )
    task = ReasoningTask(
        capability=AgentCapability.INVARIANT_EXTRACTION,
        objective="extract invariants",
        prompt="Return JSON only",
        policy=DPGAgentConfig(allow_remote=False),
    )

    with pytest.raises(ValueError, match="Remote reasoning is disabled"):
        provider.complete_json(task)


def test_llm_orchestrator_provider_requires_replaceable_policy():
    provider = LLMOrchestratorReasoningProvider(
        FakeOrchestrator("{}"),
        route=ReasoningProviderRoute(
            backend_key="local:test-agent",
            provider_kind="local",
            implementation_label="test-agent",
            local=True,
        ),
    )
    task = ReasoningTask(
        capability=AgentCapability.INVARIANT_EXTRACTION,
        objective="extract invariants",
        prompt="Return JSON only",
        policy=DPGAgentConfig(require_replaceable_provider=False),
    )

    with pytest.raises(ValueError, match="replaceable provider contract"):
        provider.complete_json(task)


def test_llm_orchestrator_provider_parses_embedded_json_object():
    provider = LLMOrchestratorReasoningProvider(
        FakeOrchestrator('analysis follows {"invariants": [{"id": "accounting"}]} done'),
        route=ReasoningProviderRoute(
            backend_key="local:test-agent",
            provider_kind="local",
            implementation_label="test-agent",
            local=True,
        ),
    )
    task = ReasoningTask(
        capability=AgentCapability.INVARIANT_EXTRACTION,
        objective="extract invariants",
        prompt="Return JSON only",
    )

    result = provider.complete_json(task)

    assert result.data == {"invariants": [{"id": "accounting"}]}


def test_llm_orchestrator_provider_uses_later_parseable_fenced_json():
    provider = LLMOrchestratorReasoningProvider(
        FakeOrchestrator(
            """
            ```solidity
            contract NotJson {}
            ```
            ```json
            {"invariants": [{"id": "later_json"}]}
            ```
            """
        ),
        route=ReasoningProviderRoute(
            backend_key="local:test-agent",
            provider_kind="local",
            implementation_label="test-agent",
            local=True,
        ),
    )
    task = ReasoningTask(
        capability=AgentCapability.INVARIANT_EXTRACTION,
        objective="extract invariants",
        prompt="Return JSON only",
    )

    result = provider.complete_json(task)

    assert result.data == {"invariants": [{"id": "later_json"}]}


def test_llm_orchestrator_provider_skips_non_json_bracket_prefix():
    provider = LLMOrchestratorReasoningProvider(
        FakeOrchestrator('note [not-json] then {"invariants": [{"id": "object"}]}'),
        route=ReasoningProviderRoute(
            backend_key="local:test-agent",
            provider_kind="local",
            implementation_label="test-agent",
            local=True,
        ),
    )
    task = ReasoningTask(
        capability=AgentCapability.INVARIANT_EXTRACTION,
        objective="extract invariants",
        prompt="Return JSON only",
    )

    result = provider.complete_json(task)

    assert result.data == {"invariants": [{"id": "object"}]}


def test_llm_orchestrator_provider_wraps_json_array_response():
    provider = LLMOrchestratorReasoningProvider(
        FakeOrchestrator('[{"statement": "supply is capped"}]'),
        route=ReasoningProviderRoute(
            backend_key="local:test-agent",
            provider_kind="local",
            implementation_label="test-agent",
            local=True,
        ),
    )
    task = ReasoningTask(
        capability=AgentCapability.INVARIANT_EXTRACTION,
        objective="extract invariants",
        prompt="Return JSON only",
    )

    result = provider.complete_json(task)

    assert result.data == {"items": [{"statement": "supply is capped"}]}


def test_llm_orchestrator_provider_rejects_malformed_json_response():
    provider = LLMOrchestratorReasoningProvider(
        FakeOrchestrator("this is not json"),
        route=ReasoningProviderRoute(
            backend_key="local:test-agent",
            provider_kind="local",
            implementation_label="test-agent",
            local=True,
        ),
    )
    task = ReasoningTask(
        capability=AgentCapability.INVARIANT_EXTRACTION,
        objective="extract invariants",
        prompt="Return JSON only",
    )

    result = provider.complete_json(task)

    assert result.data == {}


@pytest.mark.asyncio
async def test_sync_llm_orchestrator_provider_rejects_active_event_loop():
    provider = LLMOrchestratorReasoningProvider(
        FakeOrchestrator("{}"),
        route=ReasoningProviderRoute(
            backend_key="local:test-agent",
            provider_kind="local",
            implementation_label="test-agent",
            local=True,
        ),
    )
    task = ReasoningTask(
        capability=AgentCapability.INVARIANT_EXTRACTION,
        objective="extract invariants",
        prompt="Return JSON only",
    )

    with pytest.raises(RuntimeError, match="active event loop"):
        provider.complete_json(task)
    assert provider.orchestrator.seen_prompt is None


def test_local_heuristic_provider_extracts_replaceable_invariants():
    provider = LocalHeuristicReasoningProvider()
    agent = InvariantExtractionAgent(provider)

    invariants = agent.extract(
        """
        contract Vault {
            uint256 public totalSupply;
            uint256 public totalAssets;
            uint256 public cap;
            address public owner;
            modifier onlyOwner() { require(msg.sender == owner); _; }
            function deposit(uint256 amount) external {}
            function mint(uint256 amount) external onlyOwner {}
        }
        """
    )

    categories = {candidate.category.value for candidate in invariants}
    assert "accounting" in categories
    assert "cap_boundary" in categories
    assert "access_control" in categories
    assert all(candidate.confidence > 0 for candidate in invariants)


def test_local_heuristic_provider_reports_unsupported_capability():
    provider = LocalHeuristicReasoningProvider()
    task = ReasoningTask(
        capability=AgentCapability.REMEDIATION_CRITIQUE,
        objective="critique remediation",
        prompt="Return JSON only",
    )

    result = provider.complete_json(task)

    assert result.data == {}
    assert result.local is True
    assert result.metadata == {"unsupported_capability": "remediation_critique"}


def test_auto_reasoning_provider_prefers_local_fallback_without_orchestrator():
    provider = auto_reasoning_provider()

    assert isinstance(provider, LocalHeuristicReasoningProvider)


def test_auto_reasoning_provider_wraps_provided_local_orchestrator():
    orchestrator = FakeOrchestrator("{}")

    provider = auto_reasoning_provider(orchestrator)

    assert isinstance(provider, LLMOrchestratorReasoningProvider)
    assert provider.orchestrator is orchestrator
    assert provider.route == ReasoningProviderRoute(
        backend_key="local:test-agent",
        provider_kind="local",
        implementation_label="test-agent",
        local=True,
    )


def test_auto_reasoning_provider_derives_remote_route():
    orchestrator = FakeOrchestrator("{}")
    orchestrator.primary_provider = "openai:gpt-test"

    provider = auto_reasoning_provider(orchestrator)

    assert isinstance(provider, LLMOrchestratorReasoningProvider)
    assert provider.route == ReasoningProviderRoute(
        backend_key="openai:gpt-test",
        provider_kind="openai",
        implementation_label="gpt-test",
        local=False,
    )


def test_auto_reasoning_provider_derives_plain_local_route():
    orchestrator = FakeOrchestrator("{}")
    orchestrator.primary_provider = "ollama"

    provider = auto_reasoning_provider(orchestrator)

    assert isinstance(provider, LLMOrchestratorReasoningProvider)
    assert provider.route == ReasoningProviderRoute(
        backend_key="ollama",
        provider_kind="ollama",
        implementation_label="ollama",
        local=True,
    )


def test_llm_orchestrator_provider_blocks_mismatched_remote_route():
    provider = LLMOrchestratorReasoningProvider(
        FakeOrchestrator("{}"),
        route=ReasoningProviderRoute(
            backend_key="openai:gpt-test",
            provider_kind="openai",
            implementation_label="gpt-test",
            local=True,
        ),
    )
    task = ReasoningTask(
        capability=AgentCapability.INVARIANT_EXTRACTION,
        objective="extract invariants",
        prompt="Return JSON only",
        policy=DPGAgentConfig(allow_remote=False),
    )

    with pytest.raises(ValueError, match="Remote reasoning is disabled"):
        provider.complete_json(task)


def test_reasoning_provider_adapter_exports_are_available_from_src_llm():
    assert ExportedLLMOrchestratorReasoningProvider is LLMOrchestratorReasoningProvider
    assert ExportedLocalHeuristicReasoningProvider is LocalHeuristicReasoningProvider
    assert ExportedReasoningProviderRoute is ReasoningProviderRoute
    assert exported_auto_reasoning_provider is auto_reasoning_provider
