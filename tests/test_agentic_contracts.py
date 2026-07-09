"""
Tests for provider-agnostic agent contracts.
"""

from src.llm.agentic_contracts import (
    AgentCapability,
    CounterexampleEvidence,
    DPGAgentConfig,
    InvariantCategory,
    InvariantExtractionAgent,
    ReasoningResult,
    ReasoningTask,
    parse_invariant_candidates,
)


class FakeReasoningProvider:
    def __init__(self, payload):
        self.payload = payload
        self.seen_task = None

    def complete_json(self, task: ReasoningTask) -> ReasoningResult:
        self.seen_task = task
        return ReasoningResult(
            data=self.payload,
            provider_kind="local",
            implementation_label="fake-provider",
            local=True,
        )


def test_invariant_extraction_agent_uses_capability_not_provider_name():
    provider = FakeReasoningProvider(
        {
            "invariants": [
                {
                    "id": "asset_conservation",
                    "statement": "totalAssets must cover all issued shares",
                    "category": "accounting",
                    "affected_functions": ["deposit", "withdraw"],
                    "state_variables": ["totalAssets", "totalSupply"],
                    "assertion_hint": "assertGe(totalAssets(), totalSupply())",
                    "confidence": 0.82,
                    "evidence": ["totalAssets and totalSupply appear together"],
                }
            ]
        }
    )
    agent = InvariantExtractionAgent(provider)

    invariants = agent.extract(
        """
        contract Vault {
            uint256 public totalAssets;
            uint256 public totalSupply;
            function deposit(uint256 amount) external {}
            function withdraw(uint256 shares) external {}
        }
        """,
        contract_path="Vault.sol",
    )

    assert provider.seen_task is not None
    assert provider.seen_task.capability == AgentCapability.INVARIANT_EXTRACTION
    prompt_lower = provider.seen_task.prompt.lower()
    assert "interchangeable security reasoning agent" in prompt_lower
    assert "specific model" in prompt_lower
    assert "external api" in prompt_lower
    assert "deepseek" not in prompt_lower
    assert "openai" not in prompt_lower
    assert "anthropic" not in prompt_lower

    assert len(invariants) == 1
    invariant = invariants[0]
    assert invariant.id == "asset_conservation"
    assert invariant.category == InvariantCategory.ACCOUNTING
    assert invariant.affected_functions == ["deposit", "withdraw"]
    assert invariant.confidence == 0.82


def test_invariant_extraction_task_carries_dpg_policy():
    policy = DPGAgentConfig(local_first=True, allow_remote=False, max_source_chars=40)
    provider = FakeReasoningProvider({"invariants": []})
    agent = InvariantExtractionAgent(provider, policy=policy)

    task = agent.build_task("contract A {" + (" " * 100) + "}", contract_path="A.sol")

    exported = task.to_dict()
    assert exported["policy"]["local_first"] is True
    assert exported["policy"]["allow_remote"] is False
    assert exported["policy"]["require_replaceable_provider"] is True
    assert exported["inputs"]["source_chars"] == 40


def test_parse_invariant_candidates_accepts_json_string_and_bounds_confidence():
    candidates = parse_invariant_candidates(
        """
        {
          "invariants": [
            {
              "statement": "unlockTime must not increase when user adds no new lock",
              "category": "state-sync",
              "affected_functions": ["lockOnBehalf"],
              "state_variables": ["unlockTime"],
              "confidence": "1.7"
            }
          ]
        }
        """
    )

    assert len(candidates) == 1
    assert candidates[0].id.startswith("unlocktime_must_not_increase")
    assert candidates[0].category == InvariantCategory.STATE_SYNC
    assert candidates[0].confidence == 1.0


def test_parse_invariant_candidates_rejects_malformed_items():
    candidates = parse_invariant_candidates(
        {
            "invariants": [
                {"id": "missing_statement"},
                ["bad"],
                {"statement": "valid invariant", "category": "unknown", "confidence": -2},
            ]
        }
    )

    assert len(candidates) == 1
    assert candidates[0].statement == "valid invariant"
    assert candidates[0].confidence == 0.0


def test_reasoning_result_and_counterexample_evidence_export_safe_dicts():
    result = ReasoningResult(
        data={"ok": True, "bad\nkey": "ignored", "huge": float("inf")},
        provider_kind="local",
        implementation_label="local/mock",
        metadata={"nested": {"a": 1}},
    )
    evidence = CounterexampleEvidence(
        invariant_id="asset_conservation",
        status="counterexample_found",
        tool="foundry",
        compiled=True,
        counterexample_found=True,
        test_name="testAssetConservation",
        details={"raw": object()},
    )

    result_dict = result.to_dict()
    evidence_dict = evidence.to_dict()

    assert result_dict["data"]["ok"] is True
    assert "bad\nkey" not in result_dict["data"]
    assert result_dict["data"]["huge"] is None
    assert evidence_dict["counterexample_found"] is True
    assert evidence_dict["details"]["raw"] == "<object>"
