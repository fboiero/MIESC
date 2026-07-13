"""
Tests for provider-agnostic agent contracts.
"""

from miesc.llm.agentic_contracts import (
    MAX_AGENT_METADATA_KEYS,
    MAX_AGENT_SOURCE_CHARS,
    MAX_AGENT_TEXT_CHARS,
    AgentCapability,
    CounterexampleEvidence,
    DPGAgentConfig,
    InvariantCandidate,
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
    candidates = parse_invariant_candidates("""
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
        """)

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


def test_reasoning_task_export_sanitizes_hostile_prompt_fields():
    task = ReasoningTask(
        capability=AgentCapability.FINDING_JUDGMENT,
        objective="judge\x00finding",
        prompt="p" * (MAX_AGENT_TEXT_CHARS * 40),
        inputs={"bad\nkey": "ignored", "ok": float("inf")},
        output_schema={"schema": object()},
        policy=DPGAgentConfig(max_source_chars=-20),
    )

    exported = task.to_dict()

    assert exported["objective"] == ""
    assert len(exported["prompt"]) <= MAX_AGENT_TEXT_CHARS * 35
    assert "bad\nkey" not in exported["inputs"]
    assert exported["inputs"]["ok"] is None
    assert exported["output_schema"]["schema"] == "<object>"
    assert exported["policy"]["max_source_chars"] == 0


def test_invariant_candidate_export_sanitizes_direct_instances():
    candidate = InvariantCandidate(
        id="asset conservation\nbad",
        statement="s" * (MAX_AGENT_TEXT_CHARS + 10),
        category=InvariantCategory.ACCOUNTING,
        affected_functions=["deposit", "bad\x00fn", "withdraw"],
        state_variables=["totalAssets", object(), "totalSupply"],
        assertion_hint="hint\x00bad",
        confidence=float("inf"),
        evidence=["specific code signal", "bad\x00evidence"],
    )

    exported = candidate.to_dict()

    assert exported["id"] == "asset_conservation_bad"
    assert len(exported["statement"]) == MAX_AGENT_TEXT_CHARS
    assert exported["affected_functions"] == ["deposit", "withdraw"]
    assert exported["state_variables"] == ["totalAssets", "totalSupply"]
    assert exported["assertion_hint"] == ""
    assert exported["confidence"] == 0.0
    assert exported["evidence"] == ["specific code signal"]


def test_counterexample_evidence_export_sanitizes_scalar_fields():
    evidence = CounterexampleEvidence(
        invariant_id="asset\nconservation",
        status="counterexample found",
        tool="foundry/test",
        test_name="bad\u2028name",
        artifact_path="p" * (MAX_AGENT_TEXT_CHARS + 10),
        details={f"bad\x00{i}": i for i in range(MAX_AGENT_METADATA_KEYS + 5)}
        | {"valid_key": True},
    )

    exported = evidence.to_dict()

    assert exported["invariant_id"] == "asset_conservation"
    assert exported["status"] == "counterexample_found"
    assert exported["tool"] == "foundry_test"
    assert exported["test_name"] == ""
    assert len(exported["artifact_path"]) == MAX_AGENT_TEXT_CHARS
    assert exported["details"] == {"valid_key": True}


def test_dpg_config_export_clamps_max_source_chars():
    assert DPGAgentConfig(max_source_chars=-1).to_dict()["max_source_chars"] == 0
    assert (
        DPGAgentConfig(max_source_chars=MAX_AGENT_SOURCE_CHARS * 2).to_dict()["max_source_chars"]
        == MAX_AGENT_SOURCE_CHARS
    )


def test_parse_invariant_candidates_category_variants():
    candidates = parse_invariant_candidates(
        {
            "invariants": [
                {"statement": "cap cannot exceed max", "category": "cap-boundary"},
                {"statement": "only admin can pause", "category": "access control"},
                {"statement": "unknown category", "category": "bad\x00category"},
            ]
        }
    )

    assert [candidate.category for candidate in candidates] == [
        InvariantCategory.CAP_BOUNDARY,
        InvariantCategory.ACCESS_CONTROL,
        InvariantCategory.UNKNOWN,
    ]
