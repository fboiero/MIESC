# SDD: Cross-Chain Message Hardening

Date: 2026-07-11
Owner lane: Codex
Status: proposed, first provider-neutral plan contract implemented

## 1. Signal

MIESC already covers signature-domain hardening, sequence oracles, semantic
graph gates, snapshot fuzzing, economic simulation, metamorphic testing, and
upgrade evolution. A remaining Solidity risk class is bridge and L2 message
validation: the vulnerable surface is not a local call or a signature alone,
but a cross-domain message envelope that must prove source, destination, remote
sender, message identity, replay status, payload scope, and finality.

This SDD adds a provider-neutral artifact for cross-chain message hardening:
inventory bridge/L2 handlers and emit validation checks for source domain,
trusted sender, message id uniqueness, consumed-message tracking, proof/root or
finality assumptions, sender aliasing, ordering, and value consistency.

Relevant external signals:

- OWASP SCWE-034 covers insecure cross-chain messaging and unauthorized
  cross-chain actions.
- OWASP SC05:2026 calls out cross-chain inputs as an input-validation surface.
- BridgeFuzz is recent work focused on fuzzing cross-chain bridge
  vulnerabilities.
- Bridge security guidance repeatedly identifies message verification, replay,
  finality, validator assumptions, and destination execution policy as primary
  bridge risk areas.

## 2. Spec

Add `cross_chain_message_hardening` as a provider-neutral plan type.

Inputs:

- Solidity source.
- Existing findings.
- Optional bridge/L2 summary.
- Local-first policy constraints.

Output:

```json
{
  "cross_chain_message_hardening_plans": [
    {
      "id": "l2_message_plan",
      "objective": "Harden L2 receiveMessage against spoofed remotes",
      "message_flows": [
        {
          "id": "l2_receive_message",
          "handler_function": "receiveMessage",
          "source_domain": "Ethereum",
          "destination_domain": "Optimism",
          "trusted_sender_source": "trustedRemote[sourceChainId]",
          "message_id_source": "keccak256(sourceChainId, nonce, payload)",
          "replay_guard": "processedMessages[messageId]",
          "finality_assumption": "proof root finalized before execute",
          "payload_scope": ["token", "amount", "recipient"],
          "evidence": ["receiveMessage decodes sourceChainId and payload"]
        }
      ],
      "risks": [
        {
          "id": "missing_source_sender_check",
          "category": "trusted_sender",
          "affected_flow_id": "l2_receive_message",
          "severity_hint": "high",
          "description": "handler does not verify the trusted remote sender",
          "evidence": ["source sender is decoded but not checked"],
          "recommended_check": "spoof source sender must revert"
        }
      ],
      "validation_tests": ["replay consumed message id must revert"],
      "recommended_tools": ["foundry", "bridgefuzz", "slither"],
      "confidence": 0.85,
      "evidence": ["bridge receive handler is present"]
    }
  ]
}
```

Parser aliases:

- `cross_chain_message_hardening_plans`
- `bridge_message_hardening_plans`
- `cross_chain_validation_plans`

Non-goals:

- Replacing signature-domain hardening for EIP-712, permit, or ERC-1271 flows.
- Replacing sequence-oracle plans for transaction ordering.
- Confirming exploitability without replay, spoofing, or finality evidence.
- Adding local heuristic routing in this checkpoint.
- Editing frozen paper artifacts or canonical benchmark outputs.

## 3. Design

Implemented first checkpoint:

1. Add `AgentCapability.CROSS_CHAIN_MESSAGE_HARDENING`.
2. Add `CrossChainMessageFlow`.
3. Add `CrossChainMessageRisk`.
4. Add `CrossChainMessageHardeningPlan`.
5. Add `CrossChainMessageHardeningAgent`.
6. Add `parse_cross_chain_message_hardening_plans()`.
7. Export the contract through `src.llm` and `miesc.llm`.

The plan is hardening and validation guidance. It should feed Foundry,
BridgeFuzz-style campaigns, Slither/static checks, or future local bridge/L2
adapters, but it does not by itself become a vulnerability finding.

False-positive controls:

- Plans require an objective.
- Plans require at least one message flow, risk, or validation test.
- Message flows require id and handler function.
- Risks require id, category, and description.
- Confidence, evidence, tools, text, and metadata are bounded.
- Prompt text prohibits provider/model/API binding.

## 4. Validation

Focused validation:

```bash
pytest tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py -q
ruff check src/llm/agentic_contracts.py src/llm/__init__.py miesc/llm/__init__.py tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py
```

Required assertions:

- capability is provider-neutral;
- prompts avoid vendor/model binding;
- parser aliases are accepted;
- incomplete cross-chain message plans are rejected;
- hostile fields are sanitized;
- public `miesc.llm` facade exports remain stable.

## 5. Integration Plan

The next 50 activities should remain additive and non-canonical until Fernando
approves a benchmark or paper baseline update.

Discovery and schema:

1. Inventory functions named receive, execute, finalize, relay, consume, lzReceive.
2. Inventory inbox/outbox/portal/messenger endpoint contracts.
3. Inventory source chain/domain fields.
4. Inventory destination chain/domain fields.
5. Inventory trusted remote sender checks.
6. Inventory message id/hash derivation.
7. Inventory consumed message tracking.
8. Inventory proof/root/finality checks.
9. Inventory sender aliasing logic.
10. Define bridge message flow taxonomy.

Contract and local heuristics:

11. Add cross-chain message plan contracts.
12. Add parser and sanitization tests.
13. Add public exports.
14. Add local heuristic for missing trusted sender checks.
15. Add local heuristic for missing source domain checks.
16. Add local heuristic for missing destination domain checks.
17. Add local heuristic for replay guard absence.
18. Add local heuristic for weak message id derivation.
19. Add local heuristic for missing finality/delay checks.
20. Keep no-signal output empty.

Validation tests:

21. Generate Foundry test for replay consumed message id.
22. Generate spoofed source sender test.
23. Generate spoofed source domain test.
24. Generate wrong destination domain test.
25. Generate payload recipient mismatch test.
26. Generate token/amount mismatch test.
27. Generate sender aliasing test.
28. Generate message ordering test.
29. Generate finality delay bypass test.
30. Generate value consistency test.

Adapter bridge:

31. Route `CROSS_CHAIN_MESSAGE_HARDENING` in local heuristic provider.
32. Emit canonical `cross_chain_message_hardening_plans` key.
33. Emit metadata strategy and count.
34. Consume bridge summaries when available.
35. Reuse bridge pattern fixtures as semantic examples.
36. Reuse L2 validator fixtures as semantic examples.
37. Preserve deterministic plan ordering.
38. Add MCP/schema exposure.
39. Add CLI JSON output behind opt-in profile.
40. Add report section for cross-chain message validation.

Evaluation:

41. Add fixture for safe L2 messenger receive.
42. Add fixture for missing trusted sender.
43. Add fixture for missing replay guard.
44. Add fixture for weak message id.
45. Add fixture for missing finality delay.
46. Add fixture for payload scope mismatch.
47. Add fixture for sender aliasing mismatch.
48. Run non-canonical fixture suite.
49. Compare bridge-message TPR/FPR only on ground-truth fixtures.
50. Update paper/benchmark claims only after explicit approval.

## 6. References

- OWASP SCWE-034 Insecure Cross-Chain Messaging:
  https://scs.owasp.org/SCWE/SCSVS-BRIDGE/SCWE-034/
- OWASP SC05:2026 Lack of Input Validation:
  https://scs.owasp.org/sctop10/SC05-LackOfInputValidation/
- BridgeFuzz: Fuzzing Cross-Chain Vulnerabilities:
  https://dl.acm.org/doi/10.1145/3803525.3804980
- Chainlink cross-chain bridge vulnerabilities:
  https://chain.link/education-hub/cross-chain-bridge-vulnerabilities
- LayerZero V2 message security:
  https://docs.layerzero.network/v2/concepts/protocol/message-security
