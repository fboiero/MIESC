# SDD: Token Hook Reentrancy Hardening

Date: 2026-07-11
Lane: Codex
Status: implemented as provider-neutral contract

## Goal

Add a provider-neutral reasoning contract for token hook reentrancy review in
Solidity systems. The contract focuses on ERC-777, ERC-1363, ERC-1820, and
transfer/approval callback paths where token-controlled execution can reenter
protocol accounting before effects are finalized.

## Scope

The agent builds hardening plans, not confirmed vulnerabilities. It identifies:

- Entry points that perform external token calls.
- Hook or callback functions such as `tokensReceived`, `tokensToSend`,
  `onTransferReceived`, and `onApprovalReceived`.
- State update ordering around balances, shares, deposits, debt, claims, and
  authorization.
- Expected callback sender checks and reentrancy guards.
- Validation tests with malicious token hooks or sender-spoofed callbacks.

Out of scope:

- Generic reentrancy without a token hook or callback mechanism.
- ERC4626 inflation math unless a token hook reenters share accounting.
- Transfer-fee/non-standard ERC20 behavior unless callback control flow is the
  relevant risk.
- EIP-1153 lock design except as a mitigation for a token hook surface.

## Contract

Capability:

```text
TOKEN_HOOK_REENTRANCY_HARDENING
```

Canonical output key:

```text
token_hook_reentrancy_hardening_plans
```

Primary dataclasses:

- `TokenHookSurface`
- `TokenHookReentrancyRisk`
- `TokenHookReentrancyHardeningPlan`

Accepted parser aliases:

- `token_hook_reentrancy_hardening_plans`
- `token_hook_reentrancy_plans`
- `erc777_hook_hardening_plans`
- `erc1363_callback_hardening_plans`
- `callback_reentrancy_hardening_plans`
- `token_callback_hardening_plans`

## Validation

Focused tests cover:

- Agent task construction and provider-neutral prompt constraints.
- Canonical capability routing.
- Parser aliases, bounded fields, and incomplete item rejection.
- Public `src.llm` and `miesc.llm` exports.

Run:

```bash
python3 -m pytest tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py -q
```

## Next Loop

Add local heuristic provider support once the provider-neutral contract is stable:

- Dispatch on `AgentCapability.TOKEN_HOOK_REENTRANCY_HARDENING`.
- Return `token_hook_reentrancy_hardening_plans`.
- Detect ERC-777/ERC-1363/ERC-1820 and token callback terms.
- Infer token calls before effects, callback sender validation, guards, and
  accounting fields.
- Add focused `tests/test_reasoning_provider_adapter.py` coverage.

## References

- OWASP SCWE-104: Unprotected ERC777 Token Hooks
  https://scs.owasp.org/SCWE/SCSVS-COMM/SCWE-104/
- EIP-777: Token Standard
  https://eips.ethereum.org/EIPS/eip-777
- EIP-1363: Payable Token
  https://eips.ethereum.org/EIPS/eip-1363
- Ackee: Reentrancy Attack in ERC-777
  https://ackee.xyz/blog/reentrancy-attack-in-erc-777/
- MixBytes: One more problem with ERC777
  https://mixbytes.io/blog/one-more-problem-with-erc777
