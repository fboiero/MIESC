# Code-quality report — `AssetRouter._changeNativeToken` deletes a mapping-only struct (no-op)

**Project:** Lombard Finance — `evm-smart-contracts`
**Commit:** `7fe83e5`
**File:** `contracts/LBTC/AssetRouter.sol`
**Function:** `_changeNativeToken(address)` (L906–914)
**Class:** Incorrect state cleanup (`delete` on a struct containing only mappings)
**Severity:** Low / Informational (correctness & operational-safety; **not** attacker-exploitable in current code)
**Disclosure:** Shared directly with the team as a courtesy. This is **not** a bug-bounty submission — there is no demonstrated in-scope impact and therefore no PoC (per the Immunefi V2.3 criteria). Please treat it as a hardening suggestion.

---

## Summary

`_changeNativeToken` tries to clear the previous native token's routes with `delete $.routes[key]`. Because `Routes` is a struct whose only field is a mapping, `delete` on it is a **no-op** in Solidity (mapping contents cannot be cleared by `delete`). The old routes therefore persist in storage, silently, after a native-token change.

## Affected code

```solidity
// L84–90 — the route storage model
struct Routes { mapping(bytes32 => Route) direction; }   // only a mapping
struct Route  { mapping(bytes32 => RouteType) toTokens; } // only a mapping

// L906–914
function _changeNativeToken(address newValue) internal {
    AssetRouterStorage storage $ = _getAssetRouterStorage();
    address prevValue = $.nativeToken;
    $.nativeToken = newValue;
    bytes32 key = keccak256(abi.encode(prevValue, LChainId.get()));
    delete $.routes[key];                 // <-- NO-OP: Routes holds only mappings
    _revokeRole(CALLER_ROLE, prevValue);
    emit AssetRouter_NativeTokenChanged(prevValue, newValue);
}
```

## Root cause

`delete x` on a struct recursively zeroes its value-type and fixed fields but **skips mapping fields** (the EVM cannot enumerate a mapping's keys). `Routes` contains only `mapping(bytes32 => Route) direction`, and each `Route` contains only `mapping(bytes32 => RouteType) toTokens`. So `delete $.routes[key]` clears nothing: every `direction[*].toTokens[*]` entry for the previous native token remains set. The intended cleanup (remove the old token's routes) does not happen.

Contrast with `removeRoute` (L158–170), which correctly deletes a leaf value: `delete r.toTokens[toToken]` (a `RouteType` enum, not a mapping) — that one works.

## Exploitability trace (why this is not attacker-exploitable today)

Routes are read in exactly two operational paths, and neither reaches the stale entries for the *old* native token `A` after a change to `B`:

1. **Deposit** — `_deposit` (L442) keys the route lookup on the **current** native token, not a caller-supplied one:
   ```solidity
   _getRouteType(addressToBytes32($.nativeToken), LChainId.get(), tolChainId, toToken) != RouteType.DEPOSIT → revert
   ```
   After the change `$.nativeToken == B`, so `A`'s stale routes are never consulted on deposit.

2. **Redeem** — `_redeem` (L604) uses a `fromToken` parameter (which *could* be `A`) but gates it:
   ```solidity
   if (!_isAllowedCaller(fromToken)) revert NotStakingToken();   // fromToken must hold CALLER_ROLE
   _getRouteType(fromTokenBytes, ...) != RouteType.REDEEM → revert
   ```
   `_changeNativeToken` calls `_revokeRole(CALLER_ROLE, A)`, so `_isAllowedCaller(A)` now reverts. The stale redeem route for `A` is unreachable.

Route management (`setRoute`/`removeRoute`) is `onlyRole(DEFAULT_ADMIN_ROLE)`.

**Conclusion:** there is no attacker-controlled path to the stale routes in the current code; both readers are either re-anchored to the new native token or gated by the revoked `CALLER_ROLE`.

## Impact (residual, operational)

The real risk is an **operational / admin footgun**, not an external exploit:

- The team may believe `_changeNativeToken` removed the old token's routes (the function name and the `delete` imply so), but they persist.
- If the old token `A` is ever **re-introduced** — re-granted `CALLER_ROLE`, or re-registered via `setRoute` with `A` as the native/route source (same `key = keccak(A, chainId)`) — the **old, supposedly-deleted routes resurface** and become active again, contradicting operator intent. Depending on what those stale routes allowed, that could re-enable a redeem/deposit direction that was meant to be retired.

This requires privileged action plus the operator being unaware the routes were never cleared, so it is not an unauthenticated vulnerability — but it is a latent correctness/safety defect worth fixing.

## Proposed fix

`delete` cannot clear a mapping-only struct, so clear the entries explicitly (as `removeRoute` already does for a single leaf), or make route keys unforgeable across re-use:

- **Explicit cleanup:** on native-token change, iterate the known `(toChainId, toToken)` directions for `key` and `delete $.routes[key].direction[toChainId].toTokens[toToken]` for each. (Requires tracking the set of configured directions per token — e.g. an auxiliary enumerable set — since mappings aren't enumerable.)
- **Or version the routes:** add a per-token `uint256 epoch` (or include a nonce in `key = keccak(token, chainId, epoch)`) and bump it on `_changeNativeToken`, so a later re-introduction of the same token reads a fresh, empty route namespace and cannot inherit stale entries.
- At minimum, **remove the misleading `delete $.routes[key]`** (it does nothing) and document that routes must be cleared with `removeRoute` before/after a native-token change, so operators are not misled.

## Notes

- Reported at commit `7fe83e5`; line numbers are from that revision.
- Found via an automated static scan (Slither `mapping-deletion`), then manually verified and traced. We are **not** opening a bounty submission; this is a good-faith hardening report for the team to triage as it sees fit.
