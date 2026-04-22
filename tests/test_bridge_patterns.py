"""
Tests for src/adapters/bridge_patterns.py.

Covers all 7 bridge exploit patterns with positive-detection samples and
negative (mitigated) samples to ensure absence_patterns work correctly.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
"""

from __future__ import annotations

import pytest

from src.adapters.bridge_patterns import (
    BRIDGE_EXPLOIT_PATTERNS,
    BridgePattern,
    detect_bridge_vulnerabilities,
)


# =============================================================================
# 1. Missing replay protection — Wormhole $326M
# =============================================================================

REPLAY_VULNERABLE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract WormholeBridge {
    function processMessage(bytes calldata message, bytes32 messageHash) external {
        // No nonce or processed-message tracking
        _executeTransfer(message);
    }
}
"""

REPLAY_PROTECTED = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SafeBridge {
    mapping(bytes32 => bool) public processedMessages;

    function processMessage(bytes calldata message, bytes32 messageHash) external {
        require(!processedMessages[messageHash], "already processed");
        processedMessages[messageHash] = true;
        _executeTransfer(message);
    }
}
"""


class TestMissingReplayProtection:
    def test_detects_missing_replay_protection(self):
        findings = detect_bridge_vulnerabilities(REPLAY_VULNERABLE)
        types = [f["type"] for f in findings]
        assert "missing_replay_protection" in types

    def test_no_finding_when_processed_messages_mapping_present(self):
        findings = detect_bridge_vulnerabilities(REPLAY_PROTECTED)
        types = [f["type"] for f in findings]
        assert "missing_replay_protection" not in types

    def test_finding_has_required_fields(self):
        findings = detect_bridge_vulnerabilities(REPLAY_VULNERABLE)
        rp = next(f for f in findings if f["type"] == "missing_replay_protection")
        assert rp["severity"] == "Critical"
        assert "Wormhole" in rp["exploit_ref"]
        assert rp["line"] > 0
        assert rp["tool"] == "bridge-patterns"


# =============================================================================
# 2. Insufficient signature validation — Ronin $624M
# =============================================================================

RONIN_VULNERABLE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract RoninBridge {
    uint256 public required = 2;

    function executeWithdrawal(bytes[] calldata signatures) external {
        require(signatures.length >= required, "not enough sigs");
        _mint(msg.sender, 1000 ether);
    }
}
"""

RONIN_SAFE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SafeRonin {
    uint256 public required = 7;

    function executeWithdrawal(bytes[] calldata signatures) external {
        require(signatures.length >= 7, "not enough sigs");
        _mint(msg.sender, 1000 ether);
    }
}
"""


class TestInsufficientSignatureValidation:
    def test_detects_low_threshold(self):
        findings = detect_bridge_vulnerabilities(RONIN_VULNERABLE)
        types = [f["type"] for f in findings]
        assert "insufficient_signature_validation" in types

    def test_no_finding_when_threshold_not_low(self):
        findings = detect_bridge_vulnerabilities(RONIN_SAFE)
        types = [f["type"] for f in findings]
        assert "insufficient_signature_validation" not in types

    def test_finding_references_ronin(self):
        findings = detect_bridge_vulnerabilities(RONIN_VULNERABLE)
        f = next(f for f in findings if f["type"] == "insufficient_signature_validation")
        assert "Ronin" in f["exploit_ref"]
        assert f["severity"] == "Critical"


# =============================================================================
# 3. Hash collision in proof verification — BNB Bridge $586M
# =============================================================================

BNB_VULNERABLE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract BNBBridge {
    function verifyProof(bytes32[] calldata proof, bytes32 root) public pure returns (bool) {
        bytes32 computed = keccak256(abi.encodePacked(proof[0], proof[1]));
        return computed == root;
    }
}
"""

BNB_SAFE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract SafeProof {
    function verify(bytes32[] calldata proof, bytes32 root, bytes32 leaf) public pure returns (bool) {
        return MerkleProof.verify(proof, root, leaf);
    }
}
"""


class TestHashCollisionProofVerification:
    def test_detects_raw_keccak_proof(self):
        findings = detect_bridge_vulnerabilities(BNB_VULNERABLE)
        types = [f["type"] for f in findings]
        assert "hash_collision_proof_verification" in types

    def test_no_finding_when_oz_merkleproof_imported(self):
        findings = detect_bridge_vulnerabilities(BNB_SAFE)
        types = [f["type"] for f in findings]
        assert "hash_collision_proof_verification" not in types

    def test_finding_references_bnb_bridge(self):
        findings = detect_bridge_vulnerabilities(BNB_VULNERABLE)
        f = next(f for f in findings if f["type"] == "hash_collision_proof_verification")
        assert "BNB" in f["exploit_ref"]
        assert f["severity"] == "Critical"


# =============================================================================
# 4. Missing origin validation — Nomad $190M
# =============================================================================

NOMAD_VULNERABLE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract NomadBridge {
    function process(bytes32 root, bytes calldata message) external {
        // No origin check, no non-zero root check
        _dispatch(message);
    }
}
"""

NOMAD_SAFE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SafeNomad {
    mapping(bytes32 => bool) public committedRoot;

    function process(bytes32 root, bytes calldata message) external {
        require(root != bytes32(0), "zero root");
        require(committedRoot[root], "unknown root");
        _dispatch(message);
    }
}
"""


class TestMissingOriginValidation:
    def test_detects_missing_origin_check(self):
        findings = detect_bridge_vulnerabilities(NOMAD_VULNERABLE)
        types = [f["type"] for f in findings]
        assert "missing_origin_validation" in types

    def test_no_finding_when_committed_root_checked(self):
        findings = detect_bridge_vulnerabilities(NOMAD_SAFE)
        types = [f["type"] for f in findings]
        assert "missing_origin_validation" not in types

    def test_finding_references_nomad(self):
        findings = detect_bridge_vulnerabilities(NOMAD_VULNERABLE)
        f = next(f for f in findings if f["type"] == "missing_origin_validation")
        assert "Nomad" in f["exploit_ref"]
        assert f["severity"] == "Critical"


# =============================================================================
# 5. Unprotected relay function — generic
# =============================================================================

RELAY_VULNERABLE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UnprotectedRelay {
    function relay(bytes calldata data) external {
        // No access control at all
        _process(data);
    }
}
"""

RELAY_PROTECTED = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ProtectedRelay {
    address public owner;

    modifier onlyRelayer() {
        require(msg.sender == owner, "not relayer");
        _;
    }

    function relay(bytes calldata data) external onlyRelayer {
        _process(data);
    }
}
"""


class TestUnprotectedRelayFunction:
    def test_detects_unprotected_relay(self):
        findings = detect_bridge_vulnerabilities(RELAY_VULNERABLE)
        types = [f["type"] for f in findings]
        assert "unprotected_relay_function" in types

    def test_no_finding_when_access_control_present(self):
        findings = detect_bridge_vulnerabilities(RELAY_PROTECTED)
        types = [f["type"] for f in findings]
        assert "unprotected_relay_function" not in types

    def test_finding_severity_is_high(self):
        findings = detect_bridge_vulnerabilities(RELAY_VULNERABLE)
        f = next(f for f in findings if f["type"] == "unprotected_relay_function")
        assert f["severity"] == "High"
        assert f["swc_id"] == "SWC-105"


# =============================================================================
# 6. Missing amount bounds — generic
# =============================================================================

BOUNDS_VULNERABLE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract NoBounds {
    function deposit(uint256 amount) external {
        // No max amount check
        token.transferFrom(msg.sender, address(this), amount);
    }
}
"""

BOUNDS_SAFE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract WithBounds {
    uint256 public maxTransfer = 1_000_000e18;

    function deposit(uint256 amount) external {
        require(amount <= maxTransfer, "exceeds limit");
        token.transferFrom(msg.sender, address(this), amount);
    }
}
"""


class TestMissingAmountBounds:
    def test_detects_missing_bounds(self):
        findings = detect_bridge_vulnerabilities(BOUNDS_VULNERABLE)
        types = [f["type"] for f in findings]
        assert "missing_amount_bounds" in types

    def test_no_finding_when_max_transfer_enforced(self):
        findings = detect_bridge_vulnerabilities(BOUNDS_SAFE)
        types = [f["type"] for f in findings]
        assert "missing_amount_bounds" not in types

    def test_finding_has_fix_recommendation(self):
        findings = detect_bridge_vulnerabilities(BOUNDS_VULNERABLE)
        f = next(f for f in findings if f["type"] == "missing_amount_bounds")
        assert len(f["fix"]) > 10
        assert f["recommendation"] == f["fix"]


# =============================================================================
# 7. Token mapping inconsistency — generic
# =============================================================================

MAPPING_VULNERABLE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IMintable {
    function mint(address to, uint256 amount) external;
}

contract NoMapping {
    function mintWrapped(address token, address to, uint256 amount) external {
        // No check that token is registered
        IMintable(token).mint(to, amount);
    }
}
"""

MAPPING_SAFE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IMintable {
    function mint(address to, uint256 amount) external;
}

contract WithMapping {
    mapping(address => address) public tokenMapping;

    function mintWrapped(address sourceToken, address to, uint256 amount) external {
        address destToken = tokenMapping[sourceToken];
        require(destToken != address(0), "token not registered");
        IMintable(destToken).mint(to, amount);
    }
}
"""


class TestTokenMappingInconsistency:
    def test_detects_unregistered_mint(self):
        findings = detect_bridge_vulnerabilities(MAPPING_VULNERABLE)
        types = [f["type"] for f in findings]
        assert "token_mapping_inconsistency" in types

    def test_no_finding_when_mapping_present(self):
        findings = detect_bridge_vulnerabilities(MAPPING_SAFE)
        types = [f["type"] for f in findings]
        assert "token_mapping_inconsistency" not in types

    def test_finding_severity_is_high(self):
        findings = detect_bridge_vulnerabilities(MAPPING_VULNERABLE)
        f = next(f for f in findings if f["type"] == "token_mapping_inconsistency")
        assert f["severity"] == "High"


# =============================================================================
# General / cross-cutting tests
# =============================================================================


class TestBridgePatternsGeneral:
    def test_empty_source_returns_no_findings(self):
        assert detect_bridge_vulnerabilities("") == []

    def test_non_bridge_contract_returns_no_findings(self):
        simple_erc20 = """
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.0;

        contract Token {
            mapping(address => uint256) public balances;
            function transfer(address to, uint256 amount) external {
                balances[msg.sender] -= amount;
                balances[to] += amount;
            }
        }
        """
        findings = detect_bridge_vulnerabilities(simple_erc20)
        assert findings == []

    def test_all_patterns_have_required_metadata(self):
        for name, bp in BRIDGE_EXPLOIT_PATTERNS.items():
            assert isinstance(bp, BridgePattern), f"{name} is not a BridgePattern"
            assert bp.severity in {"Critical", "High", "Medium", "Low"}, f"{name}: invalid severity"
            assert len(bp.description) > 10, f"{name}: description too short"
            assert len(bp.exploit_ref) > 5, f"{name}: exploit_ref missing"
            assert len(bp.fix) > 10, f"{name}: fix too short"
            assert len(bp.patterns) >= 1, f"{name}: no patterns defined"

    def test_finding_schema_completeness(self):
        """Every finding returned by detect_bridge_vulnerabilities has the required keys."""
        required_keys = {"type", "severity", "description", "exploit_ref", "fix", "line", "tool", "confidence"}
        # Use the most obviously vulnerable code
        findings = detect_bridge_vulnerabilities(REPLAY_VULNERABLE + RONIN_VULNERABLE)
        for f in findings:
            missing = required_keys - set(f.keys())
            assert not missing, f"Finding {f.get('type')} missing keys: {missing}"

    def test_seven_patterns_defined(self):
        """Exactly 7 bridge exploit patterns are registered."""
        assert len(BRIDGE_EXPLOIT_PATTERNS) == 7
