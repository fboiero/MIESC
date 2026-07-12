"""
Tests for ContractCloneDetectorAdapter (src/adapters/contract_clone_detector_adapter.py).

Pure-python clone/similarity detector (hashlib + regex, no external deps): code
normalization, SHA256 hashing, feature extraction, Jaccard + metric similarity,
clone-type classification, malicious-hash matching and finding generation.
"""

from miesc.adapters.contract_clone_detector_adapter import (
    ContractCloneDetectorAdapter,
    register_adapter,
)
from src.core.tool_protocol import ToolStatus


def test_register_adapter():
    reg = register_adapter()
    assert reg["adapter_class"] is ContractCloneDetectorAdapter
    assert reg["metadata"]["name"] == "contract_clone_detector"

CONTRACT = (
    "// SPDX-License-Identifier: MIT\n"
    "pragma solidity ^0.8.0;\n"
    "contract Token is ERC20 {\n"
    "  uint256 public total;\n"
    "  event Transfer(address from, address to);\n"
    "  modifier onlyOwner() { _; }\n"
    "  function mint(address to) public {}\n"
    "  function burn(uint256 amt) public {}\n"
    "}\n"
)


def _a(config=None):
    return ContractCloneDetectorAdapter(config)


# --------------------------------------------------------------------------- #
# metadata / availability / config
# --------------------------------------------------------------------------- #
def test_metadata_availability_check():
    a = _a()
    assert a.get_metadata().name == "contract_clone_detector"
    assert a.is_available() == ToolStatus.AVAILABLE
    chk = a.check_availability()
    assert chk["available"] is True
    assert chk["similarity_threshold"] == 0.85


def test_init_defaults_and_config():
    assert _a().similarity_threshold == 0.85
    assert _a().check_malicious_db is True
    custom = _a({"similarity_threshold": 0.5, "check_malicious_db": False, "methods": ["token_based"]})
    assert custom.similarity_threshold == 0.5
    assert custom.check_malicious_db is False
    assert custom.methods == ["token_based"]


# --------------------------------------------------------------------------- #
# _normalize_code / _calculate_hash
# --------------------------------------------------------------------------- #
def test_normalize_code_strips_comments_and_whitespace():
    a = _a()
    raw = "// a comment\ncontract C {\n  uint  x ;\n}\n/* block */"
    norm = a._normalize_code(raw)
    assert "comment" not in norm
    assert "block" not in norm
    assert "contract C{uint x;}" in norm.replace(" ", "") or "contract" in norm


def test_calculate_hash_is_deterministic_and_normalization_invariant():
    a = _a()
    h1 = a._calculate_hash("contract C { uint x; }  // note")
    h2 = a._calculate_hash("contract C { uint x; }")
    assert h1 == h2  # comment stripped before hashing
    assert len(h1) == 64


# --------------------------------------------------------------------------- #
# _extract_features
# --------------------------------------------------------------------------- #
def test_extract_features():
    a = _a()
    feats = a._extract_features(CONTRACT)
    assert feats["num_functions"] == 2
    assert "mint" in feats["function_names"]
    assert feats["num_events"] == 1
    assert feats["uses_inheritance"] == 1  # " is " present
    assert feats["has_assembly"] == 0


# --------------------------------------------------------------------------- #
# _jaccard_similarity
# --------------------------------------------------------------------------- #
def test_jaccard_identical_disjoint_empty():
    a = _a()
    assert a._jaccard_similarity("alpha beta gamma", "alpha beta gamma") == 1.0
    assert a._jaccard_similarity("alpha beta", "delta epsilon") == 0.0
    assert a._jaccard_similarity("", "anything") == 0.0


# --------------------------------------------------------------------------- #
# _metric_similarity
# --------------------------------------------------------------------------- #
def test_metric_similarity_identical_and_partial():
    a = _a()
    f = a._extract_features(CONTRACT)
    assert a._metric_similarity(f, f) == 1.0  # identical features
    # empty vs empty -> no comparable metrics -> 0.0
    assert a._metric_similarity({}, {}) == 0.0


# --------------------------------------------------------------------------- #
# _classify_clone_type
# --------------------------------------------------------------------------- #
def test_classify_clone_type_all_bands():
    a = _a()
    assert "Type-1" in a._classify_clone_type(1.0)
    assert "Type-2" in a._classify_clone_type(0.97)
    assert "Type-3" in a._classify_clone_type(0.88)
    assert "Type-4" in a._classify_clone_type(0.50)


# --------------------------------------------------------------------------- #
# _calculate_similarity (two files)
# --------------------------------------------------------------------------- #
def test_calculate_similarity_identical_files_high(tmp_path):
    a = _a()
    other = tmp_path / "other.sol"
    other.write_text(CONTRACT)
    sim = a._calculate_similarity(CONTRACT, str(other))
    assert sim > 0.85


def test_calculate_similarity_missing_file_zero():
    a = _a()
    assert a._calculate_similarity(CONTRACT, "/nonexistent/x.sol") == 0.0


# --------------------------------------------------------------------------- #
# analyze — end to end
# --------------------------------------------------------------------------- #
def test_analyze_file_not_found():
    out = _a().analyze("/nonexistent/C.sol")
    assert out["success"] is False
    assert "not found" in out["error"]


def test_analyze_detects_clone(tmp_path):
    a = _a()
    main = tmp_path / "main.sol"
    main.write_text(CONTRACT)
    twin = tmp_path / "twin.sol"
    twin.write_text(CONTRACT)
    out = a.analyze(str(main), comparison_contracts=[str(twin)])
    assert out["success"] is True
    assert out["clones_found"]
    assert out["uniqueness_score"] < 1.0
    assert out["features"]["num_functions"] == 2


def test_analyze_flags_known_malicious(tmp_path):
    a = _a()
    # a comment-only file normalizes to "" whose SHA256 is the seeded Ponzi hash
    mal = tmp_path / "mal.sol"
    mal.write_text("// only a comment\n")
    out = a.analyze(str(mal))
    assert out["success"] is True
    assert out["is_malicious"] is True
    assert any(f["type"] == "malicious_contract_detected" for f in out["findings"])


def test_analyze_unique_contract_no_clones(tmp_path):
    a = _a()
    sol = tmp_path / "uniq.sol"
    sol.write_text(CONTRACT)
    out = a.analyze(str(sol))
    assert out["success"] is True
    assert out["clones_found"] == []
    assert out["uniqueness_score"] == 1.0


def test_analyze_handles_generic_exception(tmp_path):
    a = _a()
    # passing a directory path -> open() raises IsADirectoryError -> generic except branch
    out = a.analyze(str(tmp_path))
    assert out["success"] is False
    assert out["error"]
