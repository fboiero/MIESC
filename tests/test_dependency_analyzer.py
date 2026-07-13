"""
Tests for DependencyAnalyzer (src/detectors/dependency_analyzer.py).

Pure-python (re + dataclasses, no external deps): supply-chain / dependency
analysis — vulnerable OpenZeppelin imports, unnecessary SafeMath on 0.8+, dangerous
builtins (tx.origin / selfdestruct / delegatecall / ecrecover), package identity,
and summary stats. Written from scratch (module previously had no tests).
"""

from pathlib import Path

from miesc.detectors.dependency_analyzer import (
    DependencyAnalyzer,
    DependencyFinding,
    DependencyRisk,
)

VULN = (
    "pragma solidity ^0.8.20;\n"
    'import "@openzeppelin/contracts/access/Ownable.sol";\n'
    'import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";\n'
    'import "@openzeppelin/contracts/utils/math/SafeMath.sol";\n'
    "contract C {\n"
    "  address owner;\n"
    "  function f(address a, bytes32 h, uint8 v, bytes32 r, bytes32 s) public {\n"
    "    require(tx.origin == owner);\n"
    "    ecrecover(h, v, r, s);\n"
    "    a.delegatecall('');\n"
    "    selfdestruct(payable(owner));\n"
    "  }\n"
    "}\n"
)


def _a():
    return DependencyAnalyzer()


# --------------------------------------------------------------------------- #
# dataclass / enum
# --------------------------------------------------------------------------- #
def test_finding_dataclass_and_enum():
    f = DependencyFinding(title="t", description="d", severity=DependencyRisk.HIGH, package="p")
    assert f.severity.value == "high"
    assert f.references == []
    assert DependencyRisk.CRITICAL.value == "critical"


# --------------------------------------------------------------------------- #
# small pure helpers
# --------------------------------------------------------------------------- #
def test_extract_solidity_version():
    a = _a()
    assert a._extract_solidity_version("pragma solidity ^0.8.20;") == "0.8.20"
    assert a._extract_solidity_version("contract C {}") is None


def test_identify_package():
    a = _a()
    assert a._identify_package("@openzeppelin/contracts/access/Ownable.sol") == "openzeppelin"
    assert a._identify_package("@uniswap/v3/X.sol") == "uniswap"
    assert a._identify_package("@chainlink/Y.sol") == "chainlink"
    assert a._identify_package("@aave/Z.sol") == "aave"
    assert a._identify_package("@compound/W.sol") == "compound"
    assert a._identify_package("./local/Thing.sol") == "unknown"


def test_extract_contract_name():
    a = _a()
    assert a._extract_contract_name("@openzeppelin/contracts/access/Ownable.sol") == "Ownable"
    assert a._extract_contract_name("") == ""


def test_extract_imports():
    a = _a()
    src = 'import "@openzeppelin/contracts/access/Ownable.sol";\ncontract C {}'
    imports = a._extract_imports(src, src.split("\n"))
    assert len(imports) == 1
    assert imports[0]["package"] == "openzeppelin"
    assert imports[0]["contract"] == "Ownable"
    assert imports[0]["line"] == 1


# --------------------------------------------------------------------------- #
# _check_import branches
# --------------------------------------------------------------------------- #
def test_check_import_openzeppelin_vuln():
    a = _a()
    info = {
        "line": 1,
        "path": "@openzeppelin/contracts/access/Ownable.sol",
        "package": "openzeppelin",
        "contract": "Ownable",
    }
    out = a._check_import(info, "0.8.20")
    assert out and "Ownable" in out[0].title


def test_check_import_unnecessary_safemath_on_08():
    a = _a()
    info = {
        "line": 2,
        "path": "@openzeppelin/contracts/utils/math/SafeMath.sol",
        "package": "openzeppelin",
        "contract": "SafeMath",
    }
    out = a._check_import(info, "0.8.20")
    assert any("Unnecessary SafeMath" in f.title for f in out)


def test_check_import_safemath_pre_08_not_flagged():
    a = _a()
    info = {
        "line": 2,
        "path": "@openzeppelin/contracts/math/SafeMath.sol",
        "package": "openzeppelin",
        "contract": "SafeMath",
    }
    out = a._check_import(info, "0.6.0")  # SafeMath legitimate pre-0.8
    assert not any("SafeMath" in f.title for f in out)


def test_check_import_dangerous_non_safemath():
    a = _a()
    info = {
        "line": 3,
        "path": "@openzeppelin/contracts/utils/Counters.sol",
        "package": "openzeppelin",
        "contract": "Counters",
    }
    out = a._check_import(info, "0.8.20")
    assert any("Counters" in f.title for f in out)


# --------------------------------------------------------------------------- #
# _check_dangerous_patterns
# --------------------------------------------------------------------------- #
def test_check_dangerous_patterns():
    a = _a()
    src = (
        "require(tx.origin == owner);\n"
        "selfdestruct(payable(o));\n"
        "x.delegatecall('');\n"
        "ecrecover(h, v, r, s);"
    )
    out = a._check_dangerous_patterns(src, src.split("\n"))
    titles = " ".join(f.title for f in out)
    assert "tx.origin" in titles
    assert "selfdestruct" in titles
    assert "delegatecall" in titles
    assert "ecrecover" in titles


# --------------------------------------------------------------------------- #
# analyze (end to end) + analyze_file + get_summary
# --------------------------------------------------------------------------- #
def test_analyze_end_to_end():
    a = _a()
    findings = a.analyze(VULN)
    assert findings
    titles = " ".join(f.title for f in findings)
    assert "Ownable" in titles
    assert "Unnecessary SafeMath" in titles
    assert "tx.origin" in titles


def test_analyze_file(tmp_path):
    a = _a()
    sol = tmp_path / "C.sol"
    sol.write_text(VULN)
    findings = a.analyze_file(Path(sol))
    assert findings


def test_analyze_clean_contract():
    a = _a()
    assert a.analyze("pragma solidity ^0.8.20;\ncontract Clean { uint x; }") == []


def test_get_summary():
    a = _a()
    findings = a.analyze(VULN)
    summary = a.get_summary(findings)
    assert summary["total"] == len(findings)
    assert summary["by_severity"]
    assert summary["by_package"]
    # OZ findings carry CVEs
    assert isinstance(summary["cves"], list)
