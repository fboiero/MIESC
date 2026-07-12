from pathlib import Path

import pytest

from miesc.detectors.detector_api import Category, Severity
from miesc.detectors.transient_storage_detector import (
    TransientStorageDetector,
    detect_transient_storage_risks,
)


@pytest.fixture
def detector() -> TransientStorageDetector:
    return TransientStorageDetector()


def test_detects_tstore_transfer_low_gas_reentrancy(detector: TransientStorageDetector) -> None:
    code = """
    pragma solidity ^0.8.28;
    contract Vault {
        function withdraw(address payable to) external {
            assembly { tstore(0x00, 1) }
            to.transfer(1 ether);
            assembly { tstore(0x00, 0) }
        }
    }
    """

    findings = detector.analyze(code, Path("Vault.sol"))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.HIGH
    assert finding.category is Category.REENTRANCY
    assert finding.metadata["pattern"] == "transient-low-gas-reentrancy"
    assert "transfer" in (finding.code_snippet or "")
    assert finding.confidence == "high"


def test_detects_send_low_gas_reentrancy(detector: TransientStorageDetector) -> None:
    code = """
    contract Vault {
        function payout(address payable to) external {
            assembly { tstore(0x00, 1) }
            to.send(1 ether);
        }
    }
    """

    findings = detector.analyze(code)

    assert findings
    assert findings[0].metadata["pattern"] == "transient-low-gas-reentrancy"


def test_detects_explicit_2300_gas_call(detector: TransientStorageDetector) -> None:
    code = """
    contract Vault {
        function payout(address to) external {
            assembly { tstore(0x00, 1) }
            (bool ok,) = to.call{value: 1 ether, gas: 2300}("");
            require(ok);
        }
    }
    """

    findings = detector.analyze(code)

    assert findings[0].severity is Severity.HIGH
    assert findings[0].metadata["pattern"] == "transient-low-gas-reentrancy"


def test_detects_missing_transient_lock_reset(detector: TransientStorageDetector) -> None:
    code = """
    contract Vault {
        function guarded(address to) external {
            assembly {
                if tload(0x00) { revert(0, 0) }
                tstore(0x00, 1)
            }
            (bool ok,) = to.call("");
            require(ok);
        }
    }
    """

    findings = detector.analyze(code)

    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].metadata["pattern"] == "transient-lock-not-cleared"


def test_reset_downgrades_to_external_call_review(detector: TransientStorageDetector) -> None:
    code = """
    contract Vault {
        function guarded(address to) external {
            assembly { tstore(0x00, 1) }
            (bool ok,) = to.call("");
            require(ok);
            assembly { tstore(0x00, 0) }
        }
    }
    """

    findings = detector.analyze(code)

    assert len(findings) == 1
    assert findings[0].metadata["pattern"] == "transient-external-call-review"
    assert findings[0].severity is Severity.MEDIUM


def test_detects_solidity_transient_keyword_with_delete(
    detector: TransientStorageDetector,
) -> None:
    code = """
    pragma solidity ^0.8.28;
    contract Vault {
        bool transient locked;
        function guarded(address to) external {
            require(!locked);
            locked = true;
            (bool ok,) = to.call("");
            require(ok);
            delete locked;
        }
    }
    """

    findings = detector.analyze(code)

    assert len(findings) == 1
    assert findings[0].metadata["pattern"] == "transient-external-call-review"


def test_reports_low_review_when_no_external_call(detector: TransientStorageDetector) -> None:
    code = """
    contract Vault {
        function mark() external {
            assembly { tstore(0x00, 1) }
        }
    }
    """

    findings = detector.analyze(code)

    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW
    assert findings[0].metadata["pattern"] == "transient-storage-review"


def test_ignores_comments_and_strings(detector: TransientStorageDetector) -> None:
    code = '''
    contract Safe {
        function noop() external {
            // assembly { tstore(0x00, 1) } to.transfer(1 ether);
            string memory note = "tstore(0x00, 1) and to.transfer(1 ether)";
        }
    }
    '''

    assert detector.analyze(code) == []


def test_non_string_and_empty_source_return_no_findings(detector: TransientStorageDetector) -> None:
    assert detector.analyze("") == []
    assert detector.analyze(None) == []  # type: ignore[arg-type]


def test_convenience_wrapper_returns_findings() -> None:
    code = """
    contract Vault {
        function payout(address payable to) external {
            assembly { tstore(0x00, 1) }
            to.transfer(1 ether);
        }
    }
    """

    findings = detect_transient_storage_risks(code)

    assert findings
    assert findings[0].detector == "transient-storage-detector"


def test_line_mapping_points_to_function_start(detector: TransientStorageDetector) -> None:
    code = "\n\ncontract Vault {\n    function payout(address payable to) external {\n"
    code += "        assembly { tstore(0x00, 1) }\n        to.transfer(1 ether);\n    }\n}"

    findings = detector.analyze(code)

    assert findings[0].location is not None
    assert findings[0].location.line_start == 4
