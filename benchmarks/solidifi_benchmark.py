#!/usr/bin/env python3
"""
MIESC v4.6.0 - SolidiFI Benchmark Evaluation
Evaluates v4.6.0 detection modules against the SolidiFI dataset (350 contracts)

Dataset: https://github.com/smartbugs/SolidiFI-benchmark
Categories: Reentrancy, Overflow-Underflow, TOD, Timestamp, Unchecked-Send,
           Unhandled-Exceptions, tx.origin

Author: Fernando Boiero
Institution: UNDEF - IUA
"""

import csv
import json
import sys
import time
import importlib.util
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import re

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent
DATASET_PATH = PROJECT_ROOT / "benchmarks" / "datasets" / "solidifi-benchmark" / "buggy_contracts"
RESULTS_PATH = PROJECT_ROOT / "benchmarks" / "results"


def _import_module_directly(module_path: str, module_name: str):
    """Import module directly bypassing __init__.py to avoid circular imports."""
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


# Import modules directly to avoid circular import issues
ML_PATH = PROJECT_ROOT / "src" / "ml"

classic_patterns = _import_module_directly(
    str(ML_PATH / "classic_patterns.py"), "classic_patterns_direct"
)
false_positive_filter = _import_module_directly(
    str(ML_PATH / "false_positive_filter.py"), "fp_filter_direct"
)
call_graph = _import_module_directly(
    str(ML_PATH / "call_graph.py"), "call_graph_direct"
)
taint_analysis = _import_module_directly(
    str(ML_PATH / "taint_analysis.py"), "taint_analysis_direct"
)

# Get classes from modules
ClassicPatternDetector = classic_patterns.ClassicPatternDetector
AccessControlSemanticDetector = classic_patterns.AccessControlSemanticDetector
DoSCrossFunctionDetector = classic_patterns.DoSCrossFunctionDetector
SemanticContextAnalyzer = false_positive_filter.SemanticContextAnalyzer
SLITHER_DETECTOR_FP_RATES = false_positive_filter.SLITHER_DETECTOR_FP_RATES
CallGraphBuilder = call_graph.CallGraphBuilder
TaintAnalyzer = taint_analysis.TaintAnalyzer

# Import Slither validator if available
try:
    slither_validator = _import_module_directly(
        str(ML_PATH / "slither_validator.py"), "slither_validator_direct"
    )
    SlitherValidator = slither_validator.SlitherValidator
    # Check if Slither binary is actually available
    _slither_test = SlitherValidator()
    SLITHER_AVAILABLE = _slither_test.is_available
except Exception:
    SlitherValidator = None
    SLITHER_AVAILABLE = False

# Import FP classifier for v4.7.0
try:
    fp_classifier_module = _import_module_directly(
        str(ML_PATH / "fp_classifier.py"), "fp_classifier_direct"
    )
    FPClassifier = fp_classifier_module.FPClassifier
    FP_CLASSIFIER_AVAILABLE = True
except Exception:
    FPClassifier = None
    FP_CLASSIFIER_AVAILABLE = False

# Import Mythril adapter for cross-validation
# Need to add project root to path for mythril_adapter's internal imports
import sys
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

ADAPTERS_PATH = PROJECT_ROOT / "src" / "adapters"
try:
    mythril_module = _import_module_directly(
        str(ADAPTERS_PATH / "mythril_adapter.py"), "mythril_adapter_direct"
    )
    MythrilAdapter = mythril_module.MythrilAdapter
    # Check if Mythril is actually available
    _mythril_test = MythrilAdapter()
    from src.core.tool_protocol import ToolStatus
    MYTHRIL_AVAILABLE = _mythril_test.is_available() == ToolStatus.AVAILABLE
except Exception as e:
    print(f"Warning: Mythril import failed: {e}")
    MythrilAdapter = None
    MYTHRIL_AVAILABLE = False


# Category mapping
SOLIDIFI_TO_SWC = {
    "Re-entrancy": "SWC-107",
    "Overflow-Underflow": "SWC-101",
    "TOD": "SWC-114",
    "Timestamp-Dependency": "SWC-116",
    "Unchecked-Send": "SWC-104",
    "Unhandled-Exceptions": "SWC-104",
    "tx.origin": "SWC-115",
}

CATEGORY_TO_VULN_TYPES = {
    "Re-entrancy": {
        "reentrancy", "reentrancy_eth", "reentrancy_no_eth", "reentrancy_path",
        "vyper_reentrancy"
    },
    "Overflow-Underflow": {
        "integer_overflow", "integer_underflow", "arithmetic", "overflow", "underflow"
    },
    "TOD": {
        "front_running", "tod", "transaction_order_dependence", "race_condition",
        "permit_frontrun"
    },
    "Timestamp-Dependency": {
        "timestamp_dependence", "block_timestamp", "weak_randomness", "timestamp",
        "bad_randomness"
    },
    "Unchecked-Send": {
        "unchecked_send", "unchecked_low_level_calls", "unchecked_call", "unchecked_return",
        "reentrancy"  # .transfer() patterns detected as reentrancy also count
    },
    "Unhandled-Exceptions": {
        "unchecked_low_level_calls", "unhandled_exception", "unchecked_call",
        "unchecked_return", "unchecked_send"
    },
    "tx.origin": {
        "tx_origin", "tx.origin", "access_control", "authorization",
        "unprotected_function", "missing_access_control"
    },
}


@dataclass
class GroundTruth:
    """Ground truth vulnerability from BugLog CSV."""
    line: int
    length: int
    bug_type: str
    approach: str


@dataclass
class Detection:
    """Detection from MIESC modules."""
    line: int
    vuln_type: str
    severity: str
    confidence: float
    detector: str


@dataclass
class ContractResult:
    """Results for a single contract."""
    name: str
    category: str
    ground_truth: List[GroundTruth]
    detections: List[Detection]
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    analysis_time_ms: float = 0.0
    error: Optional[str] = None


@dataclass
class CategoryMetrics:
    """Metrics for a vulnerability category."""
    total_contracts: int = 0
    total_ground_truth: int = 0
    total_detections: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0


@dataclass
class BenchmarkResults:
    """Complete benchmark results."""
    version: str = "4.6.0"
    timestamp: str = ""
    total_contracts: int = 0
    total_ground_truth: int = 0
    total_detections: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    total_time_seconds: float = 0.0
    by_category: Dict[str, CategoryMetrics] = field(default_factory=dict)
    contract_results: List[ContractResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


def parse_buglog(csv_path: Path) -> List[GroundTruth]:
    """Parse BugLog CSV to extract ground truth."""
    ground_truth = []
    try:
        with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    gt = GroundTruth(
                        line=int(row.get('loc', 0)),
                        length=int(row.get('length', 0)),
                        bug_type=row.get('bug type', '').strip(),
                        approach=row.get('approach', '').strip()
                    )
                    if gt.line > 0:
                        ground_truth.append(gt)
                except (ValueError, KeyError):
                    continue
    except Exception as e:
        print(f"  Warning: Could not parse {csv_path}: {e}")
    return ground_truth


def analyze_contract(source_code: str, category: str) -> Tuple[List[Detection], float]:
    """Analyze contract using v4.6.0 modules."""
    detections = []
    start_time = time.time()

    try:
        # 1. Classic Pattern Detector
        classic_detector = ClassicPatternDetector()
        classic_matches = classic_detector.detect(source_code)

        for match in classic_matches:
            detections.append(Detection(
                line=match.line,
                vuln_type=match.vuln_type.value if hasattr(match.vuln_type, 'value') else str(match.vuln_type),
                severity=match.severity,
                confidence=match.confidence,
                detector="classic_pattern"
            ))

        # 2. Access Control Semantic Detector
        ac_detector = AccessControlSemanticDetector()
        ac_findings = ac_detector.analyze(source_code)

        for finding in ac_findings:
            detections.append(Detection(
                line=finding.line,
                vuln_type=finding.vuln_type,
                severity=finding.severity,
                confidence=finding.confidence,
                detector="access_control_semantic"
            ))

        # 3. DoS Cross-Function Detector
        dos_detector = DoSCrossFunctionDetector()
        dos_findings = dos_detector.analyze(source_code)

        for finding in dos_findings:
            detections.append(Detection(
                line=finding.line,
                vuln_type=finding.vuln_type,
                severity=finding.severity,
                confidence=finding.confidence,
                detector="dos_cross_function"
            ))

        # 4. Call Graph Analysis (for reentrancy paths)
        try:
            cg_builder = CallGraphBuilder()
            call_graph_obj = cg_builder.build_from_source(source_code)
            reentrancy_paths = call_graph_obj.get_reentrancy_risk_paths()

            for path in reentrancy_paths[:5]:  # Limit to top 5
                if path.nodes:
                    # Find line number from first node
                    func_name = path.nodes[0]
                    line = _find_function_line(source_code, func_name)
                    if line > 0:
                        detections.append(Detection(
                            line=line,
                            vuln_type="reentrancy_path",
                            severity="MEDIUM",
                            confidence=0.6,
                            detector="call_graph"
                        ))
        except Exception:
            pass  # Call graph analysis is supplementary

        # 5. Taint Analysis
        try:
            taint_analyzer = TaintAnalyzer()
            tainted_paths = taint_analyzer.analyze(source_code)

            for tpath in tainted_paths[:10]:  # Limit
                if hasattr(tpath, 'sink') and tpath.sink:
                    detections.append(Detection(
                        line=tpath.sink.line if hasattr(tpath.sink, 'line') else 0,
                        vuln_type=f"tainted_{tpath.sink.sink_type.value}" if hasattr(tpath.sink.sink_type, 'value') else "tainted_sink",
                        severity="MEDIUM",
                        confidence=0.5,
                        detector="taint_analysis"
                    ))
        except Exception:
            pass  # Taint analysis is supplementary

    except Exception as e:
        print(f"  Analysis error: {e}")

    elapsed_ms = (time.time() - start_time) * 1000
    return detections, elapsed_ms


def analyze_contract_with_fp_filter(
    source_code: str, category: str, fp_threshold: float = 0.6
) -> Tuple[List[Detection], float, int]:
    """
    Analyze contract using v4.6.0 modules with v4.7.0 FP scoring.

    NOTE: We DON'T remove findings - we only adjust confidence scores.
    This preserves recall while improving precision through confidence thresholds.

    Returns: (detections, elapsed_ms, high_fp_count)
    """
    detections, elapsed_ms = analyze_contract(source_code, category)

    if not FP_CLASSIFIER_AVAILABLE or not detections:
        return detections, elapsed_ms, 0

    # Apply FP classifier - adjust confidence only, don't remove
    classifier = FPClassifier(fp_threshold=fp_threshold)

    # Convert detections to dict format for classifier
    findings_dicts = []
    for det in detections:
        findings_dicts.append({
            "type": det.vuln_type,
            "confidence": det.confidence,
            "severity": det.severity,
            "location": {"line": det.line},
            "detector": det.detector,
        })

    # Score but don't filter (remove_fps=False)
    scored, _ = classifier.filter_findings(
        findings_dicts, source_code, remove_fps=False, adjust_confidence=True
    )

    # Convert back to Detection objects with adjusted confidence
    adjusted_detections = []
    high_fp_count = 0
    for f in scored:
        fp_prob = f.get("_fp_probability", 0.0)
        if fp_prob >= fp_threshold:
            high_fp_count += 1

        adjusted_detections.append(Detection(
            line=f["location"]["line"],
            vuln_type=f["type"],
            severity=f["severity"],
            confidence=f["confidence"],  # Now adjusted by FP classifier
            detector=f.get("detector", "fp_scored")
        ))

    return adjusted_detections, elapsed_ms, high_fp_count


def cross_validate_with_mythril(
    source_code: str,
    detections: List[Detection],
    timeout: int = 60,
) -> Tuple[List[Detection], int]:
    """
    Cross-validate detections using Mythril symbolic execution.

    Findings confirmed by Mythril get boosted confidence.
    Findings not confirmed get reduced confidence.

    Returns: (validated_detections, mythril_confirmed_count)
    """
    if not MYTHRIL_AVAILABLE or not detections:
        return detections, 0

    adapter = MythrilAdapter()

    # Run Mythril analysis once
    import tempfile
    import os

    with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
        f.write(source_code)
        temp_path = f.name

    try:
        mythril_result = adapter.analyze(temp_path, timeout=timeout, verbose=False)
    finally:
        try:
            os.unlink(temp_path)
        except:
            pass

    if mythril_result.get("status") != "success":
        return detections, 0

    mythril_findings = mythril_result.get("findings", [])

    # Map Mythril SWC to vulnerability types
    mythril_swc_to_type = {
        "SWC-107": {"reentrancy", "reentrancy_eth", "reentrancy_no_eth"},
        "SWC-101": {"integer_overflow", "integer_underflow", "arithmetic"},
        "SWC-104": {"unchecked_low_level_calls", "unchecked_send", "unchecked_call"},
        "SWC-105": {"access_control", "unprotected_function"},
        "SWC-106": {"access_control", "suicidal"},
        "SWC-115": {"tx_origin"},
        "SWC-116": {"timestamp_dependence", "timestamp"},
        "SWC-114": {"front_running", "tod"},
        "SWC-120": {"bad_randomness", "weak_randomness"},
    }

    # Build set of (type, line) confirmed by Mythril
    mythril_confirmed = set()
    for mf in mythril_findings:
        swc = mf.get("swc_id", "")
        line = mf.get("location", {}).get("line", 0)
        types = mythril_swc_to_type.get(swc, set())
        for t in types:
            mythril_confirmed.add((t, line))

    # Validate detections
    validated = []
    confirmed_count = 0

    for det in detections:
        det_type = det.vuln_type.lower().replace("-", "_")
        det_line = det.line

        # Check if Mythril confirms this (within 10 lines)
        is_confirmed = False
        for (mtype, mline) in mythril_confirmed:
            if mtype in det_type or det_type in mtype:
                if abs(mline - det_line) <= 10:
                    is_confirmed = True
                    break

        if is_confirmed:
            confirmed_count += 1
            # Boost confidence for confirmed
            new_conf = min(0.95, det.confidence + 0.2)
        else:
            # Reduce confidence for unconfirmed (but not too much)
            new_conf = max(0.3, det.confidence - 0.1)

        validated.append(Detection(
            line=det.line,
            vuln_type=det.vuln_type,
            severity=det.severity,
            confidence=new_conf,
            detector=det.detector + ("+mythril" if is_confirmed else "")
        ))

    return validated, confirmed_count


def cross_validate_with_slither(
    source_code: str,
    detections: List[Detection],
    timeout: int = 30,
) -> Tuple[List[Detection], int]:
    """
    Cross-validate detections using Slither static analysis.

    Findings confirmed by Slither get boosted confidence.
    Findings not confirmed get reduced confidence (only for types Slither can detect).

    Returns: (validated_detections, slither_confirmed_count)
    """
    if not SLITHER_AVAILABLE or not detections:
        return detections, 0

    validator = SlitherValidator(timeout=timeout)
    slither_findings = validator.run_slither(source_code)

    if not slither_findings:
        return detections, 0

    # Map Slither detector names to vulnerability types
    slither_detector_to_type = {
        "reentrancy-eth": {"reentrancy", "reentrancy_eth"},
        "reentrancy-no-eth": {"reentrancy", "reentrancy_no_eth"},
        "reentrancy-benign": {"reentrancy"},
        "reentrancy-events": {"reentrancy"},
        "arbitrary-send-eth": {"access_control", "unprotected_function"},
        "suicidal": {"access_control", "suicidal"},
        "controlled-delegatecall": {"access_control", "delegatecall"},
        "tx-origin": {"tx_origin"},
        "timestamp": {"timestamp_dependence", "timestamp"},
        "weak-prng": {"bad_randomness", "timestamp_dependence"},
        "unchecked-lowlevel": {"unchecked_low_level_calls", "unchecked_call"},
        "unchecked-send": {"unchecked_send", "unchecked_low_level_calls"},
        "low-level-calls": {"unchecked_low_level_calls"},
        "calls-loop": {"denial_of_service", "dos"},
        "costly-loop": {"denial_of_service", "dos"},
        "divide-before-multiply": {"arithmetic"},
    }

    # Types that Slither CAN detect well - only apply penalty for these
    # Slither doesn't detect overflow/underflow, TOD, front-running, short address well
    slither_detectable_types = {
        "reentrancy", "reentrancy_eth", "reentrancy_no_eth", "reentrancy_path",
        "access_control", "unprotected_function", "suicidal",
        "tx_origin", "tx.origin",
        "timestamp_dependence", "timestamp", "bad_randomness",
        "unchecked_low_level_calls", "unchecked_call", "unchecked_send",
        "denial_of_service", "dos",
    }

    # Build set of (type, lines) confirmed by Slither
    slither_confirmed = []
    for sf in slither_findings:
        detector = sf.detector.lower().replace("_", "-")
        types = slither_detector_to_type.get(detector, set())
        for t in types:
            for line in sf.lines:
                slither_confirmed.append((t, line))

    # Validate detections
    validated = []
    confirmed_count = 0

    for det in detections:
        det_type = det.vuln_type.lower().replace("-", "_")
        det_line = det.line

        # Check if this is a type Slither can detect
        slither_can_detect = any(
            st in det_type or det_type in st
            for st in slither_detectable_types
        )

        # Check if Slither confirms this (within 10 lines)
        is_confirmed = False
        for (stype, sline) in slither_confirmed:
            if stype in det_type or det_type in stype:
                if abs(sline - det_line) <= 10:
                    is_confirmed = True
                    break

        if is_confirmed:
            confirmed_count += 1
            # Boost confidence for confirmed
            new_conf = min(0.95, det.confidence + 0.25)
        elif slither_can_detect:
            # Only reduce confidence for types Slither can detect
            # This is a meaningful signal that finding might be FP
            new_conf = max(0.35, det.confidence - 0.20)
        else:
            # Slither can't detect this type, keep original confidence
            new_conf = det.confidence

        validated.append(Detection(
            line=det.line,
            vuln_type=det.vuln_type,
            severity=det.severity,
            confidence=new_conf,
            detector=det.detector + ("+slither" if is_confirmed else "")
        ))

    return validated, confirmed_count


def _find_function_line(source: str, func_name: str) -> int:
    """Find line number where function is defined."""
    pattern = rf'function\s+{re.escape(func_name)}\s*\('
    for i, line in enumerate(source.split('\n'), 1):
        if re.search(pattern, line):
            return i
    return 0


def match_detections(
    ground_truth: List[GroundTruth],
    detections: List[Detection],
    category: str,
    line_tolerance: int = 10
) -> Tuple[int, int, int]:
    """
    Match detections against ground truth.
    Returns: (true_positives, false_positives, false_negatives)
    """
    expected_types = CATEGORY_TO_VULN_TYPES.get(category, set())

    matched_gt = set()
    matched_det = set()

    for i, gt in enumerate(ground_truth):
        gt_start = gt.line
        gt_end = gt.line + gt.length

        for j, det in enumerate(detections):
            if j in matched_det:
                continue

            # Check if detection type matches category
            det_type = det.vuln_type.lower().replace('-', '_').replace(' ', '_')
            type_matches = any(
                exp_type in det_type or det_type in exp_type
                for exp_type in expected_types
            )

            # Check line proximity
            line_matches = (
                (gt_start - line_tolerance <= det.line <= gt_end + line_tolerance) or
                (det.line >= gt_start and det.line <= gt_end)
            )

            if type_matches and line_matches:
                matched_gt.add(i)
                matched_det.add(j)
                break

    true_positives = len(matched_gt)
    false_negatives = len(ground_truth) - true_positives
    false_positives = len(detections) - len(matched_det)

    return true_positives, false_positives, false_negatives


def run_benchmark(
    max_contracts_per_category: Optional[int] = None,
    categories: Optional[List[str]] = None,
    min_confidence: float = 0.0,
    use_fp_filter: bool = False,
    fp_threshold: float = 0.6,
    use_mythril: bool = False,
    mythril_timeout: int = 60,
    use_slither: bool = False,
    slither_timeout: int = 30,
) -> BenchmarkResults:
    """Run the complete benchmark.

    Args:
        max_contracts_per_category: Limit contracts per category
        categories: List of categories to evaluate
        min_confidence: Minimum confidence to count detection (improves precision)
        use_fp_filter: Use ML-based FP classifier (v4.7.0)
        fp_threshold: FP probability threshold for filtering
        use_mythril: Use Mythril for cross-validation (slow but improves precision)
        mythril_timeout: Timeout per contract for Mythril analysis
        use_slither: Use Slither for cross-validation (fast, improves precision)
        slither_timeout: Timeout per contract for Slither analysis
    """
    results = BenchmarkResults(
        timestamp=datetime.now().isoformat()
    )

    if categories is None:
        categories = list(SOLIDIFI_TO_SWC.keys())

    version = "v4.7.0" if (use_fp_filter or use_mythril or use_slither) else "v4.6.0"
    print("=" * 70)
    print(f"  MIESC {version} - SolidiFI Benchmark Evaluation")
    print("=" * 70)
    print(f"\nDataset: {DATASET_PATH}")
    print(f"Categories: {', '.join(categories)}")
    if max_contracts_per_category:
        print(f"Max contracts per category: {max_contracts_per_category}")
    if min_confidence > 0:
        print(f"Minimum confidence threshold: {min_confidence:.0%}")
    if use_fp_filter:
        print(f"FP Classifier: ENABLED (threshold={fp_threshold})")
    if use_slither:
        if SLITHER_AVAILABLE:
            print(f"Slither Cross-Validation: ENABLED (timeout={slither_timeout}s)")
        else:
            print("Slither Cross-Validation: NOT AVAILABLE (slither not installed)")
            use_slither = False
    if use_mythril:
        if MYTHRIL_AVAILABLE:
            print(f"Mythril Cross-Validation: ENABLED (timeout={mythril_timeout}s)")
        else:
            print("Mythril Cross-Validation: NOT AVAILABLE (mythril not installed)")
            use_mythril = False
    print()

    start_time = time.time()

    for category in categories:
        category_path = DATASET_PATH / category
        if not category_path.exists():
            print(f"Warning: Category path not found: {category_path}")
            continue

        print(f"\n[{category}]")
        print("-" * 50)

        cat_metrics = CategoryMetrics()

        # Find contract files
        sol_files = sorted(category_path.glob("buggy_*.sol"))
        if max_contracts_per_category:
            sol_files = sol_files[:max_contracts_per_category]

        for sol_file in sol_files:
            contract_name = sol_file.stem
            csv_file = category_path / f"BugLog_{contract_name.replace('buggy_', '')}.csv"

            # Parse ground truth
            ground_truth = []
            if csv_file.exists():
                ground_truth = parse_buglog(csv_file)

            # Read source code
            try:
                source_code = sol_file.read_text(encoding='utf-8', errors='ignore')
            except Exception as e:
                results.errors.append(f"{sol_file}: {e}")
                continue

            # Analyze contract
            if use_fp_filter and FP_CLASSIFIER_AVAILABLE:
                detections, analysis_time, filtered_count = analyze_contract_with_fp_filter(
                    source_code, category, fp_threshold
                )
            else:
                detections, analysis_time = analyze_contract(source_code, category)

            # Cross-validate with Slither (fast, improves precision)
            if use_slither and SLITHER_AVAILABLE and detections:
                detections, slither_confirmed = cross_validate_with_slither(
                    source_code, detections, slither_timeout
                )

            # Cross-validate with Mythril (slow but improves precision)
            if use_mythril and MYTHRIL_AVAILABLE and detections:
                detections, mythril_confirmed = cross_validate_with_mythril(
                    source_code, detections, mythril_timeout
                )

            # Filter by minimum confidence (improves precision)
            if min_confidence > 0:
                detections = [d for d in detections if d.confidence >= min_confidence]

            # Match detections
            tp, fp, fn = match_detections(ground_truth, detections, category)

            # Create result
            contract_result = ContractResult(
                name=contract_name,
                category=category,
                ground_truth=ground_truth,
                detections=detections,
                true_positives=tp,
                false_positives=fp,
                false_negatives=fn,
                analysis_time_ms=analysis_time
            )
            results.contract_results.append(contract_result)

            # Update category metrics
            cat_metrics.total_contracts += 1
            cat_metrics.total_ground_truth += len(ground_truth)
            cat_metrics.total_detections += len(detections)
            cat_metrics.true_positives += tp
            cat_metrics.false_positives += fp
            cat_metrics.false_negatives += fn

            # Progress indicator
            status = "OK" if tp > 0 else "MISS" if len(ground_truth) > 0 else "EMPTY"
            print(f"  {contract_name}: GT={len(ground_truth)}, Det={len(detections)}, "
                  f"TP={tp}, FP={fp}, FN={fn} [{status}]")

        # Calculate category metrics
        if cat_metrics.true_positives + cat_metrics.false_positives > 0:
            cat_metrics.precision = cat_metrics.true_positives / (
                cat_metrics.true_positives + cat_metrics.false_positives
            )
        if cat_metrics.true_positives + cat_metrics.false_negatives > 0:
            cat_metrics.recall = cat_metrics.true_positives / (
                cat_metrics.true_positives + cat_metrics.false_negatives
            )
        if cat_metrics.precision + cat_metrics.recall > 0:
            cat_metrics.f1_score = 2 * (cat_metrics.precision * cat_metrics.recall) / (
                cat_metrics.precision + cat_metrics.recall
            )

        results.by_category[category] = cat_metrics

        print(f"\n  {category} Summary:")
        print(f"    Contracts: {cat_metrics.total_contracts}")
        print(f"    Ground Truth: {cat_metrics.total_ground_truth}")
        print(f"    Detections: {cat_metrics.total_detections}")
        print(f"    TP: {cat_metrics.true_positives}, FP: {cat_metrics.false_positives}, FN: {cat_metrics.false_negatives}")
        print(f"    Precision: {cat_metrics.precision:.1%}")
        print(f"    Recall: {cat_metrics.recall:.1%}")
        print(f"    F1: {cat_metrics.f1_score:.1%}")

    # Calculate overall metrics
    results.total_time_seconds = time.time() - start_time
    results.total_contracts = sum(m.total_contracts for m in results.by_category.values())
    results.total_ground_truth = sum(m.total_ground_truth for m in results.by_category.values())
    results.total_detections = sum(m.total_detections for m in results.by_category.values())
    results.true_positives = sum(m.true_positives for m in results.by_category.values())
    results.false_positives = sum(m.false_positives for m in results.by_category.values())
    results.false_negatives = sum(m.false_negatives for m in results.by_category.values())

    if results.true_positives + results.false_positives > 0:
        results.precision = results.true_positives / (results.true_positives + results.false_positives)
    if results.true_positives + results.false_negatives > 0:
        results.recall = results.true_positives / (results.true_positives + results.false_negatives)
    if results.precision + results.recall > 0:
        results.f1_score = 2 * (results.precision * results.recall) / (results.precision + results.recall)

    return results


def print_results(results: BenchmarkResults):
    """Print benchmark results summary."""
    print("\n" + "=" * 70)
    print("  BENCHMARK RESULTS - MIESC v4.6.0")
    print("=" * 70)

    print(f"\nOverall Metrics:")
    print(f"  Total Contracts: {results.total_contracts}")
    print(f"  Total Ground Truth Vulnerabilities: {results.total_ground_truth}")
    print(f"  Total Detections: {results.total_detections}")
    print(f"  True Positives: {results.true_positives}")
    print(f"  False Positives: {results.false_positives}")
    print(f"  False Negatives: {results.false_negatives}")
    print()
    print(f"  Precision: {results.precision:.1%}")
    print(f"  Recall: {results.recall:.1%}")
    print(f"  F1 Score: {results.f1_score:.1%}")
    print()
    print(f"  Total Time: {results.total_time_seconds:.1f}s")
    print(f"  Avg Time/Contract: {results.total_time_seconds / max(results.total_contracts, 1) * 1000:.0f}ms")

    print("\nMetrics by Category:")
    print("-" * 70)
    print(f"{'Category':<25} {'Precision':>10} {'Recall':>10} {'F1':>10} {'TP':>6} {'FP':>6} {'FN':>6}")
    print("-" * 70)

    for cat, metrics in sorted(results.by_category.items()):
        print(f"{cat:<25} {metrics.precision:>9.1%} {metrics.recall:>9.1%} "
              f"{metrics.f1_score:>9.1%} {metrics.true_positives:>6} "
              f"{metrics.false_positives:>6} {metrics.false_negatives:>6}")

    print("-" * 70)
    print(f"{'TOTAL':<25} {results.precision:>9.1%} {results.recall:>9.1%} "
          f"{results.f1_score:>9.1%} {results.true_positives:>6} "
          f"{results.false_positives:>6} {results.false_negatives:>6}")

    if results.errors:
        print(f"\nErrors ({len(results.errors)}):")
        for err in results.errors[:10]:
            print(f"  - {err}")


def save_results(results: BenchmarkResults, output_path: Path):
    """Save results to JSON file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Convert to serializable dict
    data = {
        "version": results.version,
        "timestamp": results.timestamp,
        "total_contracts": results.total_contracts,
        "total_ground_truth": results.total_ground_truth,
        "total_detections": results.total_detections,
        "true_positives": results.true_positives,
        "false_positives": results.false_positives,
        "false_negatives": results.false_negatives,
        "precision": results.precision,
        "recall": results.recall,
        "f1_score": results.f1_score,
        "total_time_seconds": results.total_time_seconds,
        "by_category": {
            cat: {
                "total_contracts": m.total_contracts,
                "total_ground_truth": m.total_ground_truth,
                "total_detections": m.total_detections,
                "true_positives": m.true_positives,
                "false_positives": m.false_positives,
                "false_negatives": m.false_negatives,
                "precision": m.precision,
                "recall": m.recall,
                "f1_score": m.f1_score,
            }
            for cat, m in results.by_category.items()
        },
        "errors": results.errors,
    }

    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)

    print(f"\nResults saved to: {output_path}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="MIESC v4.6.0 SolidiFI Benchmark")
    parser.add_argument("--max-contracts", type=int, default=None,
                        help="Max contracts per category (default: all)")
    parser.add_argument("--categories", nargs="+", default=None,
                        help="Categories to evaluate (default: all)")
    parser.add_argument("--output", type=str, default=None,
                        help="Output JSON file path")
    parser.add_argument("--quick", action="store_true",
                        help="Quick mode: 10 contracts per category")
    parser.add_argument("--min-confidence", type=float, default=0.0,
                        help="Minimum confidence threshold to count as detection (default: 0.0)")
    parser.add_argument("--high-precision", action="store_true",
                        help="High precision mode: min-confidence=0.5")
    parser.add_argument("--fp-filter", action="store_true",
                        help="Use ML-based FP classifier (v4.7.0)")
    parser.add_argument("--fp-threshold", type=float, default=0.6,
                        help="FP probability threshold (default: 0.6)")
    parser.add_argument("--mythril", action="store_true",
                        help="Use Mythril for cross-validation (slow)")
    parser.add_argument("--mythril-timeout", type=int, default=60,
                        help="Mythril timeout per contract (default: 60s)")
    parser.add_argument("--slither", action="store_true",
                        help="Use Slither for cross-validation (fast, recommended)")
    parser.add_argument("--slither-timeout", type=int, default=30,
                        help="Slither timeout per contract (default: 30s)")

    args = parser.parse_args()

    max_contracts = args.max_contracts
    if args.quick:
        max_contracts = 10

    min_confidence = args.min_confidence
    if args.high_precision:
        min_confidence = 0.5

    # Run benchmark
    results = run_benchmark(
        max_contracts_per_category=max_contracts,
        categories=args.categories,
        min_confidence=min_confidence,
        use_fp_filter=args.fp_filter,
        fp_threshold=args.fp_threshold,
        use_mythril=args.mythril,
        mythril_timeout=args.mythril_timeout,
        use_slither=args.slither,
        slither_timeout=args.slither_timeout,
    )

    # Print results
    print_results(results)

    # Save results
    if args.output:
        output_path = Path(args.output)
    else:
        RESULTS_PATH.mkdir(parents=True, exist_ok=True)
        output_path = RESULTS_PATH / f"solidifi_v460_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    save_results(results, output_path)
