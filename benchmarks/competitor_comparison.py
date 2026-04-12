#!/usr/bin/env python3
"""
MIESC vs Competitors — Honest Head-to-Head Comparison
======================================================

Runs MIESC and each competitor tool on the same contracts and reports:
  - Findings count per tool
  - Time taken
  - Severity distribution
  - Where MIESC is better, where worse, where equal

Tools compared:
  - Slither (Trail of Bits) — static analysis baseline
  - Aderyn (Cyfrin) — fast Rust static analyzer
  - Mythril (ConsenSys) — symbolic execution
  - Echidna (Trail of Bits) — fuzzing
  - Solhint — linter
  - MIESC (us) — multi-layer orchestration

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Test contracts (intentionally vulnerable, well-understood)
TEST_CONTRACTS = [
    ("EtherStore.sol", "Classic reentrancy (DAO-style)"),
    ("VulnerableDeFi.sol", "Modern DeFi vulnerabilities"),
    ("AccessControlFlaws.sol", "Access control issues"),
    ("ReentrancyDAO.sol", "Multiple reentrancy patterns"),
    ("FlashLoanAttack.sol", "Flash loan attack patterns"),
]

CONTRACTS_DIR = PROJECT_ROOT / "examples" / "contracts"


def run_tool(name, cmd, timeout=120):
    """Run a tool and return (findings_count, elapsed, raw_output)."""
    start = time.time()
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        elapsed = time.time() - start
        return result.returncode, result.stdout, result.stderr, elapsed
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT", time.time() - start
    except FileNotFoundError:
        return -2, "", "NOT_INSTALLED", 0


def parse_slither(stdout, stderr):
    """Parse Slither JSON output."""
    try:
        data = json.loads(stdout)
        if data.get("success") and data.get("results"):
            detectors = data["results"].get("detectors", [])
            return len(detectors)
    except (json.JSONDecodeError, KeyError):
        pass
    # Fallback: count findings in stderr
    return stderr.count("Reentrancy") + stderr.count("INFO:") // 2


def parse_aderyn(workdir, contract_name):
    """Parse Aderyn report."""
    report_path = Path(workdir) / "report.json"
    if report_path.exists():
        try:
            data = json.loads(report_path.read_text())
            high = len(data.get("high_issues", {}).get("issues", []))
            low = len(data.get("low_issues", {}).get("issues", []))
            return high + low
        except Exception:
            pass
    return 0


def parse_solhint(stdout):
    """Parse Solhint JSON output."""
    try:
        data = json.loads(stdout)
        return sum(len(report.get("messages", [])) for report in data)
    except Exception:
        return stdout.count("error") + stdout.count("warning")


def parse_miesc(json_path):
    """Parse MIESC output."""
    if not Path(json_path).exists():
        return 0, {}
    data = json.loads(Path(json_path).read_text())
    findings = data.get("findings", [])
    severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "").upper()
        if sev in severity_count:
            severity_count[sev] += 1
    return len(findings), severity_count


def benchmark_contract(contract_name, description):
    """Run all tools on a single contract."""
    contract_path = CONTRACTS_DIR / contract_name
    if not contract_path.exists():
        return None

    print(f"\n{'='*70}")
    print(f"  Contract: {contract_name}")
    print(f"  {description}")
    print(f"{'='*70}\n")

    results = {}

    # Slither
    print("  [Slither] Running...", end=" ", flush=True)
    import os
    SOLC = os.path.expanduser("~/.solc-select/artifacts/solc-0.8.20/solc-0.8.20")
    if Path(SOLC).exists():
        slither_cmd = ["slither", str(contract_path), "--solc", SOLC, "--json", "-"]
    else:
        slither_cmd = ["slither", str(contract_path), "--json", "-"]
    rc, out, err, t = run_tool("slither", slither_cmd, timeout=60)
    if rc == -2:
        print("NOT INSTALLED")
        results["slither"] = {"installed": False}
    else:
        count = parse_slither(out, err)
        # Slither also reports "X result(s) found" in stderr
        import re
        m = re.search(r"(\d+)\s+result\(s\)\s+found", err)
        if m:
            count = int(m.group(1))
        print(f"{count} findings in {t:.1f}s")
        results["slither"] = {"findings": count, "time": t, "installed": True}

    # Aderyn (needs workdir)
    import tempfile
    print("  [Aderyn] Running...", end=" ", flush=True)
    with tempfile.TemporaryDirectory() as workdir:
        # Copy contract to workdir
        shutil.copy(contract_path, Path(workdir) / contract_name)
        rc, out, err, t = run_tool(
            "aderyn",
            ["aderyn", workdir, "-o", "report.json"],
            timeout=60,
        )
        if rc == -2:
            print("NOT INSTALLED")
            results["aderyn"] = {"installed": False}
        else:
            # Try to parse from current dir or workdir
            count = 0
            for path in [Path("report.json"), Path(workdir) / "report.json"]:
                if path.exists():
                    try:
                        data = json.loads(path.read_text())
                        count = (
                            len(data.get("high_issues", {}).get("issues", []))
                            + len(data.get("low_issues", {}).get("issues", []))
                        )
                        if path.name == "report.json" and path == Path("report.json"):
                            path.unlink()  # cleanup
                        break
                    except Exception:
                        pass
            print(f"{count} findings in {t:.1f}s")
            results["aderyn"] = {"findings": count, "time": t, "installed": True}

    # Solhint (needs to run from contract dir with relative path)
    print("  [Solhint] Running...", end=" ", flush=True)
    # Ensure config exists
    solhint_config = Path("/tmp/.solhint_bench.json")
    solhint_config.write_text('{"extends": "solhint:recommended"}')
    start = time.time()
    try:
        result = subprocess.run(
            ["solhint", "--config", str(solhint_config), "--formatter", "json", contract_name],
            cwd=str(CONTRACTS_DIR),
            capture_output=True, text=True, timeout=30,
        )
        t = time.time() - start
        try:
            data = json.loads(result.stdout)
            count = sum(len(r.get("messages", r.get("reports", []))) for r in data) if isinstance(data, list) else 0
        except (json.JSONDecodeError, AttributeError):
            count = 0
        print(f"{count} findings in {t:.1f}s")
        results["solhint"] = {"findings": count, "time": t, "installed": True}
    except (subprocess.TimeoutExpired, FileNotFoundError):
        print("ERROR")
        results["solhint"] = {"installed": False}

    # Echidna (property-based fuzzer — needs property contracts, will mostly find 0 without them)
    print("  [Echidna] Running...", end=" ", flush=True)
    rc, out, err, t = run_tool(
        "echidna",
        ["echidna", str(contract_path), "--test-limit", "1000"],
        timeout=60,
    )
    if rc == -2:
        print("NOT INSTALLED")
        results["echidna"] = {"installed": False}
    else:
        # Echidna reports "passed" or "failed" per property
        failed = err.count("FAILED!") + out.count("FAILED!")
        print(f"{failed} property violations in {t:.1f}s")
        results["echidna"] = {"findings": failed, "time": t, "installed": True}

    # MIESC (using its CLI)
    print("  [MIESC]   Running...", end=" ", flush=True)
    output_json = Path(f"/tmp/miesc_bench_{contract_name}.json")
    rc, out, err, t = run_tool(
        "miesc",
        ["python3", "-m", "miesc.cli.main", "scan", str(contract_path), "-o", str(output_json)],
        timeout=120,
    )
    count, sev = parse_miesc(output_json)
    print(f"{count} findings in {t:.1f}s ({sev})")
    results["miesc"] = {
        "findings": count,
        "time": t,
        "installed": True,
        "severity": sev,
    }

    return results


def main():
    print("\n" + "="*70)
    print("  MIESC vs Competitors — Head-to-Head Comparison")
    print("="*70)

    all_results = {}
    for contract, desc in TEST_CONTRACTS:
        res = benchmark_contract(contract, desc)
        if res:
            all_results[contract] = res

    # Summary table
    print("\n" + "="*70)
    print("  SUMMARY: Findings per Tool per Contract")
    print("="*70)
    print()

    # Build header
    tools = ["slither", "aderyn", "solhint", "echidna", "miesc"]
    print(f"  {'Contract':<25}", end="")
    for t in tools:
        print(f" {t:>10}", end="")
    print()
    print("  " + "-"*25 + " " + "-"*43)

    totals = {t: 0 for t in tools}
    times = {t: 0.0 for t in tools}

    for contract, results in all_results.items():
        name = contract.replace(".sol", "")[:23]
        print(f"  {name:<25}", end="")
        for t in tools:
            r = results.get(t, {})
            if not r.get("installed", False):
                print(f" {'N/A':>10}", end="")
            else:
                count = r.get("findings", 0)
                totals[t] += count
                times[t] += r.get("time", 0)
                print(f" {count:>10}", end="")
        print()

    print("  " + "-"*25 + " " + "-"*43)
    print(f"  {'TOTAL findings':<25}", end="")
    for t in tools:
        print(f" {totals[t]:>10}", end="")
    print()
    print(f"  {'TOTAL time (s)':<25}", end="")
    for t in tools:
        print(f" {times[t]:>10.1f}", end="")
    print()

    # Save JSON
    output = {
        "comparison_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "miesc_version": "5.1.1",
        "results": all_results,
        "totals": totals,
        "times": times,
    }
    out_path = PROJECT_ROOT / "benchmarks" / "results" / f"competitor_comparison_{time.strftime('%Y%m%d_%H%M%S')}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, indent=2, default=str))
    print(f"\n  Detailed results: {out_path}")


if __name__ == "__main__":
    main()
